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
- [x] Lower severity: `?strictConfig=a&strictConfig=b` returns 400 here and 200 in Go (Go
  reads the first value), which falsifies the documented "never a 400"; the
  `Option<Json<..>>` rationale is wrong (axum yields `None` only when `Content-Type` is
  absent, not for a malformed JSON body with the header set); `HEAD /api/reload` now
  performs a real reload because axum serves HEAD through the `get` handler.
  The duplicate-parameter half and the doc claim are fixed in this change (raw-query parse,
  first value wins). The `Option<Json<..>>` rationale is **already** fixed: `handle_reload`
  takes `body: Bytes` and its comment gives the correct reason ("a body that is present but
  not well-formed JSON must be a 400 on every method"), so no `Option<Json<..>>` remains to
  mis-explain.
  Done: the `HEAD` half is fixed in `frp-client/src/admin.rs` — the admin route table
  (`admin_router`) registers an explicit `.head(...)` on **every** `GET` route, answering
  `405` and never running the GET handler. A blanket HEAD-rejection *layer* was rejected on
  measurement, not on the axum docs: outermost it answers `405` for
  `HEAD /api/nonexistent` where Go answers `404` (a new divergence); innermost it lets auth
  win on a matched path (unauthenticated `HEAD /api/reload` -> 401, the very divergence it
  was meant to avoid). Per-route `.head()` changes only `HEAD` on a *registered* route and
  keeps axum's natural 404. Pinned by `admin_head_is_405_and_never_runs_a_get_handler`
  (integration, unknown-key oracle: a handler run would answer 400/200, so a 405 is the
  proof it did not run) and
  `head_on_registered_admin_get_routes_is_405_without_running_the_handler` (unit, over the
  real route table; also asserts that no reload request is enqueued by any HEAD). Residual,
  pre-existing and unchanged: an unauthenticated `HEAD` on a registered route is 401 here
  where Go answers 405, because frp-rs wraps the whole router in the auth layer before the
  method router runs.
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
- [x] `frp-server`'s `tls`-off test targets still have no gate: the symmetric
  `cargo check -p frp-server --no-default-features --all-targets` does not compile.
  `error[E0004]` at `frp-server/src/service.rs:1842` — `ConnectionType::WebSocket` is not
  covered, because feature unification gives `frp-core` the variant (through frp-client's
  default features, frp-client being frp-server's dev-dependency) while frp-server's own
  `websocket` feature is off. **Done-when:** `service.rs`'s `match` has a defensive arm for
  the unbuilt transport (or the variant is otherwise made unreachable under feature
  unification), and the isolated `-p frp-server` step joins the `-p frp-client` one in
  `ci.yml`.
  Done: `ConnectionType::WebSocket` is no longer feature-gated in
  `frp-core/src/transport/mod.rs`, so the variant always exists and frp-server's `match` is
  exhaustive by construction. The `b'G' => ConnectionType::WebSocket` *detection* arm keeps
  its `#[cfg(feature = "websocket")]`, so a websocket-off frp-core still classifies `G` as
  `V1(b'G')`: shipped micro/tiny byte behaviour is unchanged, and that build cannot
  construct the variant. `service.rs`'s arm is now unconditional with a
  `#[cfg(feature = "websocket")]` call to `handle_websocket_connection` and a
  `#[cfg(not(feature = "websocket"))]` warn-and-drop body. The blanket `_ =>` alternative
  was rejected: it would silently swallow any *future* `ConnectionType` variant in a
  websocket-off build. `ci.yml`'s `verify` job now runs
  `RUSTFLAGS="-D warnings" cargo check -p frp-server --no-default-features --all-targets`
  beside the `-p frp-client` step. The E0004 was the only error that configuration
  reported — but also the only one it *reached*; with it closed the run exposed two more,
  now fixed: `frp-server/tests/vhost_audit_fixes.rs` needed per-item `tls` gates (the two
  rustls-driving tests, the `https_proxy`/`NoVerify` helpers they share, and the
  `Read`/`Write`/`Arc` imports) and `frp-server/tests/vhost_h2c.rs` a whole-file
  `#![cfg(feature = "http-proxy")]` (it is entirely driven by `dep:h2`).
  `docs/developing.md § Binary Variants` states what the new step does and does not prove.
- [x] **The same feature-unification defect class survives elsewhere: `AuthMethod::Oidc` in
  `dashboard.rs`.** `frp-core`'s `AuthMethod::Oidc` carries `#[cfg(feature = "oidc")]`
  (`frp-core/src/auth.rs:206`) while `frp-server/src/dashboard.rs:2344` matches it under
  `#[cfg(feature = "oidc")]` — frp-server's own feature. With frp-core's `oidc` on and
  frp-server's off the `match` is non-exhaustive. Evidence:
  `RUSTFLAGS="-D warnings" cargo check -p frp-server --no-default-features --features dashboard --all-targets`
  exits 101 with `error[E0004]: non-exhaustive patterns: 'AuthMethod::Oidc' not covered` at
  `frp-server/src/dashboard.rs:2344:28`, plus four unrelated pre-existing errors in the same
  configuration: `E0425 cannot find type 'TcpListener'` (`dashboard.rs:185`), `E0425 cannot
  find type 'TcpStream'` (`dashboard.rs:189`), `E0433 cannot find module or crate 'io'`
  (`dashboard.rs:206`) and `unused import: 'AtomicU64'` (`dashboard.rs:21`) — all five must
  be fixed before any CI step can gate this configuration. **Not reachable from a shipped
  binary:** the three `[[bin]]` targets require `full`, `tiny` or `micro`; `full`/default
  include `oidc` and tiny/micro both exclude `dashboard`, so no `frps` artifact has
  frp-core/oidc on with frp-server/oidc off. It *is* reachable from that `-p` invocation and
  from any downstream workspace that enables `frp-core/oidc` while leaving frp-server's
  `oidc` off — and that downstream must also enable frp-server's `dashboard` feature, since
  the module itself is gated (`frp-server/src/lib.rs:5-6`). Measured counterexample to the
  looser phrasing: `-p frp-server --no-default-features --all-targets` has frp-core's `oidc`
  **on** (via the dev-dependency edge) with frp-server's own features at none, and exits 0,
  because frp-server's `dashboard` is off so the `match` is not compiled at all. **Done-when:** the gate on the `Oidc` variant is keyed to the same crate
  feature that gates its construction (or the variant stops being feature-gated the way
  `ConnectionType::WebSocket` was), the four unrelated errors are fixed, and the command
  above exits 0. Note this is the second instance of the class fixed in
  `frp-core/src/transport/mod.rs` — the fix there was per-variant, not systematic.

  Done (branch `fix/dashboard-oidc-feature`, based on `main` @ `d302b50`): `AuthMethod::Oidc` is no
  longer feature-gated, following the `ConnectionType::WebSocket` precedent — the variant and the
  three `frp-core` arms that match it are unconditional, while *construction* stays gated in each
  dependent crate's config parse, so the variant is only built where a verifier exists and a
  hand-built `Oidc` still fails closed through the `#[cfg(not(feature = "oidc"))]` stubs (whose
  comments no longer claim the variant is "compiled out"). The four unrelated errors were real gate
  bugs in the same configuration: `NoDelayListener` serves the plain-HTTP dashboard path with `tls`
  off, so `io`/`TcpListener`/`TcpStream` are no longer tls-gated, and `AtomicU64` is now tls-gated
  while `Ordering` stays unconditional. `RUSTFLAGS="-D warnings" cargo check -p frp-server
  --no-default-features --features dashboard --all-targets` exits 0 (measured 101 with exactly the
  five documented errors on `d302b50`), and a new `ci.yml` step gates the configuration — the only
  step that compiles frp-server's test targets with `dashboard` ON **and `oidc` OFF**. It runs
  `cargo clippy` (not `check`) for both reverse-feature directions, because the `--all-features`
  clippy lane compiles `#[cfg(not(feature = "oidc"))]` items *out*: a `clippy::field_reassign_with_default`
  error in this branch's own client pin escaped that lane and was caught locally by hand (measured
  cost of the added line: ~12 s warm, ~33 s cold). Both reviewers re-ran the command, every
  neighbouring CI combination, and a 29-configuration single-feature sweep under `-D warnings`; no
  other instance of the class exists, and the healthy OIDC-on counts are unchanged (`frp-core --lib
  auth` 86, `frp-server --features dashboard --lib` 469→470 with the new dashboard test).

  The adversarial review then measured what the newly-compilable configuration did at runtime and
  found a **pre-existing silent downgrade** that the first version of the new test blessed: with
  frp-server's `oidc` off, `auth.method = "oidc"` parsed to `Token`, so a config carrying a `token`
  started as **token auth** and a token login authenticated (measured on `frps-tiny`: `logged in with
  run_id …`, proxy registered); the parent `d302b50` behaves identically. Both parses now **refuse**
  the configuration with a shared `OIDC_FEATURE_REQUIRED` error naming the feature, the test is
  inverted to assert the rejection in both the no-token and with-token halves, the client parse
  refuses it too with its own pin, the dashboard arm that used to be cfg-gated is covered by an
  `"oidc"` assertion, and the method match now precedes token-source resolution so a config that
  cannot work names the decisive reason. The refusal happens where the service is constructed —
  server startup, the server's SIGUSR1 reload (which logs the error and keeps serving the old
  config), `frpc run` — and in `frpc verify` (`frpc-tiny verify` on an OIDC config: rc 2 with the
  feature error; a default `frpc` still says valid), so the CLI's two paths agree. This is a
  behaviour change for builds without the `oidc` feature (tiny/micro): such a config now fails
  instead of starting as token auth — recorded in `CHANGELOG.md`.

  Residue, recorded below as new items: `auth.method` parsing is inconsistent across the three sites
  (the client compares case-sensitively; unknown/whitespace spellings fall back to `Token` on both
  sides), the client's admin-triggered `reload` never re-derives auth, and `oidc_throttle_tests` —
  filed here as load-dependent, since fixed: the mock IdP could read 0 bytes after accepting because
  the accepted socket inherited the listener's non-blocking mode (see the item below).
- [x] **The help *document* is bpaf's, not cobra's — every `--help` surface is a different
  document from Go's, not just a different layout.** Filed by the `--help=<bool>` round
  (`TODO.md:3274`), which matched the *behaviour* of every help argv and deliberately left the
  rendering. Measured 2026-09-28 on Go v0.71.0 darwin/arm64 against frp-rs `b8b0ffc`, stdout and
  stderr separate, rc from the child:
  * `frpc status --help`, `frpc status -h`, `frpc --help=true status` and `frpc -hc --help=false
    status` all print **627 B** of cobra help on Go (`Overview of all proxies status` + `Usage:
    frpc status [flags]` + `Flags:` + `Global Flags:`) and **1604 B** of bpaf usage here;
  * `frpc --help`, `frpc -h`, `frpc --help=true` and `frpc -hc -hc` are **1370 B** vs **2405 B**;
  * `frps --help` is **2394 B** vs **3571 B**, and `frps verify --help` **2103 B** vs **3317 B**;
  * `frpc verify --help` **543 B** vs **1094 B**, `frpc tcp --help` **2211 B** vs **1893 B**,
    `frpc reload --help` **626 B** vs **1358 B**, `frpc stop --help` **614 B** vs **1356 B**,
    `frpc https --help` **2269 B** vs **1457 B** (the last three are *larger* here because bpaf
    renders one entry per bool spelling — `(--version=BOOL | [-v])` — where cobra prints one
    `-v, --version` line; see § `--flag=<bool>`).
  The rc, the stream and the "did a command run" questions all match Go; what does not is the
  document. **Done-when:** one rendering layer in `frp-core/src/cli.rs` that renders cobra's shape
  from bpaf metadata for every surface above — command short text, the `Usage:`/`Flags:`/`Global
  Flags:` sections, 30-column flag alignment, `-h, --help  help for <cmd>` — with the nine byte
  counts above (or their replacements, stated per surface) as the witness, **and** the bool-flag
  collapse from two entries to one. It is a flag-surface-wide row: it covers argv the
  `--help=<bool>` item never touched, so it is filed here rather than closed there. No sha.

  Done: closed on `feat/cobra-help-rendering` (four commits `762e2246` -> `54921885` -> `235ac0cc` ->
  `3abc7ebf`, rebased onto `a0c16c83` as `936f0458`, replayed onto `f503b4e7` as `da8e9d8d` ->
  `57f7d415` -> `58dcfab5`, then onto `f679e822` as `af0c2713` -> `df4e6764` -> `808d27f8`; `frp-core/src/cli.rs` +2082 and
  `frps/tests/cli_exit_codes.rs` +4/-1). One rendering layer -- `render_cobra_help`, called from
  `run_cli` on `bpaf::ParseFailure::Stdout` only -- reconstructs cobra's document from the flag
  surface read back out of bpaf's own rendering (`bpaf_help_flags`, `frp-core/src/cli.rs:2611`), so
  the document follows the parser rather than a hand-maintained list. `frps verify --help` (**2103 B**)
  and `frpc verify --help` (**543 B**) are Go v0.71.0's documents byte-for-byte; the seven other
  surfaces of the item are stated replacements -- `frps` 2467 (Go 2394), `frpc` 1517 (1370),
  `frpc status` 859 (627), `frpc tcp` 992 (2211), `frpc reload` 801 (626), `frpc stop` 789 (614),
  `frpc https` 979 (2269) -- and six further surfaces are pinned as well. All fifteen are pinned
  whole-text **and** by byte count, the bool-flag collapse is asserted
  (`bool_flags_collapse_to_one_row_each`), and the eleven alternate argv forms resolve to Go's surface.
  Done-when met: one layer, cobra's shape, the nine byte counts (two exact, seven stated per surface),
  the collapse. Ledger after this batch: **31 open / 164 closed** (base `f679e822`: 29 open / 163
  closed; this batch closes the cobra help-document item and files the three residues below). Review record in the PR (four rounds; the round-2 adversarial BLOCK was a red
  `cargo test -p frp-core --no-default-features --all-targets` lane -- 749 passed / 4 failed because
  the pins baked in the kcp/quic rows -- fixed by `235ac0cc`). Residues filed below.

- [ ] **frp-rs's proxy-command flag *names* differ from Go's, not just their rendered text.**
  Filed by the `--help` cobra-rendering round (`TODO.md:253`), which prints the parser's own names with
  translated usage text. The proxy commands spell `--custom-domains`, `--subdomain`, `--mux-port`,
  `--server-name` where Go v0.71.0 has `--custom-domain` (shorthand `-d`), `--sd`, `--mux` (and `--sk`
  on stcp/xtcp). Closing the gap is a **parser** change (add Go's names as aliases, or rename and keep
  the old spelling as an alias), not a rendering change. **Done-when:** every proxy flag Go accepts is
  accepted here under Go's spelling, pinned by an argv probe per surface, and the rendered document
  shows Go's name.

- [ ] **Go's proxy-command shorthands are unimplemented.**
  Go v0.71.0's proxy commands carry `-i` (`--local-ip`), `-l` (`--local-port`), `-r` (`--remote-port`),
  `-s` (`--server-addr`), `-P` (`--server-port`) and `-n` (`--proxy-name`); frp-rs's parser never
  implemented them, so `frpc tcp` renders only `-t` (`--token`) and every shorthand above is rejected.
  Filed with the same round's residue (`TODO.md:253`). **Done-when:** each shorthand parses to its Go
  flag, pinned by an argv probe, and the rendered row matches Go's.

- [ ] **Six residual weaknesses in the help-document pins.**
  Measured by the `feat/cobra-help-rendering` round-4 adversarial review (`TODO.md:253`), all LOW/NIT
  and none blocking the render:
  1. **Inert pin data**: a bogus `GoFlagRow` in `FRPS_EXTENSION_FLAGS`
     (`frp-core/src/cli.rs:2344`), a re-worded `allow-users` row (`:2148`), or a wrong `SURFACES`
     Go-byte/label column (`:8540-8556`) leaves all twelve tests green -- the pins that read those
     fields are not themselves falsified by the data they read.
  2. **`row_long_flag` misreads cobra's footer**: `frp-core/src/cli.rs:9097-9105` returns
     `Some("--help\"")` for `Use "frps [command] --help" for more information about a command.`
     (`FRPS_DOC:8661`, `FRPC_DOC:8698`), contradicting its own doc comment (`:9086-9089`); inert
     today, so a two-line fix (require indent 2/6 with a leading `-`, or bail when the line has no
     two-space grid gap).
  3. **CI never runs the feature-split shapes**: the pins run with kcp and quic both off or both on;
     kcp-only and quic-only are compiled (`.github/workflows/ci.yml:1487`, `:1507`, `:1534`) but
     never executed.
  4. **An unreachable assertion**: `frp-core/src/cli.rs:9160-9167` cannot fail with teeth.
  5. **Weakening survives**: `assert_eq!(removed, 1, ...)` (`frp-core/src/cli.rs:9079-9082`) back to
     `>= 1`, or `:9099` `> 6` -> `> 60`, keeps all twelve tests green.
  6. **`zip(SURFACE_DOCUMENTS)` truncates** (`frp-core/src/cli.rs:8981`, `:9006-9027`,
     `:9175-9199`), so a sixteenth surface in one list survives.
  **Done-when:** each of the six is either fixed or shown to be unreachable, with the mutant that
  demonstrated it now red.
- [x] **`auth.method` parsing is inconsistent across its three sites; a typo silently selects token
  auth.** Measured 2026-09-25 by the adversarial review on this branch, with real binaries:
  - *Client*: `frp-client` compares `ac.method == "oidc"` (feature-on arm, the new refusal helper and
    `frpc/src/main.rs`'s verify check), so with `oidc` **off**, `method = "OIDC"` and `" oidc"` still
    fall through to `Token` — the client connects and authenticates while the server lowercases and
    uses OIDC. With `oidc` **on** the same spelling makes the *client* do token auth against an OIDC
    server, and `frp-core/src/config/loader.rs:414` skips the OIDC client-credentials validation for
    it.
  - *Server*: `to_lowercase()` catches `"OIDC"`/`"Oidc"`, but `" oidc"`, `"oidc "`, `"OIDC "`, a
    Cyrillic-о lookalike and `""` all fall through the `_ => Token` arm and start a **token** server
    when a token is set. Pre-existing (the same spellings give token in an OIDC-on build too), but it
    is the exact silent-downgrade outcome the sibling fix closes for the canonical spelling.
  **Done-when:** one method-parsing policy at all sites — trim, compare case-insensitively, and decide
  (with a Go frp v0.71.0 source/probe check first) whether an unrecognised method is a load error
  rather than a token fallback — pinned by a probe per site.
  Done: fixed on `fix/auth-method-and-reload` (one commit; author's report
  `/tmp/auth-method-report.md`; review record in the PR). **The done-when's "trim, compare
  case-insensitively" was measured against Go and rejected**: `slices.Contains` over
  `SupportedAuthMethods` (`pkg/config/v1/validation/validation.go:37-40`, used at
  `validation/server.go:31` / `client.go:101`) is an exact match, so the policy is exact matching
  plus Go's `util.EmptyOr` fill (`pkg/config/v1/server.go:136-139`, `client.go:206-209`) — trimming
  or lower-casing would make frp-rs *accept* configs Go rejects with rc 1. Re-derived on the real
  v0.71.0 binaries (own config and free port per case, streams separate, rc from `wait`):
  `method = "OIDC"`/`"Oidc"`/`" oidc"`/`"oidc "`/`"tokenn"`/Cyrillic-о → **rc 1, 54 B stdout,
  0 B stderr**, whole stdout `invalid auth method, optional values are [token oidc]\n`; `""` and
  `"token"` start. frp-rs base vs head: `frps` `"OIDC"` rc 3 (parsed as OIDC) → **rc 1**, `" oidc"`/
  `"oidc "`/`"tokenn"` rc 0 *running as token* → **rc 1**, `""` runs in both; `frpc verify` on
  `"OIDC"` **rc 0 `is valid`** → **rc 1**; `frpc run` `"OIDC"` started a **token** client → rc 1 with
  Go's text; the client-credentials check no longer skips `"OIDC"`. Policy in
  `frp-core/src/auth.rs` (`complete_auth_method` + `parse_auth_method` + `INVALID_AUTH_METHOD`),
  called by the four sites (both validators, `frp-server`'s `build_auth_config`, the client's shared
  refusal helper and its construction parse). Pins: 3 unit tests in `frp-core/src/auth.rs`,
  `auth_method_is_completed_then_validated_exactly` in `frp-core/src/config/tests.rs`, 2 unit tests
  in `frp-client/src/service.rs`, 2 spawn tests in `frps/tests/cli_exit_codes.rs`, 2 in
  `frpc/tests/cli_exit_codes.rs` (which also run in the `tiny` lane, where the binary is
  `frpc-tiny`). Both guards moved in the same commit — `FRPS_CLI_TESTS` 27 → **29**,
  `FRPC_TINY_CLI_TESTS` 11 → **13** — and both guard shells were driven locally, red at the old
  literals. Falsified: deleting `parse_auth_method` from both validators reddens the four CLI pins.
  Recorded divergence: frp-rs prefixes the loader line with `<path>: ` where Go's is bare.
- [x] **The client's admin-triggered reload never re-derives auth, so an OIDC config reload reports
  success.** Measured 2026-09-25 by the adversarial review: with a running `frpc-tiny` (oidc off) and
  an OIDC config file, `frpc-tiny reload -c <file>` returns rc 0 with
  `reload success: reload success: no changes detected` and **zero** log lines mentioning
  oidc/auth — `reload_from_sources` diffs proxies and never re-parses auth (auth is startup-only).
  The server's SIGUSR1 reload is the opposite: it logs the refusal and keeps the old config. Pre-existing
  and out of the sibling item's scope. **Done-when:** a reload that changes `auth.method` either
  re-derives auth (rejecting a method this build cannot serve) or reports that auth changes need a
  restart, pinned by a probe.
  Done: fixed on `fix/auth-method-and-reload` (same change). **Decision: refuse, not re-derive** —
  `Service::auth_cfg` and `Service::encryption_key` are not behind a lock and the bridge key is
  copied by value into the live control connection, so a mid-flight swap cannot reach the running
  session and would leave its two ends disagreeing; Go's client is the same shape (its reload
  re-reads proxies and visitors only, `client/service.go:494-525`). `reload::auth_reload_refusal`
  compares the newly loaded `[auth]` against `Service::cfg.auth` (which nothing writes after
  construction) after the load and store merge and before any proxy/plugin/visitor work, and returns
  an error naming the changed field(s) — names only, never a token or secret value. Pinned by
  `frp-client/tests/reload_malformed_config.rs::reload_that_changes_auth_is_refused_and_applies_nothing`
  (a loader-rejected `"OIDC"` rewrite and a loader-**accepted** `additionalAuthScopes` rewrite, each
  also moving the proxy, plus a positive control that a non-auth rewrite still applies) and by 5 unit
  tests in `frp-client/src/reload.rs`. Falsified: deleting the `auth_reload_refusal` call reddens the
  integration test (the auth change then applied and moved the proxy). The first cut of that test was
  **vacuous** — it used flat `oidcClientID` keys and the loader refused its "accepted" arm for an
  unrelated reason, so it stayed green with the check deleted; that is recorded in the test's
  comment. `docs/deployment.md` lists the new admin-API 400 source. Not covered: an `auth.method`
  change on the **server**'s SIGUSR1 reload is neither refused nor separately tested (the server does
  rebuild `auth_cfg` when the token changes). Measured by the second reviewer and re-measured here,
  the server half is worse than "not covered": a `method = "token"` → `"oidc"` change with the same
  token and unchanged OIDC fields is reported as **`config reloaded: no changes detected`** while the
  file now says `oidc`. It is filed as its own item immediately below, and it is **outside this
  item's scope** (this item is the client's admin reload).
- [x] **The server's SIGUSR1 reload compares neither `auth.method` nor the running verifier, so a
  method change can be reported as `no changes detected` or leave `auth_cfg` on `oidc` with no
  verifier.**
  Measured 2026-09-28 on this tree with the `frps` built from this worktree — own config and free
  port per case, stdout/stderr separate, child bounded and reaped; this is a **probe**, not a code
  read (script `/tmp/amp/server_reload_probe3.sh`, logs kept):
  * **Shape A — silently ignored.** Running config: `method = "token"`, one token, and the OIDC
    fields already present and unchanged (`oidc_issuer`, `oidc_audience`). Rewrite to
    `method = "oidc"` (same token, same OIDC fields) + `kill -USR1` →
    `SIGUSR1: config reloaded: no changes detected`. The file says `oidc`; the server kept token
    auth, and nothing in the reload output mentions auth.
  * **Shape B — swapped without a verifier.** The same, with the token changed too →
    `SIGUSR1: auth token updated`. `reload()` then assigns the whole new `AuthConfig`
    (`frp-server/src/service.rs:2068-2072`; the item first cited `:2057-2061`, which is the
    `allow_ports` arm — corrected when this item was closed), so the live `auth_cfg.method`
    becomes `Oidc`, while
    `state.oidc.verifier` is built **once** at startup (`frp-server/src/service.rs:215`, `if
    auth_cfg.method == AuthMethod::Oidc`) and is still `None`. The login dispatch keys off the
    **verifier's presence**, not the method (`frp-server/src/control/login.rs:299`, `else if let
    Some(ref verifier) = state.oidc.verifier`), so logins still take the token branch — with the new
    token. It fails closed only by accident of that dispatch; the config and the running auth
    disagree.
  * **Correction to the reviewer's wording, measured:** the reload is *not* always silent. When the
    **OIDC fields** change (issuer / audience / skip-expiry / skip-issuer / skip-audience /
    additional-audience / trusted CA), `frps` does print
    `OIDC settings changed (restart required)` (`frp-server/src/service.rs:2132-2142`), so a
    `token` → `oidc` rewrite that *adds* `oidc_issuer`/`oidc_audience` reports that line instead.
    Shape A needs those fields present **and unchanged** in the running config — reachable, because
    with `method = "token"` the loader validates none of them.
  * Adjacent behaviour, also measured, so the item is not read as "the server ignores auth reloads":
    an **invalid** spelling is refused by the loader before any of this (closed by the `auth.method`
    item above), and an OIDC config that fails `check_startup` is refused with its message
    (`oidc_audience is empty` → `SIGUSR1 reload: security misconfiguration: …`, old config kept).
  **What is missing is a comparison of the method itself:** the token arm (`:2068-2072`) compares
  `token`, the OIDC arm (`:2132-2142`) compares the OIDC fields, and neither reads `method`.
  **Done-when:** a `method` difference is either applied (rebuild/swap the verifier) or reported the
  way the OIDC fields already are — e.g. a `note_restart_change`-shaped arm on
  `self.cfg.auth.method` vs `new_cfg.auth.method`, or treating any `[auth]` difference as
  restart-required — pinned by a probe per shape above (A: not `no changes detected`; B: no
  `auth_cfg.method == Oidc` without a verifier), and either the login dispatch is keyed off the
  method instead of `Option<verifier>` or that invariant is stated and pinned. Pre-existing; **not**
  fixed by the client-side change that closed the item above.
  Done: fixed on `fix/server-reload-auth` (fix commit `360948e`, ledger commit `4d9b251`, fix-round
  commit after them on the branch). **Decision: report, not an in-place verifier swap.** The client
  half's reason for refusing ("the auth state is not behind a lock and the bridge key is copied by
  value") does
  **not** hold for the server's *credential*: `state.reloadable` is a `std::sync::RwLock` and the
  reload already swaps `auth_cfg` + the derived `encryption_key` through it. It **does** hold for
  the *verifier*: `state.oidc.verifier` is a plain `Option<Arc<OidcVerifier>>`
  (`frp-server/src/state.rs:649-653`) — not behind a lock, and not data the signal path can
  re-derive without a network round trip (it is built by an async JWKS fetch) — and it is read
  locklessly by four sites (`frp-server/src/control/login.rs`, `frp-server/src/handlers/dispatch.rs`,
  `frp-server/src/control/proxy.rs`, and the shutdown path's `stop_background_refresh()` at
  `frp-server/src/service.rs`), so swapping it on the signal path would add a fetch-failure mode to
  a path whose contract is "re-read the file", for a setting `docs/config.md`
  already documents as restart-required. The reload now applies the fields it can re-key in place —
  `auth.token` / `auth.tokenSource`, `auth.additionalAuthScopes`, and
  `auth.authenticationTimeout` / `auth.tokenAuthTimeout` (both read from the live `auth_cfg` on
  every use: `frp-server/src/control/login.rs:486-527`,
  `frp-server/src/handlers/dispatch.rs:68`/`:552`,
  `frp-server/src/control/nathole.rs:380`/`:575`) — and reports the rest as
  restart-required (`auth.method: token -> oidc (restart required)`, the existing
  `OIDC settings changed (restart required)` for the OIDC group).
  `auth.useEncryption` is the one `[auth]` field that is **neither applied nor reported**: nothing
  on the server reads `AuthConfig::use_encryption` (its only writer is `build_auth_config`; every
  other `use_encryption` in the crate is a different field), and Go's `AuthServerConfig` has no
  such field (`pkg/config/v1/server.go:129-135`; `UseEncryption` is `proxy.go:32` /
  `visitor.go:25`) — so a restart cannot make a change to it take effect either, and saying
  "restart required" would be false. The `AuthConfig`
  it puts live is the **running** one with only those five fields replaced — never the parsed
  struct, which is what made Shape B — so `auth_cfg.method` is the method the startup verifier was
  built for for the process's lifetime and `method == Oidc` ⟺ `verifier.is_some()`; that invariant
  is why the login dispatch is **not** changed and keeps keying off `Option<verifier>` (stated with
  its mechanism and its failure mode at `frp-server/src/control/login.rs:297-323`).
  Pins: `frp-server/tests/server_reload_auth.rs`, 6 tests (own config file in a `TempDir`, own free
  port and in-process `Service` each; live state read through `Service::state()`; real V1 token
  logins through `common::raw_login`) — Shape A (summary is not `no changes detected` and carries
  the method line; live method/token/verifier unchanged; T1 still logs in), Shape B (live
  `method == Token` **with the new token applied**, verifier still `None`, T2 logs in and T1 does
  not), a positive control (a matching file is still `no changes detected`, including
  `method = ""` vs `method = "token"`; a credential-only change still applies with no
  `restart required`), the widened field list (`oidcSkipNbf` → `OIDC settings changed (restart
  required)`; `authenticationTimeout` **applied**, exact summary
  `auth.authenticationTimeout: 90 -> 7; OIDC settings changed (restart required)` with the live
  window asserted to be 7; and `use_encryption = true` alone → `no changes detected`, the
  deliberate silent case), a `tokenSource` swap observed
  through the live source (both files start on `T1`, so only the live `token_source` — re-resolved
  per login — decides which token is accepted after file A is rewritten), and the dispatch's
  fail-closed answer (hand-written `method == Oidc` + no verifier → a token login is refused with
  `OIDC auth requires server-side verifier (not configured)`). Falsified against a pristine
  `0829774` tree (`git archive`) with the identical test file: **4 fail / 2 pass**; head 6/6.
  Probe: `/tmp/sra-probe/probe.sh` with a real `frps` per side (base built from the same pristine
  tree) and a real `frpc` — own config, own temp dir, own free port per case (54904/54907/54988/
  54991; `lsof` checked first, `ControlCe` holds 7000 on this host and the script never reuses it),
  `SIGUSR1` by pid, stdout/stderr to separate files, bounded settle, every child reaped with `wait`,
  exit status read directly, strays by `pgrep -x` only — base A `config reloaded: no changes
  detected`; base B `auth token updated` with a T2 login **refused** (`OIDC auth requires
  server-side verifier (not configured)`) and the `SIGUSR1:` line on **stdout** (0 B stderr); head A
  `auth.method: token -> oidc (restart required)`; head B
  `auth token updated; auth.method: token -> oidc (restart required)` with T2 accepted and T1
  refused (`token in login doesn't match token from configuration`). **Base B is worse than "the
  config disagrees": the lockout is total** — the login with the *previously working* token is
  refused with the same `OIDC auth requires server-side verifier (not configured)`, because the
  token path rejects every attempt once the live method says `oidc`, so that one reload takes the
  whole client fleet offline until the process is restarted. Full base/head table and the
  least-sure section: `/tmp/server-reload-auth-report.md`.
  **Citations corrected** (re-derived from `git show 0829774:frp-server/src/service.rs`; two
  independent reviewers had measured it): the token arm is **`:2068-2072`**, and `:2070`
  (`r.auth_cfg = Arc::new(new_auth_cfg)`) is the line that caused Shape B; the original
  `:2057-2061` is the `allow_ports` arm (`:2061` is `if *r.allow_ports != new_allow_ports`). `:215`,
  `control/login.rs:299` and `:2132-2142` check out as written. Both occurrences in this item's text
  are corrected above.
  The field list is compiler-enforced: `note_auth_restart_changes` destructures
  `AuthServerConfig` twice with **no `..`**, so a new `[auth]` field is an E0027 compile error —
  measured by adding a probe field to the struct + its `Default` (`cargo check -p frp-server`
  reported it twice, once per destructure) and reverted.
  Carriers: `frp-server/src/service.rs` (`reload()`'s apply block + `note_auth_restart_changes`),
  `frp-server/src/control/login.rs` (the invariant comment), `docs/config.md` § Server Config
  Reload, `README.md` § Server config reload (SIGUSR1), `docs/deployment.md` (systemd SIGUSR1
  comment), `CHANGELOG.md`.
  Gates (all re-run on the fix-round tree, the commit after `4d9b251`):
  `cargo fmt --all -- --check` clean; `cargo clippy --workspace --all-targets --all-features
  -- -D warnings` clean; `cargo test -p frp-core --lib` 966/0; `cargo test -p frp-server` rc 0
  (41 `ok` lanes, `server_reload_auth` 6/0, `reload_integration` guard ran);
  `cargo test -p frps` rc 0 (`cli_exit_codes` still lists 29); `cargo test -p frpc` rc 0; the tiny
  lane (`cargo test -p frpc --no-default-features --features tiny --test cli_exit_codes`) 13/0 and
  `RUSTFLAGS="-D warnings" cargo check --workspace --no-default-features --features tiny` rc 0;
  `bash scripts/repo-health.sh` rc 0; `bash scripts/compat-test.sh` **86 passed / 0 failed** vs Go
  frp v0.71.0 (full run, not a subset — the change is not on a wire path, it is run because the
  surface is the server's auth/reload; log `/tmp/sra-compat2.log`). That compat run is a **re-run**:
  the coordinating agent interrupted a live run at ~14:18 and a second independent full run on the
  frozen `4d9b251` binaries (another agent's, `/tmp/r2/compat-final.log`) finished only afterwards,
  so no run from that window is cited. The leak reproduced a third time — `pgrep -x frps` 33,
  `pgrep -x frpc` 50, all Go binaries under `/tmp/frp-compat-test/` with `PPID 1` (the item below
  records the same 33/50) — all 83 reaped by explicit pid, and the **84** orphans (34 + 50) left by
  the other agent's finished run were reaped the same way before this run started (their
  `compat-test.sh` had exited and their `TEST_DIR` was gone, so they were holding listeners for
  nothing). Both sweeps matched on the command line **and** `PPID == 1` **and** the absence of a
  live `compat-test.sh` — never by name alone; `pgrep -x` is 0 afterwards. The base-side
  falsification was re-run on the fix-round test file: **4 failed / 2 passed** on a pristine
  `0829774` tree, head 6/6.
  Not covered, stated rather than implied: the OIDC branch itself (needs a live issuer), and no
  `apply` implementation was ever built — the rejection of `apply` is a code-reading argument, and
  `auth.tokenSource` is compared by `Debug` shape (`ValueSource` has no `PartialEq`), which can
  over-report but not under-report. Both are recorded in the report's least-sure section.
- [x] **Every restart-only setting outside `[auth]` was silently ignored by the SIGUSR1
  reload.** Measured 2026-09-28 on this branch's fix-round head (the commit after `4d9b251`,
  `frps` built from that working tree; first measured at `360948e`) — own config, own free
  port (60981, 60982 in the first measurement; 49388 in the re-measurement; never 7000), `SIGUSR1`
  by pid, stdout and stderr to **separate** files,
  bounded settle, every child reaped with `wait`, strays by `pgrep -x` only; script
  `/tmp/sra-probe/probe-non-auth.sh` — **deleted during the #399 cleanup, re-derived from this
  item's text and recreated at the same path** in this round — run twice with identical summary
  lines (re-measured here: the `SIGUSR1:` lines are identical run to run, but the **byte counts are
  not the claim and are only approximate** — they move by a few bytes between runs of one probe,
  because the startup lines carry the port and its digit count varies, and by ~20 B between
  independent probes of the same shape (a reviewer's own probe measured 1701 / 2637 where this
  round's re-derived script measured 1719-1720 / 2654). What matters is the *shape*: stdout at the
  moment the summary is read, a larger archived stdout because the SIGTERM drain logs after that
  read, and 0 B stderr):
  * running `transport.heartbeat_timeout = 30` with `max_ports_per_client = 0`, rewritten to `60`
    and `7` + `kill -USR1` → `SIGUSR1: config reloaded: no changes detected` on **stdout**
    (**1702 B** stdout / **0 B** stderr at the moment the summary is read; the archived
    `/tmp/sra-probe/non-auth/frps.out` is **2638 B** because the SIGTERM drain logs after that
    read, `/tmp/sra-probe/non-auth/frps.err` 0 B — the probe prints both counts and both runs
    agreed byte-for-byte). Neither value is applied, and nothing in the summary
    names either field.
  `reload()` compares only `allow_ports`, `[auth]`, `bind_port`, `bind_addr` and the
  TLS file paths (`frp-server/src/service.rs`), so this is the same class as the item above,
  outside `[auth]`: `transport.*`, `udp_packet_size`, `vhost_http_timeout`, `user_conn_timeout`,
  `web_server.*`, `http_plugins`, `max_ports_per_client` / `max_conns_per_proxy` /
  `max_proxies_per_client`, `[log]` and the rest take effect only on restart, and a reload that
  changes only those reads as a no-op. (The `[auth]` half of the class is closed above; the
  non-`[auth]` half is the part that would need a `ServerConfig`-shaped `note_restart_change`
  list.) **Done-when:** a reload that changes a restart-only setting outside `[auth]` names it in
  the summary — with a compiler-enforced field list, the way `note_auth_restart_changes` does for
  `[auth]` — pinned by a probe per field group; `[log]` (read once in `init_logging`, before the
  reload path exists) must be reported rather than silently ignored.

  Done (branch `fix/restart-only-settings`, `5c74455`). The list is
  `ServerConfig::restart_only_changes` (`frp-core/src/config/restart_only.rs`), filtered and printed by
  `note_restart_changes` in `frp-server/src/service.rs` and called from `reload()`. Both configs are
  destructured with **no `..`**, as are all eight config structs it walks, so a new field is a compile
  error until it is named and classified: measured by adding one probe field to each of the eight and
  re-checking — **16 E0027s**, two per struct (running and loaded pattern), every one in
  `restart_only.rs`; probe `/tmp/sra-probe/probe-compile-error.sh`, file restored afterwards
  (`git diff --stat frp-core/src/config/server.rs` empty). The list lives in `frp-core` and not next to
  the reload because the three `#[cfg]`-gated listener ports are gated on *frp-core's* features, which
  Cargo unifies independently of `frp-server`'s: a first draft written in `frp-server` was measured red
  in two lanes this tree already runs — `cargo test -p frp-server --no-default-features --all-targets`
  (E0027 on `kcp_bind_port`/`quic_bind_port`/`websocket_port`; the `frp-client` dev-dependency turns
  `frp-core/kcp` on while `frp-server/kcp` is off) and
  `cargo check --workspace --no-default-features --features tiny` (the mirror case, where an
  unconditional pattern entry would be E0026).
  Base/head per field group, real `frps` + `SIGUSR1` (base = `git archive 3f975e0`): base **3 OK /
  6 FAIL**, head **9 OK / 0 FAIL** on the same 9 cases, stderr 0 B everywhere, every child reaped with
  `wait`, `pgrep -x` 0 afterwards. The case above at head:
  `SIGUSR1: transport.heartbeat_timeout: 30 -> 60 (restart required); max_ports_per_client: 0 -> 7
  (restart required)`. `[log]` is reported, because all five `[log]` fields are read once in
  `init_logging`: `log.level: info -> debug (restart required)`.
  **Two over-reports found by review and fixed in the same round, each pinned by a test that fails
  against the pre-fix code** (falsification logs `/tmp/sra-probe/discrim/`): (a) the two `Option<u32>`
  limits were compared as raw options, so an absent `max_connections` / `max_accept_rate` printed
  `max_connections: <unset> -> 512 (restart required); max_accept_rate: <unset> -> 0 (restart
  required)` where base said `no changes detected` — both pairs are one setting, so the comparison is
  now on the value the server resolves (`frp_core::config::effective_max_connections` /
  `effective_max_accept_rate`, which `frp-server`'s `resolve_max_connections` and its accept-rate sites
  now delegate to, so the two cannot drift); `max_connections = 0` is *unlimited* and stays reported.
  (b) the three `#[cfg]`-gated listener ports (`kcp_bind_port`, `quic_bind_port`, `websocket_port`)
  were classed `ServerReader::Any` although their readers are `frp-server`-gated: in `cargo test -p
  frp-server --no-default-features --all-targets` — the lane that motivated this module's location —
  they printed `kcp_bind_port: 0 -> 17001 (restart required); quic_bind_port: 0 -> 17002 (restart
  required); websocket_port: 0 -> 17003 (restart required)` while `transport.quic_options` was
  correctly filtered. They now carry `ServerReader::Kcp` / `Quic` / `Websocket`. The second review round
  caught a first attempt at that fix which classed the first two as a **disjunction** with the dashboard
  (`KcpOrDashboard` / `QuicOrDashboard`): that reader does not exist — `frp-server/src/dashboard.rs`'s own
  `#[cfg(feature = "kcp")]` / `cfg(feature = "quic")` (`:501-502`, `:2491-2494`) are *frp-server's*
  features, so it prints those keys only in a build that already has the listener compiled (measured: the
  dashboard-only config printed `kcp_bind_port: 0 -> 17001 (restart required); quic_bind_port: 0 -> 17002
  (restart required)`, and the repo's own `dashboard::v2::tests::test_serverinfo_go_shape` fails there with
  `missing Go key kcpBindPort`). The disjunction is deleted and the pin's guards are the listener features,
  so the dashboard-only config — compiled by `ci.yml:916`'s clippy but test-run by no lane before this
  round — now asserts quiet and fails against the pre-fix classification.
  **Not over-reported** — a restart could not change these either, so the line would be false: the
  fields no code in `frp-server` reads (`auth.useEncryption` from the item above, `tls_server_name`,
  `web_server.pprof_enable`, `web_server.tls_ca_file` / `tls_server_name`, the nested `tls.*` fields
  (three unread, plus `cert_file` / `key_file`, which the loader's `normalize_web_server_section` renames
  onto the flat `tls_cert_file` / `tls_key_file` before deserialization, so the nested struct is
  unreachable), `[featureGates]` — each `_`-bound with its measurement and pinned by
  `unreported_fields_stay_unreported` / `inert_settings_are_not_reported`), `includes` (consumed by the reload's own `load_server_config`),
  and the applied set (`allow_ports` + `allow_port_start`/`allow_port_end`, the five `[auth]` fields,
  the TLS paths). Fields whose only reader is behind a feature are reported only where that reader
  compiles (`dashboard`, `ssh`, `quic`, `otel`) — the default `full` frps has `ssh` but not
  `dashboard`/`otel`, and both directions are asserted from whichever build runs the test. Credential-
  shaped values are never printed (`web_server.password`, `http_plugins`, whose `addr` may carry
  `user:pass@`).
  Carriers: `frp-core/src/config/restart_only.rs` (new), `frp-core/src/config/mod.rs`,
  `frp-core/src/logging.rs` (`OTEL_ENABLED` — the only way `frp-server`, which declares no `otel`
  feature, can ask whether the binary's OTLP reader exists), `frp-server/src/service.rs`,
  `frp-server/tests/server_reload_restart_only.rs` (new, 14 tests, run with default features,
  `--features dashboard`, `--no-default-features`, `--no-default-features --features dashboard`,
  `…,dashboard,kcp,quic` and `…,kcp,quic`), `docs/config.md` § Server Config Reload,
  `README.md`, `docs/deployment.md`, `CHANGELOG.md`.
  Gates: `cargo fmt --all -- --check` clean; `cargo clippy --workspace --all-targets --all-features
  -- -D warnings` clean; `cargo test -p frp-core --lib` 974/0 (was 966; +8 unit tests);
  `cargo test -p frp-server` rc 0, 659 passed / 0 failed over 42 lanes (`server_reload_auth` 6/0,
  `reload_integration` 4/0, `server_reload_restart_only` 14/0, and that target 14/0 in every config it is
  run in), the `ci.yml:628` dashboard lane (`cargo test -p frp-server --features dashboard -j 1` against a
  `frps --features dashboard` build) 720/0, and `cargo test -p frp-server
  --no-default-features --all-targets` 456/0 — with one honest caveat: the first run
  failed `reload_integration::test_reload_add_proxy` with `AddrInUse` on its own echo-server port,
  the documented `allocate_port` probe-then-drop race in that file's scaffolding (it signals **frpc**
  only, never `frps`, so this change cannot reach it); it passed on the quiet re-run. `cargo test -p
  frps` rc 0; `cargo test -p frpc` rc 0; tiny lane `cargo test -p frpc --no-default-features --features
  tiny --test cli_exit_codes` 13/0 and `cargo check --workspace --no-default-features --features tiny`
  rc 0; `bash scripts/repo-health.sh` rc 0; `bash scripts/compat-test.sh` **86 passed / 0 failed** vs Go
  frp v0.71.0 (relevant to the server config surface, but it does **not** exercise `SIGUSR1`, so it is
  not evidence about this path). The compat suite leaked its usual **83** orphans (all `PPID 1`, all
  under `/tmp/frp-compat-test/`, no live `compat-test.sh`), reaped by explicit pid after matching on
  command line and `PPID == 1`; `pgrep -x frps`/`frpc` are 0.
  Not covered, stated rather than implied: the inert list is a `grep` result, not a proof; the `otel`
  gate tracks `frp-core`'s feature, so a build that enables `frp-core/otel` through another member while
  the binary under test does not would over-report `[observability]`; the dashboard-gated and otel-gated
  groups are exercised in process, not end to end (the shell probe runs the default build);
  `OTEL_EXPORTER_OTLP_ENDPOINT` can mask an `[observability]` change; and `ServerConfig.tls_enable` has
  **no reader** in `frp-server`/`frps` (measured), so its pre-existing "restart required" line is very
  likely the same class of false positive this item is about — left alone here because it is base
  behaviour and this item counts the field among those `reload()` already compares, and **filed as its
  own item directly below** rather than left in a message. Full base/head table and the
  least-sure section: `/tmp/restart-only-report.md`.

- [x] **`tls_enable` is reported as restart-required, but nothing in `frp-server`/`frps` reads it.**
  `reload()` printed the line since before the restart-only list landed (the
  `note_restart_change(&self.cfg.tls_enable, …)` call in `frp-server/src/service.rs`), and the new list
  deliberately left it in place because it was base behaviour and the item above counted the field
  among the ones `reload()` already compares. First measured 2026-09-28 at `5c74455`, and re-measured
  on this branch at base and at head: `grep -rn tls_enable frp-server/src frps/src` finds **no read**
  of `ServerConfig.tls_enable` — the only hits are `presence.warn_inert_web_server_tls_enable()` (the
  **different** field `[web_server.tls] enable`, #402) and a comment — so a reload that changes only it
  printed `tls_enable: false -> true (restart required)` and a restart changed nothing. Go v0.71.0 is
  the same shape, so this is *not* a parity gap: its `ServerConfig` has no `TlsEnable` at all,
  `TLS.Enable` is a **client** field (`pkg/config/v1/client.go`, read by
  `pkg/config/v1/validation/client.go:155`), and the legacy INI `tls_enable` maps to
  `Transport.TLS.Enable` (`pkg/config/legacy/conversion.go:60`) which no server path reads — the
  server's switch is `TLS.Force`, i.e. `tls_only` (`conversion.go:150`,
  `pkg/config/v1/server.go:195`).

  **Measured disposition: the field is inert, so the false line is removed** — the
  `[auth].useEncryption` precedent in `note_auth_restart_changes`: nothing reads the field, so neither
  a reload nor a restart can make a change take effect, and the reload must not claim one. The field
  now sits in `frp-core/src/config/restart_only.rs`'s existing no-reader group (named in the no-`..`
  destructure and never pushed) with `tls_server_name`/`feature.gates`/`includes`, no second mechanism
  invented, and the `reload()` call site is gone. Pinned by `inert_settings_are_not_reported` in
  `frp-server/tests/server_reload_restart_only.rs`, which rewrites `tls_enable = true` and asserts
  `config reloaded: no changes detected`; putting the line back makes that test fail with
  `tls_enable: false -> true (restart required)`. The unit test `unreported_fields_stay_unreported` in
  `restart_only.rs` also asserts the field yields no report.

  Done: removed the `note_restart_change` call, moved `tls_enable` into the no-reader group, and
  updated the doc bullets plus the test doc comment that claimed the reload reported it. The
  user-visible reload-output change also owes its collateral, done in the same round: a `CHANGELOG.md`
  bullet recording the removal (with the #400 bullet's "every restart-only difference is now
  reported" qualified to "…that some code reads"), `tls_enable` added to the no-reader example lists
  in `README.md` and `docs/deployment.md`, and three `docs/config.md` corrections — the false
  `tls_enable` table row (it claimed to enable TLS on the main listener), its removal from the
  "requires a full restart" list, and the no-reader list becoming eight fields. The same defect
  class — a live, user-facing place presenting `tls_enable` as a working server knob — had two
  further carriers, both corrected by follow-up commits on this branch: `docs/architecture.md:342`
  claimed the server's QUIC listener "requires `tls_enable`", when its gate is
  `#[cfg(feature = "quic")]` + `quic_bind_port > 0` (`frp-server/src/service.rs:1541-1542`) and the
  listener self-generates a self-signed cert, so the parenthetical now reads "requires the `quic`
  feature, which implies `tls`" (grounded in `frp-core/Cargo.toml:66`
  `quic = ["dep:quinn", "tls"]`); and the root `frps.toml:26` sample wrote `tls_enable = true`
  under `## TLS` — the one line the open warning item below would make `frps -c frps.toml` warn at
  itself on every start — which is deleted, after checking that no test/script/CI job reads the
  root sample (the scripts generate their own temp copies; the lone test naming the repo example
  uses an inline literal). Full record with commands and outputs: `/tmp/tls-enable-report.md`.

- [x] **`tls_enable` is silently inert: no load-time warning, unlike the sibling `[web_server.tls]
  enable` that #402 made warn.** Measured on this branch (the `grep -rn "\.tls_enable"` above): no
  `frp-server`/`frps` code reads `ServerConfig::tls_enable`, yet a config that writes
  `tls_enable = true` loads without a word — the user gets neither an effect nor a warning, where
  `[web_server.tls] enable` at least says `… has no effect: …` at every load site that has a log
  sink. The existing mechanism to reuse is the `web_server.tls.enable` presence flag carried out of
  the loader and emitted by each site (`presence.warn_inert_web_server_tls_enable`, called from both
  `frps` startup paths); do not invent a second one.

  Done-when: a load carrying a user-written `tls_enable` warns once per load at every load site that
  has a log sink (the two startup paths, `frpc verify`, and the `frps`/`frpc` SIGUSR1 reload), with a
  test that fails if the warning is removed, and the warning must **not** fire on the legitimate
  legacy path below. **Closed with one correction to that list** — the `frpc verify` and `frpc` SIGUSR1
  entries are wrong for this item: those sites load a `ClientConfig`, whose `tls_enable` is *live*
  (`frp-client/src/control.rs` reads it to decide whether the control connection is encrypted), so a
  "no effect" warning there would be a false claim. The measured list is in the close note below.
  The caveat that makes it non-trivial: `frp-core/src/config/normalize.rs`
  **synthesizes** `tls_enable = true` when the legacy/canonical `[transport.tls]` has `force = true`
  or `certFile`/`keyFile` (while mapping `force` → `tls_only`), inserting it with `.or_insert` before
  deserialization — so after the load a synthesized value is indistinguishable from a written one,
  and the presence flag must be taken from the file (beside the existing `web_server.tls.enable`
  flag), not from the deserialized `ServerConfig`.

  **Done (branch `fix/tls-enable-warning`, based on `60624a3`).** Full record with every literal
  command, output and exit code: `/tmp/tls-enable-warn-report.md`. The premise was re-measured before
  anything was built and holds: `grep -rn "\.tls_enable" frp-server/src frps/src` (rc=0) returns only
  two comment lines — `frp-server/src/service.rs:2290` and `:2448` — and no reader, while the *client*
  field **is** read (`frp-client/src/control.rs:389`, `self.tls_enable || matches!(…, Quic)`), which
  is what makes the new warning server-only. The written spellings were measured, not assumed:
  `ServerConfig` has no `rename_all` and no alias on the field (`frp-core/src/config/server.rs:11-12`,
  `:42-43`), so `grep -rn "tlsEnable" frp-core/src frps/src frpc/src` (rc=0) finds it only inside the
  test that pins its rejection; `grep -n '"enable"' frp-core/src/config/strict.rs` exits 1; and the
  server `[transport.tls]` flatten at `frp-core/src/config/normalize.rs:802-809` has no `"enable"` arm
  (the client's, at `:1358-1373`, does). Three raw spellings count as written — a top-level
  `tls_enable`, one under `[common]`, and a literal `tls_enable` *inside* `[transport.tls]`, which the
  lift's catch-all `other => other` arm hoists onto the same field (measured on the v0.71.0 `frps`:
  `[transport.tls] tls_enable = "yes"` fails with `invalid type: string "yes", expected a boolean`,
  while `= true` loads and emits the record) — whereas `[transport.tls] force = true` / `certFile` /
  `keyFile` **synthesize** it at `frp-core/src/config/normalize.rs:812-816`. The flag is therefore
  read from the raw value beside the existing one (`normalize.rs:559`; `process_includes` at
  `:533` has already run, so `includes` spellings are seen), never from the deserialized struct.
  The Done-when site list was **wrong on two of its four entries** and is corrected above: measured
  `grep -rn` over `frps/src frpc/src frp-server/src frp-client/src frp-core/src` (rc=0) gives three
  server-config load sites with a live subscriber — `frps/src/main.rs:222` (`--config-dir`),
  `frps/src/main.rs:315` (`-c`) and `frp-server/src/service.rs:2319` (SIGUSR1 reload) — plus
  `frps/src/main.rs:88` (`frps verify`), which deliberately never initialises logging and so has no
  sink. There is no `frpc` server-config site at all: `frpc verify` and the client reload load a
  `ClientConfig` whose `tls_enable` is live, so a warning there would be false and none is emitted.
  Change: `ConfigPresence::server_tls_enable_set_in` + `server_tls_enable_set()` +
  `warn_inert_server_tls_enable()` + the `SERVER_TLS_ENABLE_INERT_WARNING` const (all in
  `frp-core/src/config/loader.rs`, beside the sibling), the flag captured in `normalize.rs`, and the
  call added at the three sites above. Tests: new `frp-core/tests/server_tls_enable_warning.rs`
  (7 tests — the message names the inertness, `tls_only` and the real certificate source including the
  self-signed fallback; a written `true` **and** a written `false` warn exactly once in both loader
  modes; a synthesized `force` / `certFile`+`keyFile` load stays silent and `[transport.tls] enable =
  true` never reaches the field; a literal `tls_enable` inside `[transport.tls]` — and under
  `[common.transport.tls]` — **is** a written spelling and warns; `[common]`, inline `common = { … }`
  and `includes` spellings; `tlsEnable` is not a written key; the string loader
  emits nothing); `frps/tests/warn_delivery.rs` +5 tests (delivery on `-c` and `--config-dir`, the
  `[common]` spelling, a written `false`, the synthesized negative control, and one more record after
  SIGUSR1 — 12 passed rc=0); `frpc/tests/warn_delivery.rs` +2 tests (the client `-c` run and
  `frpc verify` both print **zero** server-warning records, pinning that the live-field side stays
  silent — 8 passed rc=0). Gates, each literal exit code: `cargo fmt --all --check` rc=0;
  `cargo test -p frp-core --lib config` rc=0 (`335 passed; 0 failed`); `cargo test -p frp-core --test
  web_server_tls_enable_warning` rc=0 (`4 passed`) and `--test server_tls_enable_warning` rc=0
  (`7 passed`); `cargo test -p frp-core --no-default-features --all-targets` rc=0 (13 `test result:
  ok` lines, all green); the three isolated `-D warnings` lanes rc=0 each; and
  `bash scripts/repo-health.sh` rc=0 (`RESULT: invariants hold`). The CLI-count guards were
  re-measured because this change adds tests under `frps/tests/` and `frpc/tests/`: `cli_exit_codes.rs`
  still lists **29** (frps) and **13** (frpc tiny) via `-- --list`, so `.github/workflows/ci.yml`
  `FRPS_CLI_TESTS` / `FRPC_TINY_CLI_TESTS` are unchanged. The *warning-delivery* guards do move,
  because their steps pin the count in a **bare literal** (seven occurrences each, not the two the CI
  error message named): `frps/tests/warn_delivery.rs` lists **12** and `frpc/tests/warn_delivery.rs`
  **8** via `-- --list`, so every literal in those two steps was moved 7→12 and 6→8
  (`frps/tests/log_completion.rs`, still 5, was checked and left alone). Docs updated:
  the `docs/config.md` `tls_enable` row and inert-fields note, the server example (which no longer
  writes the now-warning key), and one `CHANGELOG.md` `### Fixed` bullet. Ledger after this close:
  28 open / 98 closed.

- [x] **The new server `tls_enable` warning's text is inaccurate on three measured points (#407).**
  Filed from the two independent round-2 reviews of #407 (frozen `2e060b0432101a41a944111e25f6416382044495`,
  merged as `8ff41e05f90b9673ac25d8ae082f112018f18238`). Both reviewers returned MERGE and rated all three
  **non-blocking**; they were filed rather than fixed so that the merge did not overrun its window.

  (a) **A new factual error, introduced by #407.** The new prose says the server `[transport.tls]` lift renames
  "only four Go keys (force/certFile/keyFile/trustedCaFile)". It renames **five** — `serverName => tls_server_name`
  is omitted, and that arm is visible in the very citation the sentence carries
  (`frp-core/src/config/normalize.rs:869-878`). Sites: `frp-core/src/config/loader.rs:379`,
  `frp-core/tests/server_tls_enable_warning.rs:27` and `:320`. The detector's behaviour is unaffected, which is why
  R2 rated it non-blocking — but it is a false statement added by a change whose whole subject was a false statement.

  (b) **A branch the message does not name.** With only `tls_cert_file` written (or only `tls_key_file`), `frps`
  emits the warning and then aborts startup with `TLS requires both cert_file and key_file to be set; got only one`
  (`frp-core/src/transport/tls.rs:308-326`). The emitted sentence is not false there, but it does not name the
  outcome the user actually gets.

  (c) **The mechanism prose is false for one combination.** `[common.transport.tls] tls_enable` warns even when a
  competing top-level `[transport]` table makes the `[common]` flatten drop the key whole:
  `frp-core/src/config/normalize.rs:586-589` does `table.entry(k).or_insert(v)`, so `[common]`'s `transport` never
  reaches the lift. R1 measured real `frps` warn=1 for `[transport] heartbeat_timeout = 30` +
  `[common.transport.tls] tls_enable = true`, while a temporary in-copy probe printed
  `competing.tls_enable=false alone.tls_enable=true`. The emitted sentence stays literally true — a dropped key
  genuinely has no effect — so what is wrong is the "hoisted onto the same inert field" wording in
  `frp-core/src/config/loader.rs:377-385`, the test header `frp-core/tests/server_tls_enable_warning.rs:29-34`, and
  the close note above. The sibling dashboard detector deliberately mirrors the drop and stays silent
  (`frp-core/src/config/loader.rs:310-328`), so moving this one has a precedent to follow or to distinguish.

  Done-when: (a) the count and the key list are correct at all three sites; (b) either the message names the
  half-written-pair abort or a half-written pair is deliberately made silent, with the reason stated; and (c) either
  the detector consults `[common]`'s `transport` only when the top-level `transport` is absent or not a table, or
  the mechanism prose is narrowed to what it actually models — the chosen behaviour pinned by a test that reds
  before the change.

  Fix (round 1: all three points; round 2: the micro-tier falsehood and the reviewers' cheap items;
  every count re-measured on this tree).
  (a) **Corrected at five carriers, not four.** A sentence-level sweep (`grep -rn -i four` over `*.rs`/`*.md`,
  then reading each hit's sentence) found the four this item's table carried plus a fifth a phrase-level sweep
  misses: `docs/config.md:176` — "The four Go-shaped TLS fields (`tls_only`, `tls_cert_file`, `tls_key_file`,
  `tls_ca_file`) are carried by the nested `[transport.tls]` section instead" — which omits `tls_server_name`.
  All five now say five and list `serverName` => `tls_server_name`: the `server_tls_enable_set_in` doc comment and
  its inline comment in `frp-core/src/config/loader.rs`, `frp-core/tests/server_tls_enable_warning.rs:27` and
  `:320`, and `docs/config.md:176`. The lift's five arms are measured by
  `test_go_v0701_server_transport_tls_toml` (writes all five Go spellings, asserts all five flat fields; rc 0).
  A probe of the **real Go v0.71.0 `frps`** (`/private/tmp/frp_0.71.0_darwin_arm64/frps verify -c` on a
  `[transport.tls]` with all five keys) exits 0 — all five are Go's server spellings, not frp-rs inventions (an
  unknown key in that table exits 1, `json: unknown field "bogusKey"`). Round 2 re-grepped for the **old**
  `normalize.rs` ranges rather than the new ones and corrected every live carrier: `docs/config.md:25`,
  `docs/config.md:375` and two source doc comments at `frp-core/src/config/tests.rs:2061` / `:2137` now carry the
  measured ranges (`:869-878` arm match, `:865-884` synthesis, `:652-655` `[common]` flatten, `:1429-1437` client
  match, `:1379-1399` client fold). Older closed ledger entries (the #407 item above, `TODO.md:695`/`:696`) keep
  their era's line numbers, which is why the round-1 "in every sentence" claim was dropped. `docs/config.md:375`
  was also **reworded**: both reviewers read its four-spelling list differently, and the client lift measurably
  maps **six** nested spellings (`normalize.rs:1429-1437`), so it now scopes the four to the four alias-less
  fields and names `serverName` / `disableCustomTLSFirstByte` as the two further nested mappings.
  `frp-core/src/config/tests.rs:5962` (`web_server.tls`, genuinely four) was checked and left.
  (b) **The pair clauses are now build-aware and cover both delivery paths.** Round 2's blocking finding: the
  acceptor block is `#[cfg(feature = "tls")]` (`frp-server/src/service.rs:603`) but the warning is not, and
  `release.yml` ships `frps-micro`. Measured on a real `frps-micro` (`/tmp/tls-warn-probe/run-micro.sh`):
  `tls_enable = true` + only `tls_cert_file` exits **0** and logs `frps listener started on 0.0.0.0:27331` (no
  refusal), and with neither file there is no auto-generated line either. So the constant is two `cfg` variants:
  the `tls` build says "…a half-written (only one of the two) or unreadable pair is refused at startup, a reload
  reports the failure and keeps the running acceptor, and with neither set the server auto-generates a
  self-signed certificate pair", and the no-TLS build says only "This build has no TLS support (frp-core's `tls`
  feature is off), so the server never builds a TLS acceptor". Both paths were measured on the real `frps`
  (`/tmp/tls-warn-probe/run-b.sh`, `run-reload.sh`; stdout/stderr separate, children bounded and reaped): at
  startup a half-written pair exits **1** (`TLS requires both cert_file and key_file to be set; got only one`),
  an unreadable pair exits **1** (`open cert file: No such file or directory`), and on a SIGUSR1 reload either
  shape **keeps the server running** with `TLS certificate reload FAILED: … (keeping old config)` — hence
  "refused at startup", not "the server refuses to start". Both variants are pinned by
  `the_message_names_the_inertness_the_real_switch_and_the_certificate`, which splits its facts by the same
  `cfg(feature = "tls")` and asserts the no-TLS variant names **no** certificate behaviour (the F1 lesson).
  (c) **Moved the detector** — the first branch; the sibling `web_server_tls_enable_set_in` already keeps the
  invariant that the flag must not claim a key the loader dropped. `[common]`'s flatten is
  `table.entry(k).or_insert(v)` on the whole value (`frp-core/src/config/normalize.rs:652-655`), so a written
  top-level `transport` — table or not — discards `[common]`'s `transport` whole and the lift at
  `frp-core/src/config/normalize.rs:861-885` never sees it; the nested `[common.transport.tls] tls_enable` now
  counts **only** when no top-level `transport` key is written. Measured on the real `frps`
  (`/tmp/tls-warn-probe/run-c.sh`): `[common.transport.tls] tls_enable` alone -> warn **1** before and after
  (must keep warning); beside `[transport] heartbeat_timeout = 30` -> warn **1** before, **0** after; a flat
  `[common] tls_enable` beside the same competing table -> **1** before and after; a top-level non-table
  `transport = 30` -> the load itself fails (`invalid type: integer 30, expected struct ServerTransportConfig`,
  exit 1) before any warning, so "absent or not a table" and "absent" are indistinguishable at the warning. The
  test `common_transport_tls_needs_no_competing_top_level_transport` now pins all **six** load cases (alone,
  competing, flat-`[common]`, empty `[transport]`, inline `transport = {}`, non-table) and **failed pre-change**
  (`competing: a dropped key must not be claimed`, rc 101). The empty-table cases close a pin-strength gap
  measured in the round-2 archive copy: a mutant that treats an empty `transport` as absent moves that shape
  0 -> 1 record while the round-1 tests stayed green (mutant-and-red in the round-2 report).
  Gates, round 2 (literal rc): `cargo fmt --all -- --check` **0**; `bash scripts/repo-health.sh` **0**;
  `cargo test -p frp-core --lib config` **0**; `cargo test -p frp-core --test server_tls_enable_warning` **0**;
  `cargo test -p frps --features dashboard --test warn_delivery` **0**; `cargo test -p frpc --test warn_delivery`
  **0**; `cargo test -p frpc --features admin --test admin_config_get_warning` **0**; `cargo clippy -p frp-core
  -p frps -p frp-server --all-targets --all-features -- -D warnings` **0**; `cargo build -p frps
  --no-default-features --features micro` **0** plus the real `frps-micro` probe above. Six CI count literals
  re-read with `-- --list` and unchanged (frps 29, frpc-tiny 13, log_completion 5, frps warn_delivery 12, frpc
  warn_delivery 8, admin_config_get_warning 4). Docs: `docs/config.md`'s `tls_enable` row gained the
  half-written/unreadable/reload/micro wording and a corrected `normalize.rs` citation, `:375` gained the six-arm
  client scoping, and the inert-fields note gained the `[common]`-nested condition; `CHANGELOG.md` gained one
  `### Fixed` bullet. Ledger after this close: **24 open / 106 closed**; the micro sibling filed below moves it
  to **25 open / 106 closed**.

- [x] **The sibling `web_server.tls.enable` warning makes the same build-unaware claim: in a build with no
  dashboard it still says the dashboard serves plaintext HTTP (filed from the round-2 review of #407's follow-up).**
  R1 measured it and this round reproduced it. `WEB_SERVER_TLS_ENABLE_INERT_WARNING`
  (`frp-core/src/config/loader.rs:258`) ends "…the dashboard HTTPS server is enabled by a non-empty
  `cert_file` + `key_file` pair; without that pair the dashboard serves plaintext HTTP", but the dashboard is
  `#[cfg(feature = "dashboard")]` (`frp-server/src/service.rs:567` and `:1710`) while this warning is not, and
  `release.yml:105-124` builds, tars and uploads `frps-tiny` / `frps-micro`. Measured on a real `frps-micro`
  (`/tmp/tls-warn-probe/run-micro.sh`, `run-micro.sh` case `micro_webserver_enable`, stdout/stderr captured
  separately, child bounded and reaped): a config with `[web_server.tls] enable = true` exits **0**, emits
  `web_server.tls.enable has no effect: … without that pair the dashboard serves plaintext HTTP`, and starts only
  the proxy listener — a second probe with `web_server.port = 27500` left TCP 27500 **closed** (`nc -z` rc 1)
  while the process stayed up. So the clause names a server that does not exist in the build that printed it.
  This is the same `#[cfg]` asymmetry as the server `tls_enable` warning fixed above, and it is **pre-existing**
  (not introduced by this series). **Done-when:** the emitted path is build-aware the same way the server
  `tls_enable` diagnostic now is (a `#[cfg(feature = "dashboard")]` variant, or wording true in both builds),
  and a test pins that a no-dashboard build names no dashboard behaviour — the server-side pin is
  `the_message_names_the_inertness_the_real_switch_and_the_certificate` in
  `frp-core/tests/server_tls_enable_warning.rs`; the sibling test file is
  `frp-core/tests/web_server_tls_enable_warning.rs`. Ledger after filing this item: **25 open / 106 closed**.

  **Closed** with the caller-supplied shape, the same one `server_reader_present` uses
  (`frp-server/src/service.rs:394`): `frp-core` has no `dashboard`/`admin` feature of its own, so a
  `#[cfg(feature = "dashboard")]` inside it is constant `false` in **every** configuration and would pin
  nothing. `WEB_SERVER_TLS_ENABLE_INERT_WARNING` keeps its exact text (the build that compiles a dashboard);
  the new `WEB_SERVER_TLS_ENABLE_INERT_WARNING_NO_DASHBOARD` (`frp-core/src/config/loader.rs:285`) says
  "web_server.tls.enable has no effect: this build has no dashboard support, so nothing reads the key and no
  dashboard HTTPS server is built"; and `warn_inert_web_server_tls_enable(&self, has_dashboard: bool)`
  (`frp-core/src/config/loader.rs:590`) picks between them. All eight call sites now pass a `cfg!`:
  `frps/src/main.rs:219`/`:311` and `frp-server/src/service.rs:2315` pass `cfg!(feature = "dashboard")`;
  `frpc/src/main.rs:527`/`:602`/`:776`, `frp-client/src/service.rs:4457` and `frp-client/src/admin.rs:771`
  pass `cfg!(feature = "admin")`. **Measured** on the real binaries (fresh `CARGO_TARGET_DIR` per tier,
  tier-named binary, stdout and stderr captured separately, child bounded and reaped, `nc -z` run while the
  process was still alive; `/tmp/wtls-probe`): `frps-micro` (build rc 0) and `frps-tiny` now print the
  no-dashboard sentence, leave TCP 27500 **closed** (`nc -z` rc 1) and start only `frps listener started on
  0.0.0.0:27381`; the **default** `frps` (`full`, no dashboard) prints it too (`nc -z` rc 1) — the shipped
  `frps` is a no-dashboard build, which is exactly why the old clause was wrong for it; `frps --features
  dashboard` keeps the pair clause and listens (`Dashboard listening on 127.0.0.1:27500`, `nc -z` rc 0);
  default `frpc` prints the no-dashboard sentence (then exits 1 on its own, `login_fail_exit` default `true`)
  and `frpc --features admin` the dashboard one. Pre-change, a pristine `66be9ce1` `frps-micro` built in a
  `git archive` copy and probed by the same harness printed the dashboard clause while leaving 27500 closed.
  **Pin:** `the_no_dashboard_build_names_no_dashboard_behaviour` in
  `frp-core/tests/web_server_tls_enable_warning.rs` asserts the shared needle
  `web_server.tls.enable has no effect` in both constants, that neither text contains the other (so the
  dispatch assertions are not vacuous), that the no-dashboard text contains **none** of `cert_file` /
  `key_file` / `plaintext HTTP` while stating its own build fact (`no dashboard support`, `no dashboard HTTPS
  server is built`), and that a load emits the variant the caller's build asks for. Proved **red twice** in a
  `git archive` copy with its own target dir: a mutant whose emitter ignores `has_dashboard` (rc **101**,
  panic at `frp-core/tests/web_server_tls_enable_warning.rs:377`) and one that appends the dashboard clause
  to the no-dashboard text (rc **101**, panic at `:335`). Gates (literal rc): `cargo fmt --all -- --check`
  **0**; `bash scripts/repo-health.sh` **0**; `cargo test -p frp-core --lib config` **0**;
  `cargo test -p frp-core --test web_server_tls_enable_warning` **0**; the same test with
  `--no-default-features` **0**; `RUSTFLAGS="-D warnings" cargo clippy -p frp-server --no-default-features
  --features dashboard --all-targets` **0**; `… clippy -p frp-client --no-default-features --all-targets`
  **0**; `… check -p frp-core --no-default-features --all-targets` **0**. Six CI count literals re-read with
  `-- --list` and unchanged (frps 29, frpc-tiny 13, `log_completion` 5, frps `warn_delivery` 12, frpc
  `warn_delivery` 8, `admin_config_get_warning` 4). Docs: `docs/config.md:192` now names both variants and
  which builds get each; `CHANGELOG.md` gained one `### Fixed` bullet.
  **Round 2 fixed the pin itself:** those eight `cfg!` arguments were pinned by nothing. Every needle the
  tests asserted was in *both* texts, and the only variant-distinguishing test passed `has_dashboard` as a
  **literal** argument, so a call site that hardcoded the wrong answer compiled clean and stayed green.
  (Reproduced by #411's round-2 review: both `frps` sites set to `cfg!(feature = "admin")`, built
  `--features dashboard`, printed "no dashboard support" while 27500 was genuinely open, with `frps`
  `warn_delivery` 12, `frpc` `warn_delivery` 8 and `frp-core --lib config` 342 all passing. Note the hole
  is the **boolean**, not the word: `cfg!(feature = "admin")` inside `frps` does trip the
  `RUSTFLAGS="-D warnings"` lanes with `unexpected cfg condition value: 'admin'`.) The clause is now
  asserted inside the existing tests, keyed on the build: `assert_clause_matches_this_build` in
  `frps/tests/warn_delivery.rs` (`cfg!(feature = "dashboard")`, also called from the SIGUSR1 reload test so
  the `frp-server/src/service.rs:2315` site is covered) and in `frpc/tests/warn_delivery.rs`
  (`cfg!(feature = "admin")`), plus `assert_clause_is_the_dashboard_one` in
  `frpc/tests/admin_config_get_warning.rs`, called from `assert_records` so all four tests reach it. The
  markers are `plaintext HTTP` and `no dashboard support` (`web_server.tls.enable has no effect` is in both
  and cannot tell them apart), and no test count changed (12 / 8 / 4). `ci.yml` gained a **default-feature**
  `frps` `warn_delivery` step — a separate step rather than an extension of the `cli_exit_codes` step,
  whose guard is `env.FRPS_CLI_TESTS` for a different file — because before it no lane ran that file
  without `--features dashboard`, which is what left the no-dashboard direction unobservable. Mutants
  re-run in a `git archive` copy with its own target dir: `frps/src/main.rs:219` → `false` is a no-op in the
  default lane (that lane's correct value) and reds the dashboard lane (rc **101**, panic at
  `frps/tests/warn_delivery.rs:398`), while → `true` reds the **default** lane (rc **101**, panic at
  `frps/tests/warn_delivery.rs:409`); each was restored and the copied file's sha256 returns to
  `e5edacf7dd83bccfc5e3d9e51a7a8cf3d68fdbdb663c20f10b7c3c82c80c9c04`. Both lanes green on the unmutated
  tree (12 passed each). Ledger after this close: **25 open / 107 closed**, measured by
  `grep -c '^- \[ \]' TODO.md` / `grep -c '^- \[x\]' TODO.md` — those read **26** open before this tick, so
  the filing note above already under-counted open by one; the closed count moves 106 → 107. Filing the
  `admin`-without-`tls` item below moves it to **26 open / 107 closed**.

  **Round 3 pinned the three call sites that were still unwitnessed** (both delta reviewers measured the
  round-2 "all eight pinned" claim as false). Site by site: `frps/src/main.rs:219`/`:311` and
  `frp-server/src/service.rs:2315` by `assert_clause_matches_this_build` in `frps/tests/warn_delivery.rs`,
  observed by both `frps` lanes (12 passed each); `frpc/src/main.rs:527`/`:602` by the same helper in
  `frpc/tests/warn_delivery.rs`, observed by the default step and — for `:527`, which only the
  `--config-dir` tests reach — by a **new** count-guarded step running
  `cargo test -p frpc --features admin --test warn_delivery` (8 passed), because before it the only lane
  that ran that configuration was the non-CI invocation, so a hardcoded `false` at `:527` survived every
  lane in CI; `:776` (`verify`) by the same helper through a new `assert_clause_matches_this_build_in(tag,
  out, err)` entry point, and its test needed the nested key added anyway — it wrote no
  `[web_server.tls]` section, so the record never fired and neither boolean was observable; and
  `frp-client/src/service.rs:4457` (client reload) by a new `assert_clause_matches_this_build` in
  `frp-client/tests/reload_warning_delivery.rs`, observed by the two existing `frp-client` lanes
  (`--features admin`, and `--no-default-features --all-targets -j 1`), one branch each.
  `frp-client/src/admin.rs:771` stays covered by `frpc/tests/admin_config_get_warning.rs` (4 passed).
  Self-run mutants in a private `git archive` copy with its own target dir, each restored by file copy and
  re-hashed to its saved value (`frpc/src/main.rs`
  `c54ac42efb075ca0b0b1e2f908858d8cb2dfcb2db477e86e55aef0c491a20b55`, `frp-client/src/service.rs`
  `ad749675ece8e0cc95fedd55c46cbbb29ea6daea334111988bfa015292c81104`, `frps/src/main.rs`
  `e5edacf7dd83bccfc5e3d9e51a7a8cf3d68fdbdb663c20f10b7c3c82c80c9c04`): `:776` → `false` reds the
  `--features admin` lane (rc **101**, `frpc/tests/warn_delivery.rs:403`) and is a no-op in the default
  lane (that lane's correct value), `:776` → `true` reds the default lane (rc **101**, `:414`);
  `:4457` → `false` reds `cargo test -p frp-client --features admin --test reload_warning_delivery`
  (rc **101**, `frp-client/tests/reload_warning_delivery.rs:100`), `:4457` → `true` reds
  `cargo test -p frp-client --no-default-features --test reload_warning_delivery` (rc **101**, `:111`);
  `:527` → `false` reds the new admin lane's command (rc **101**, 2 of the `--config-dir` tests,
  `frpc/tests/warn_delivery.rs:403`) while the default `frpc` lane and the admin config-GET lane stay
  green; and the round-2 `frps` pair (`:219` → `false` is a no-op in the default lane and rc **101** in
  the dashboard lane at `frps/tests/warn_delivery.rs:398`; `:219` → `true` rc **101** in the default lane
  at `:409`) re-runs unchanged. No test count moved (12 / 12 / 8 / 8 / 4 / 1 / 1 / 5 / 5 / 342), and no source
  crate was touched: `git diff 0ce218be -- '*/src/*'` is empty. Ledger unchanged by this round:
  **26 open / 107 closed**.

- [x] **The dashboard clause of the `web_server.tls.enable` warning is still wrong for an `admin`-without-`tls`
  client build.** Filed by #411's round-2 adversarial review; the item above is the two-variant fix it
  reviews. That fix picks the text from the caller's `cfg!`, and `frp-client`'s admin path passes
  `cfg!(feature = "admin")`. But `admin` does **not** imply `tls`: `frp-client/src/admin.rs:1149` gates the
  acceptor on `#[cfg(feature = "tls")]` and `frp-client/src/admin.rs:1164` discards the configured pair in
  the `not(feature = "tls")` arm. So `cargo build -p frpc --no-default-features --features micro,admin`
  (rc 0) is an `admin` build that prints the dashboard clause — "the dashboard HTTPS server is enabled by a
  non-empty `cert_file` + `key_file` pair" — while its admin listener logs
  `frpc admin server listening on 127.0.0.1:27598` with no `(TLS)` suffix and serves plaintext HTTP
  (measured on a real `micro,admin` binary: with `[web_server]` `user`/`password` configured a bare
  `GET /` is **401** and a credentialed `GET /api/v2/system/info` is **404**; with no credentials
  configured a bare `GET /` is **404**). That is the same class of falsehood the item above removed,
  one feature interaction further
  in. Done-when: the admin call sites (`frp-client/src/admin.rs:771`, `frp-client/src/service.rs:4457`)
  answer with `cfg!(all(feature = "admin", feature = "tls"))`, or a third text exists for "an admin server
  with no TLS" — whichever the maintainer prefers — and a test pins the emitted text in the
  `--no-default-features --features micro,admin` build, so the `admin`-without-`tls` combination names no
  TLS acceptor it cannot build. **Entanglement (recorded by round 3, not fixed):** whichever condition
  those two sites end up using, their pins must move with them — two of the three clause assertions are
  `cfg!`-keyed on `cfg!(feature = "admin")` (`frp-client/tests/reload_warning_delivery.rs:99`,
  `frpc/tests/warn_delivery.rs:402`), while `frpc/tests/admin_config_get_warning.rs` is gated whole-file
  (`#![cfg(all(feature = "full", feature = "admin"))]` at `:59`) and asserts the dashboard text
  unconditionally (`:291`/`:296`), so it needs re-keying only if that gate changes. A re-key is not
  self-witnessing at `frp-client/src/service.rs:4457`: measured there, `cfg!(feature = "tls")` and
  `cfg!(all(feature = "admin", feature = "tls"))` both leave both client reload lanes rc **0**, because
  `admin` and `tls` are correlated in every lane that runs that file — so whichever condition is chosen,
  that pin must be re-keyed deliberately and re-measured on a real build (the `frpc` site at
  `frpc/src/main.rs:776` does discriminate: `cfg!(feature = "tls")` there reds the new admin lane, rc
  **101**, `frpc/tests/warn_delivery.rs:403:9`, while the default lane stays rc 0).
  `docs/config.md:192` then loses the `admin`-without-`tls` caveat this filing added,
  because the sentence becomes unconditionally true again. Ledger after filing this item:
  **26 open / 107 closed**.
  **Done (PR #428, head `dbcf5cbf`).** No caller picks the text any more. `frp-core` exposes a three-valued
  `WebServerTlsEnableReader` (`frp-core/src/config/loader.rs:257`; `from_features` `:276`, `warning` `:286`;
  the three texts at `:330` dashboard, `:345` no-dashboard, `:368` no-TLS) and the crate that owns the
  feature pair answers it: `frp_client::web_server_tls_enable_reader()` (`frp-client/src/lib.rs:38`, its
  `admin` **and** `tls`) and `frp_server::service::web_server_tls_enable_reader()`
  (`frp-server/src/service.rs:420`, its `dashboard` **and** `tls`). All eight call sites were re-pointed
  (`frps/src/main.rs:343`/`:695`, `frp-server/src/service.rs:2333`, `frpc/src/main.rs:530`/`:647`/`:832`,
  `frp-client/src/service.rs:4458`, `frp-client/src/admin.rs:771`), so a `micro,admin` build — an `admin`
  server with no `tls`, the build this filing measured printing the dashboard clause — now gets the
  "this build has no TLS support" text. Pinned by the four cells of
  `frp-core/tests/web_server_tls_enable_warning.rs` and by the emitted **record** being compared
  byte-exactly through `frp-core/tests/common/mod.rs:88` `assert_record_is_exactly_the_message`; the
  `micro,admin` shape gets a count-guarded lane (`.github/workflows/ci.yml:1185`, literal 1). The re-key the
  filing's "Entanglement" paragraph demanded was therefore unnecessary — the condition lives in the owning
  crate, not at the sites — and `docs/config.md:192` now states the three-way rule. **Supersedes** the
  `cfg!`-passing design recorded in the item above: that paragraph's `has_dashboard` signature and its
  call-site line references (`frp-core/src/config/loader.rs:285`/`:590`, `frps/src/main.rs:219`/`:311`,
  `frp-server/src/service.rs:2315`, `frpc/src/main.rs:527`/`:602`/`:776`,
  `frp-client/src/service.rs:4457`) are historical.

- [x] **`docs/config.md` advertises four camelCase TLS aliases that no loader accepts.**
  The `tls_only`, `tls_cert_file`, `tls_key_file` and `tls_ca_file` rows at `docs/config.md:26-29`
  each name a Go-alias spelling (`tlsOnly`, `tlsCertFile`, `tlsKeyFile`, `tlsCaFile`), while
  `docs/config.md:173` in the same file states the opposite ("Exception: `tls_enable`,
  `tls_cert_file`, `tls_key_file`, `tls_ca_file` have no camelCase aliases — use the snake_case
  names") — and the loader agrees with the Exception, not the table. But that Exception sentence is
  itself incomplete and is the **third** site to reconcile: it omits `tls_only`, which also has no
  camelCase alias (the `tlsOnly = true` row below), and it does not mention that `tls_ca_file`
  *does* have a working alias, `tls_trusted_ca_file` (`frp-core/src/config/server.rs:48`), which the
  corrected sentence must not erase. Measured at `a928887` with a
  throwaway probe over `frp_core::config::load_server_config_from_str` (non-strict) and
  `frp_core::config::load_server_config_uncompleted(path, true)` (strict):
  * `tlsCertFile = "/cc.crt"` + `tlsKeyFile = "/cc.key"` → ignored; both fields stay `""`.
  * `tlsOnly = true` → ignored; `tls_only` stays `false`.
  * `tlsCaFile = "/cc-ca.crt"` → ignored; `tls_ca_file` stays `""` and `tls_only` stays `false`, so
    it does not even trigger the `tls_ca_file`-implies-`tls_only` fill at
    `frp-core/src/config/server.rs:539-540`.
  * all four together in strict mode → `unknown field "tlsCaFile" in config file <path>`,
    `unknown field "tlsCertFile" …`, `unknown field "tlsKeyFile" …`, and
    `unknown field "tlsOnly" in config file <path> — did you mean 'tls_only'?`; the snake_case
    control keys load `Ok`.
  So all four rows are wrong, `tlsOnly` included — not three of four. `frp-core/src/config/server.rs:43-51`
  declares those fields with `#[serde(default)]` and no alias for any of them; the only server-TLS
  aliases that exist are `tls_trusted_ca_file` (`:48`, → `tls_ca_file`) and `tlsServerName`
  (`:50`, → `tls_server_name`), and both do work. `frp-core/src/config/strict.rs` accepts
  `tlsServerName` (`:29`, `:207`) but lists none of the four camelCase spellings, which is why
  strict mode refuses them.

  Done-when, covering all three sites at once: (a) the four rows at `docs/config.md:26-29` name
  only spellings a loader accepts (the snake_case key where no alias exists, or the real alias
  where one exists); (b) the Exception at `docs/config.md:173` gains `tls_only` and keeps
  `tls_trusted_ca_file` as the working `tls_ca_file` alias; and (c) the accepted-spelling list in
  `frp-core/src/config/strict.rs` (`:29`, `:207`) stays the arbiter the docs agree with — with a
  test pinning the accepted/rejected spellings so the table cannot drift back.

  Done 2026-09-29 at `7323259` (docs) + `0e3912e` (test), branch `fix/config-tls-alias-docs`.
  Re-measured on this head with a throwaway probe over `load_server_config_from_str` (non-strict)
  and `load_server_config_uncompleted(path, true)` (strict):
  * `tlsOnly = true` → non-strict ignored, `tls_only` stays `false`; strict `unknown field
    "tlsOnly" in config file <path> — did you mean 'tls_only'?`.
  * `tlsCertFile = "/cc.crt"` → non-strict ignored, `tls_cert_file` stays `""`; strict
    `unknown field "tlsCertFile" in config file <path>`.
  * `tlsKeyFile = "/cc.key"` → same shape, `unknown field "tlsKeyFile" …`.
  * `tlsCaFile = "/cc-ca.crt"` → non-strict ignored, `tls_ca_file` stays `""` and `tls_only` stays
    `false` (it never reaches the fill at `frp-core/src/config/server.rs:539-540`); strict
    `unknown field "tlsCaFile" …`.
  * controls: `tlsServerName` and `tls_trusted_ca_file` load in both modes.

  Fix: `docs/config.md:26-29` now name `transport.tls.force` / `certFile` / `keyFile` /
  `trustedCaFile` — the keys `frp-core/src/config/normalize.rs:798-816` maps onto the flat fields —
  and the `docs/config.md:173` Exception names all five alias-less keys while keeping the two that
  work. `frp-core/src/config/tests.rs` pins rejected-and-accepted in both modes plus
  `known_server_keys()` membership. **Decision: the four camelCase spellings stay rejected** —
  adding them as serde aliases or to `known_server_keys()` would widen the acceptance surface away
  from Go, which has no flat `tlsCertFile` server spelling either.

- [x] **`docs/config.md` advertises four camelCase client TLS aliases that no loader accepts.**
  The **client** rows at `docs/config.md:297-300` name `tlsEnable` (`tls_enable`), `tlsCertFile`
  (`tls_cert_file`), `tlsKeyFile` (`tls_key_file`) and `tlsCaFile` / `tlsTrustedCaFile`
  (`tls_ca_file`) in their "Go frp Equivalent" column — the same defect the server rows had
  (`TODO.md:681`), in the other half of the table. None of those five spellings reaches the client
  loader. Measured on this head with a throwaway probe over
  `frp_core::config::load_client_config_from_str` (non-strict) and
  `frp_core::config::load_client_config(path, true)` (strict):
  * all four flat camelCase keys together (`tlsEnable = false`, `tlsCertFile = "/c.crt"`,
    `tlsKeyFile = "/c.key"`, `tlsCaFile = "/ca.crt"`) → ignored: `tls_enable` stays the `true`
    default and `tls_cert_file` / `tls_key_file` / `tls_ca_file` all stay `""`, while the snake_case
    controls (`tls_enable = false`, `tls_cert_file = "/s.crt"`, …) do take effect.
  * strict mode refuses each of them: `unknown field "tlsEnable" in config file <path> — did you
    mean 'tls_enable'?`, `unknown field "tlsCertFile" …`, `unknown field "tlsKeyFile" …`,
    `unknown field "tlsCaFile" …`, and `unknown field "tlsTrustedCaFile" …` (the extra spelling the
    `tls_ca_file` row advertises).
  `frp-core/src/config/client.rs:264`/`:266`/`:268`/`:270` declare `tls_enable`, `tls_cert_file`,
  `tls_key_file` and `tls_ca_file` with `#[serde(default)]` and **no** alias — a grep for
  `tlsEnable|tlsCertFile|tlsKeyFile|tlsCaFile|tlsTrustedCaFile` matches nothing in that file — and
  the client half of the strict list (`frp-core/src/config/strict.rs:150-156`, via `known_client_keys`
  at `:131`) carries only `tls_enable`, `tls_cert_file`, `tls_key_file`, `tls_ca_file`,
  `tls_server_name`, `tls_skip_verify` and `tlsSkipVerify` for those keys, plus `tlsServerName`
  (`:207`) and `disableCustomTLSFirstByte` (`:163`) for the two correct rows. The real flat spelling
  of the four is the nested `[transport.tls]` key that
  `frp-core/src/config/normalize.rs:1358-1373` flattens onto
  them (`enable`, `certFile`, `keyFile`, `trustedCaFile`). Two client rows are **right** and must not
  be erased: `tls_server_name` → `tlsServerName` (`docs/config.md:301`) and
  `disable_custom_tls_first_byte` → `disableCustomTLSFirstByte` (`docs/config.md:302`), both loading
  flat in both modes (`frp-core/src/config/client.rs:282-288`). (This sentence originally named
  `tls_skip_verify` → `tlsSkipVerify`; there is no such row — see the Done note.)

  Done-when: the four rows at `docs/config.md:297-300` name only spellings the client loader accepts
  (the snake_case key, or `transport.tls.<key>` where that is the Go spelling), the two working
  aliases stay, and a test pins the client accepted/rejected spellings the way
  `frp-core/src/config/tests.rs` now pins the server ones — without widening `known_client_keys()`,
  on the same Go-parity argument that kept the four server spellings rejected.

  Done 2026-09-29 at `272a867` (docs + test), branch `fix/client-tls-alias-docs` on base `52f02e7`.
  Correction to the item above: its "Two client rows are **right**" sentence named `tls_server_name`
  → `tlsServerName` and `tls_skip_verify` → `tlsSkipVerify`; there is **no** `tls_skip_verify` row in
  `docs/config.md` (`grep` matches none). The two rows actually right and kept are `docs/config.md:301`
  `tls_server_name` → `tlsServerName` and `docs/config.md:302` `disable_custom_tls_first_byte` →
  `disableCustomTLSFirstByte` (`frp-core/src/config/client.rs:282-288`, strict list
  `frp-core/src/config/strict.rs:207` / `:163`).
  Re-measured on this head with a throwaway probe over `load_client_config_from_str` (non-strict) and
  `super::file::load_client_config(path, true)` (strict): `tlsEnable = true` → non-strict ignored
  (`tls_enable` stays the `true` default); strict `unknown field "tlsEnable" in config file <path> —
  did you mean 'tls_enable'?`. `tlsCertFile` / `tlsKeyFile` / `tlsCaFile` / `tlsTrustedCaFile` → same
  shape, the three string fields stay `""`, strict `unknown field "<key>" in config file <path>`.
  Nested `[transport.tls]` with `enable`/`certFile`/`keyFile`/`trustedCaFile` loads in both modes;
  `tlsServerName` and `disableCustomTLSFirstByte` load flat in both modes.
  Fix: `docs/config.md:297-300` now name `transport.tls.enable` / `certFile` / `keyFile` /
  `trustedCaFile` — the keys `frp-core/src/config/normalize.rs:1358-1373` flattens onto the flat
  fields after the `[transport]` lift at `frp-core/src/config/normalize.rs:1310-1331` — and the client
  flatten block (`docs/config.md:373`) gains the same Exception the server block has, naming all four
  alias-less keys while keeping the two that work. The new pin test
  `test_flat_camelcase_client_tls_spellings_are_not_loader_spellings`
  (`frp-core/src/config/tests.rs:2140`) pins all five rejected spellings (non-strict ignored, strict
  refused by name), the nested spellings and both accepted aliases in both modes, and
  `known_client_keys()` membership. **Decision: the four camelCase spellings stay rejected** — adding
  them as serde aliases or to `known_client_keys()` would widen the acceptance surface away from Go,
  which has no flat `tlsCertFile` client spelling either. Ledger after this close: 29 open / 97 closed.

- [x] **`[web_server.tls] cert_file` — the nested section's own canonical spelling — is dropped silently
  in the non-strict loader, and refused in strict mode with a message naming a key the user never wrote.**
  Measured 2026-09-28 at `e6bda94` by loading config shapes through
  `load_server_config(path, strict)` (probe kept with that round, `/tmp/sra-probe/n1/probe2.rs`, run
  against the fix-round head):

  | spelling | `strict = false` (the reload path; `--strict-config=false`) | `strict = true` (Go's default; frps `-c`) |
  |---|---|---|
  | `[web_server.tls] cert_file` / `key_file` / `trusted_ca_file` / `server_name` / `enable` — snake_case, the struct's **canonical** serde names | `Ok`, and **all five values vanish**: nested struct at its default, `tls_cert_file = ""`, `tls_cert() = ""` | `Err`: `unknown field "web_server.cert_file" … did you mean 'certFile'?`, plus `web_server.enable`, `web_server.key_file` … `did you mean 'keyFile'?`, `web_server.server_name` … `did you mean 'serverName'?`, `web_server.trusted_ca_file` |
  | `[web_server.tls] certFile` / `keyFile` / `trustedCaFile` / `serverName` (camelCase) | `Ok`, mapped onto the flat fields (`tls_cert_file`, `tls_ca_file`, `tls_server_name`) | `Ok`, same |
  | YAML `webServer.tls.certFile` … | `Ok`, same as camelCase | `Ok`, same |
  | flat `web_server.tls_cert_file` / `tls_key_file` | `Ok` | `Ok` |
  | **both** flat and nested camelCase | flat wins (`tls_cert_file = "/flat/cert.pem"`) | flat wins |

  Mechanism: `normalize_web_server_section` (`frp-core/src/config/normalize.rs:1530`) removes the
  `web_server.tls` table and re-inserts **every** key at the parent level, renaming only the four Go
  spellings (`certFile` → `tls_cert_file`, …); every other key keeps its name, so `cert_file` becomes
  `web_server.cert_file`, which is not a field — dropped in non-strict mode, an unknown-field error in
  strict mode. Three things make that a defect rather than a quirk: (1)
  `frp-core/src/config/server.rs:968` declares the nested section with `cert_file` / `key_file` /
  `trusted_ca_file` / `server_name` as the **canonical serde names** and the camelCase spellings only as
  `alias`es, so the spelling that fails is frp-rs's own and the one that works is Go's; (2) the same
  struct's doc says the section is "Merged with the flat `tls_cert_file`/`tls_key_file` fields — the
  nested values take precedence when both are set", while the last table row shows the **opposite** (the
  flat key wins, because the rename uses `or_insert`), so the documented precedence cannot be exercised
  either; (3) the strict-mode error names `web_server.cert_file` — a path the user never wrote — and its
  `did you mean 'certFile'?` hint points at the other spelling of the same field. Go comparison, for
  calibration: Go's `WebServerConfig.TLS` is `*TLSConfig `json:"tls,omitempty"``
  (`pkg/config/v1/common.go:68`) whose fields carry camelCase json tags only (`common.go:76-84`), and
  Go's decoder is `DisallowUnknownFields: strict` (`pkg/config/load.go:158`) — on Go the nested spelling is
  necessarily camelCase and a `cert_file` key is refused, so the **silent** branch is frp-rs-specific,
  and the reload path always takes it (`load_server_config(&config_path, false)`,
  `frp-server/src/service.rs:2301`). **Done-when:** an explicit, test-pinned decision. I would **map the
  four snake_case spellings** in `normalize_web_server_section` (`cert_file` → `tls_cert_file`, `key_file`
  → `tls_key_file`, `trusted_ca_file` → `tls_ca_file`, `server_name` → `tls_server_name`; and decide
  `enable`, which nothing reads) and pin the precedence the struct's doc claims (nested over flat, so the
  rename must not silently lose to a flat key that is already set), with a load test asserting the value
  reaches `WebServerConfig::tls_cert()` in **both** modes. Mapping cannot break a config that works today
  — the spelling it fixes currently either errors or is dropped, and the camelCase spellings keep working
  — whereas the alternative (reject nested snake_case with an error naming `web_server.tls.cert_file`, the
  key the user actually wrote) is a smaller change but leaves the struct's canonical names unusable. Either
  way the test must fail on today's behaviour.

  Done 2026-09-29 at `ccff127` (+ the fix round's follow-up commit), branch `fix/web-server-tls-nested`
  (author round; full before/after table and the probes that produced it: `/tmp/wstls-report.md`; probes
  kept at `/tmp/wstls-probe/` (the 13-case table, before/after) and `/tmp/wstls-f1/` (the fix round's
  alias/per-mode matrix, base/shipped/fixed)). **Done-when chosen:** the mapping (the item's pick), and
  the struct's documented "nested takes precedence" was made true rather than the doc corrected —
  `or_insert` is now `insert`, so the nested value overwrites a flat key that is already set, in either
  key order within one `[web_server]` section (both measured; see the **qualification** below). The four
  snake_case spellings map to the same flat fields as the Go camelCase ones, and **both** spellings of a
  destination key are removed from the nested table so the loser cannot fall through to the parent-level
  re-insert. `enable` is a decision, not a mapping: **accepted and inert in both modes**, with a
  `tracing::warn!` when the key is present. Nothing reads `WebServerTlsConfig::enable` (the nested table
  is removed before serde and no `frp-server`/`frps` code reads it; `grep` finds only the struct, its
  construction sites and the `restart_only.rs` destructure that names it as unreachable), the dashboard
  TLS is driven by a non-empty cert/key pair, and Go refuses the key outright — its `TLSConfig`
  (`pkg/config/v1/common.go:76-84`) carries only `certFile`/`keyFile`/`trustedCaFile`/`serverName`, so
  `frps verify` exits 1 with `json: unknown field "enable"` (measured on the v0.71.0 binary by the
  fix-round review), which makes frp-rs's accept-and-warn a **deliberate divergence**: without the
  warning, `enable = true` and no pair leaves the dashboard on plaintext HTTP 200 with no diagnostic
  (measured end-to-end by the same review). The rejected alternative (wire `enable` to the cert/key pair)
  is pinned as harmful: `enable = false` beside a valid pair would silently disable a working dashboard
  TLS.

  **Fix round (two reviewers, both `MERGE after these fixes`).** The first attempt introduced a **base
  regression** it left unpinned: a **parent-level** serde alias beside the nested spelling of the same
  value (`[web_server] certFile` + `[web_server.tls] cert_file`) hard-failed in **both** modes with
  ``duplicate field `tls_cert_file` `` (all four destinations, TOML and YAML, server and client), where
  base loaded it under `strict = false` with the flat value — a new refused start on the reload path.
  The hoist now also removes the parent-level **alias** spelling before its insert, so the nested value
  wins there like everywhere else; base's *own* pre-existing duplicate of the same class
  (`[web_server] certFile` + `[web_server.tls] certFile`, both modes) closes with it. Pinned by
  `parent_level_alias_beside_nested_spelling_still_loads`, which fails on the frozen head (`/tmp/wstls-f1-falsify.txt`).
  The parent-level **snake** spelling (`[web_server] cert_file`, not a field) is deliberately *not*
  removed, so `check_strict` keeps reporting it
  (`parent_level_snake_spelling_is_still_reported_in_strict_mode`).

  **Correction — a claim in the first attempt was false.** The commit message, the report and the
  collision test's doc comment all said that writing `cert_file` **and** `certFile` together failed on
  the **base** tree with `duplicate field`, i.e. that it was a third, previously unrecorded base defect.
  It was not: base non-strict returned the camelCase value (`tls_cert() == "/camel/cert.pem"`) and base
  strict reported `unknown field "web_server.cert_file"`. The duplicate appears only in a
  **half-implemented mapping** (removing just the winner and letting the loser fall through to the
  re-insert) — a hazard of the implementation, not a pre-existing defect (both fix-round reviewers
  reproduced it as a scratch variant / mutant). Corrected here, in the test's doc comment, in
  `/tmp/wstls-report.md` §3/§8.2, and in the fix-round commit message. The honest count of the shipped
  test set failing against base is **7 of the 8** shipped tests/assertions — the seven unit tests plus the
  warning target's body, all compiled against `5717fa2` by `/tmp/wstls-extract-tests.py`
  (`/tmp/wstls-falsify-final.txt`; the single pass is the residue test, which has no discriminating power
  for this change and says so). The earlier text here said "3 of 4 new tests plus the extended client
  test" against a four-test harness — that was written before the fix round added the two
  `parent_level_*` tests, and `/tmp/wstls-falsify.txt` is only a 22-line tail of the original in-place
  run (2 of the 3 tests that existed then), which is why the harness above is the citable artifact.

  **Qualifications and out-of-scope findings, as they stood at this change (all three were measured
  then and all three are fixed now — see the `fix/webserver-tls-cluster` batch below, items A/B/C, and
  the close notes there).** (1) The precedence claim held for both spellings **inside one
  `[web_server]` section** only; a file that defined both `[webServer]` and `[web_server]` **discarded
  the whole `[webServer]` table** — including a nested `[webServer.tls]` — via `normalize.rs`'s
  `or_insert` section rename, so the flat `web_server.tls_*` value won. (2) The hoist **did not run for
  `.ini`**: the INI reader stored the section name verbatim, so `[webServer.tls]` became the literal
  top-level key `"webServer.tls"` and `[web_server.tls]` became `"web_server.tls"` — non-strict dropped
  the section, strict reported `unknown field "webServer.tls"` (measured in both trees). (3)
  `[web_server.tls] password = "…"` **landed on the real `web_server.password` field** (silent, both
  trees).

  **Tests** (all in `frp-core/src/config/tests.rs`, real files in their own temp dirs, accessor asserted,
  both loader modes): `nested_web_server_tls_spellings_reach_the_accessor_in_both_modes`,
  `both_spellings_of_one_nested_key_do_not_collide`,
  `nested_web_server_tls_enable_is_accepted_and_inert_in_both_modes`,
  `nested_web_server_tls_enable_warns_once_and_stays_inert` (captured with a `tracing_subscriber` writer),
  `unknown_nested_web_server_tls_key_names_the_true_nested_path` (renamed from
  `…_still_names_a_parent_level_path` when the batch corrected the path it pins),
  `parent_level_alias_beside_nested_spelling_still_loads`,
  `parent_level_snake_spelling_is_still_reported_in_strict_mode`, plus the client arm of
  `test_go_client_web_server_tls_flatten`. Docs carried in the same change:
  `frp-core/src/config/server.rs`, `frp-core/src/config/restart_only.rs` (two comments that the batch
  later re-derived), `docs/config.md`, `CHANGELOG.md`. `scripts/compat-test.sh` is not relevant (config
  loading, no wire byte).

- [x] **`oidc_throttle_tests` was filed as a load-dependent flake: the mock IdP answers 404 for a
  valid request.** `cargo test -p frp-server --lib oidc` failed **3/3** `oidc_throttle_tests` under
  CPU load with `OIDC: openid-configuration returned 404 Not Found`, while a serial run passes 6/6
  and the 469-test `-p frp-server --features dashboard --lib` run passes; measured 2026-09-25 by the
  first review round on `9c3ddd0`, whose change does not touch `control/login.rs`. Mechanism
  (established by measurement on **macOS**, with the pinned rustc 1.98.1): `oidc_mock_server` accepts
  on a **non-blocking** listener and **on macOS** the accepted stream inherits that mode — a fresh
  accepted stream's first `read` with nothing sent returns `Err(WouldBlock, os error 35)` — so the
  single `Read::read(&mut stream, &mut buf).unwrap_or(0)` returned 0 bytes whenever the accept beat
  the client's write, and the path fell back to `/` → 404. CPU load is what let the accept win; it is
  not a second cause. **The inheritance is platform-specific, so the race is macOS-only** — but that
  does **not** make the pre-fix 404 macOS-only, because the same `unwrap_or(0)` also swallowed EOF:
  on Linux the accepted stream is **blocking** (measured with the same rustc 1.98.1 in a
  `rust:1.98.1-slim` container, kernel 6.8.0/Ubuntu 24.04: a 500 ms `SO_RCVTIMEO` was waited out in
  515 ms, and a pre-fix-style single read — no mode change, no timeout — returned the full request
  304.7 ms after a client that slept 300 ms), so the *race* cannot flake the ubuntu lanes; but an
  **EOF is platform-independent**: a client that connects and half-closes before sending gives `n=0` →
  `/` → 404 on both (measured: 3.833 µs macOS, 1.625 µs Linux), and a **head split across writes**
  mis-routes on both (measured on Linux; the elapsed figure is shape-dependent and named with its shape —
  with the first write ~200 ms after the accept, `n=16`, `path="/.well-known"` → 404 in ~208 ms, while an
  immediate first write gives the same `n=16` and the same mis-route in 192 µs). The
  accumulation half of the fix is therefore load-bearing on Linux too, and the fix is **not** a Linux
  no-op. (No CI incidence is claimed for either shape — that was not measured; what is measured is that
  the old code produced the same 404 on both platforms, since the failing tests are the ones that
  exercise this mock.) Every `ci.yml` job is `ubuntu-latest` (the only macOS runner,
  `release.yml:134`, only builds).
  **Done-when:** the mock waits for the request line (or the tests retry), pinned by a looped run of
  the three tests under load.
  Done: fixed in this change, entirely inside `mod oidc_throttle_tests`: `read_request_head` clears
  `O_NONBLOCK`, bounds the whole wait with a 5 s deadline (an `SO_RCVTIMEO` no larger than the
  remaining budget) and accumulates through `\r\n\r\n` before routing; EOF is reported as `Eof` rather
  than mapped to an empty head; on expiry the mock answers an explicit `500` naming the cause instead
  of falling through to `/` → 404. Production is untouched:
  the mock is `#[cfg(test)]`-only and `verify_login_auth` never calls it; production accept paths use
  `tokio::net::TcpListener` (`frp-server/src/vhost.rs:1523`, `frp-server/src/tcpmux.rs:320`,
  `frp-server/src/service.rs:643`), and the only production `set_nonblocking` is the deliberate
  raw-splice pair in `frp-core/src/splice.rs:396-399`. Pins with literal rcs:
  `mock_idp_serves_a_request_that_arrives_after_accept` — a client connects, sleeps 0/5/20/50 ms,
  then sends — is the **race** pin: **red on `d1be6675`** on macOS (rc 101; the first delayed
  iteration was answered `HTTP/1.1 404 OK`), **green after** (rc 0). On Linux it is **green-before**
  (measured above), so it guards nothing in the ubuntu lanes; the **platform-independent** red-before
  pin is `mock_idp_answers_an_explicit_error_when_the_client_closes_before_sending` (a half-closed
  client got `404 OK` from the pre-fix read on both platforms). The rest of the guards are the
  helper-level pins, which force the accepted side non-blocking themselves:
  `read_request_head_waits_for_a_request_that_arrives_after_accept` (150 ms writer delay plus a
  measured elapsed floor), `read_request_head_times_out_on_a_client_that_never_sends` (200 ms
  deadline, bounded above and below),
  `read_request_head_reports_eof_when_the_client_closes_before_sending` (a half-close must be a fast,
  named `Eof`),
  `read_request_head_accumulates_a_head_split_across_reads` (two split points, one cutting the
  `\r\n\r\n` terminator in half), `read_request_head_rejects_an_over_max_head_without_a_terminator`
  (`TooLarge(8192)`, and fast) and `read_request_head_stops_at_the_terminator` (a pipelined tail in the
  same read is not appended to the head), plus
  `mock_idp_answers_an_explicit_error_when_no_request_line_arrives` (500 + cause, then the accept
  loop keeps serving) for the wait, the bound and the failure, and
  `mock_idp_stops_serving_after_the_stop_signal` (`send(())` really ends the accept loop — the listener
  is refused afterwards) with `mock_default_request_head_deadline_is_pinned` (the shipped 5 s value;
  its end-to-end effect is deliberately not exercised, which would cost 5 s per run). The new pins were
  demonstrated red against mutants: a single **blocking** read with the mode clear kept and no
  accumulation or truncation → rc 101, exactly the split, over-max and terminator pins fail while all
  **fourteen** other `oidc` tests stay green (the note said "ten" while the filter had 12 tests and
  still said "ten" at 14 — "twelve" appears in no committed note; the count moves with every pin
  added, so it is measured here, not carried);
  `TooLarge` guard deleted → rc 101, only the over-max pin fails (`got Eof`); terminator
  searched only in the newly-read chunk → rc 101, only the split pin fails; `Ok(0) => continue` →
  rc 101, the EOF pins fail (the helper one reporting `TimedOut` instead of `Eof`); the `break` deleted
  from the stop check → rc 101, only the stop pin fails (`the mock kept accepting connections after
  send(())`); the deadline raised to 60 s → rc 101, only the default-deadline pin fails;
  `buf.truncate(end + 4)` removed → rc 101, only the terminator pin fails. A broader single-read mutant
  that *also* drops the `set_nonblocking(false)` clear reds 8 of 17 (it reaches the three `oidc_*`
  originals, nondeterministically). Three mutants the round-3 review listed are deliberately **not**
  pinned, because none is a one-liner:
  removing the `remaining.is_zero()` guard (it needs a read that lands exactly on the expired budget),
  moving the size cap ahead of the terminator search (it needs a head that crosses 8192 bytes with its
  terminator in the crossing read), and the stop-latency gap (stated, not bounded). The **load
  sensitivity** is separate and statistical:
  **one sample on a shared host under stated ambient load, not a rate** — 50 iterations of the three
  original tests in the `frp-server` lib test binary (`--test-threads` default) failed **11/50** under
  8 concurrent `yes` CPU burners pre-fix (0/50 idle) and 0/50 after. Two independent runs of the same
  method on the same shared host gave pre-fix idle 1/50, loaded 21/50 (reviewer 1) and idle 0/50,
  loaded 0/50 at 50 iterations but 10/200 at 200 (reviewer 2). Reviewer 1 recorded the `loadavg`
  3.9–8.0 with other users active; reviewer 2's arms did not record it — so the ambient-load figure
  belongs to reviewer 1's samples only. The direction is reproducible, the literal rate is not. A
  trustworthy figure would need a quiet host, several samples per arm, and the ambient load recorded
  with each.

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

- [x] **`frp-core`'s test targets do not compile with no features.** Evidence:
  `RUSTFLAGS="-D warnings" cargo check -p frp-core --no-default-features --all-targets` exits
  101 — `could not compile frp-core (lib test) due to 2 previous errors`, `(test "kcp") due to 3`,
  `(test "xtcp_p2p") due to 20`, `(test "protocol_round14") due to 1`; sample errors `E0425 cannot find function 'connect_ws_raw'
  in this scope`, `E0432 unresolved imports frp_core::kcp::{dial_kcp, dial_kcp_with_driver,
  KcpListener}`, `E0425 cannot find function 'punch_udp_hole' in module frp_core::xtcp_p2p`.
  The `kcp`/`xtcp_p2p` integration tests and some lib tests have no `#[cfg]` gate for the
  features they need. `protocol_round14` is a different case — a lint-only failure:
  `unused_mut` at `frp-core/tests/protocol_round14.rs:24`, because the only mutation of that
  binding, `v.extend(...)` at `:198`, is `vnet`-gated and `-D warnings` promotes the unused
  `mut` to an error. **Done-when:** each such test carries its gate, so the command exits 0
  and the run can join the sibling isolated CI steps.
  Done: fixed in this change. `RUSTFLAGS="-D warnings" cargo check -p frp-core
  --no-default-features --all-targets` exits 0 (was 101). The four failing units were closed
  as follows, and closing them surfaced three further lib-test errors that the first two had
  masked (the same "only error reached" effect as the `ConnectionType` fix): two lib tests
  gated `#[cfg(feature = "websocket")]` (`frp-core/src/transport/mod.rs`), `TokenEndpointCapture`
  gated `#[cfg(feature = "oidc")]` (`frp-core/src/auth.rs:3044`) and `TEST_KEY`
  `#[cfg(feature = "compression")]` (`frp-core/src/snappy_stream.rs:430`); `frp-core/tests/kcp.rs`
  and `frp-core/tests/xtcp_p2p.rs` carry whole-file `#![cfg(feature = "kcp")]` — measured, the
  file's floor is `kcp` alone: `--features kcp,tcp-mux --all-targets` exits 0, and
  `--features kcp --all-targets` also exits 0 once the two `AtomicU64`/`AtomicUsize` imports
  at `frp-core/src/xtcp_session.rs:40` are gated — that import error is the only thing that
  makes `--features kcp --all-targets` red in-tree (it is listed under the measured-red `-p`
  entry below), so `tcp-mux`/`quic` are not folded into the gate; `protocol_round14.rs` was
  restructured, not `allow`ed — the base vector is immutable
  and the `vnet`-gated extend rebuilds it into a `mut` local, so `mut` exists exactly where
  the mutation does. The same missing-gate class then showed up at **runtime**, in two places
  the compile-only `cargo check` above cannot see:
  - `cargo test -p frp-core --no-default-features` exited 101 with 597 passed / 8 failed, every
    failure `"compression not compiled"`. The eight that failed all call a compression API that
    returns `Err("compression not compiled")` without the feature, so each gate is intrinsic
    rather than a way to silence a flake (other tests pass the flag and fall back instead of
    failing — e.g. `bridge::tests::test_encrypted_bridge_compression_smoke`
    (`frp-core/src/bridge.rs:1518`) passes `use_compression = true` and passes vacuously). The
    gates: seven in `frp-core/src/bridge.rs`
    (`test_bridge_plain_compressed_pre_read_stream_integrity`,
    `test_bridge_plain_decompressed_read_direction_split`,
    `test_bridge_encrypted_decompressed_read_direction_split`,
    `test_bridge_encrypted_compressed_pre_read_stream_integrity`,
    `test_bridge_work_to_user_decompressor_flush`,
    `test_bridge_compressed_charges_compressed_size_not_raw`,
    `test_bridge_compressed_rate_limited_throttles_incompressible`) and
    `test_compress_decompress_into_wire_equiv` in `frp-core/src/encryption.rs`.
  - `cargo test -p frp-core --no-default-features --all-targets` exited 101 while
    `cargo check -p frp-core --no-default-features --all-targets` exited 0:
    `frp-core/benches/crypto_bridge.rs` carried no compression gate and `bench_compression`
    unwraps `frp_core::encryption::compress` at registration time, outside `b.iter` —
    `thread 'main' panicked at frp-core/benches/crypto_bridge.rs:60:64: called
    Result::unwrap() on an Err value: "compression not compiled"`, then
    `error: test failed, to rerun pass -p frp-core --bench crypto_bridge`. Only that body
    carries `#[cfg(feature = "compression")]` — the bench's other groups do not need the
    feature (`make_compressor`/`make_decompressor` return `None`, `frp-core/src/bridge.rs:68,87`
    with the feature-off branches at `:77-81` and `:96-100`; measured,
    `bridge/encrypted_compressed_bridge_*` runs `Success` in the no-features run).
    The function itself stays unconditional because the `criterion_group!` invocation in
    `frp-core/benches/crypto_bridge.rs` lists it by name and it must exist.
  Measured after: `cargo test -p frp-core --no-default-features --all-targets` exits 0 (609
  tests passed, 0 failed, 124 criterion bench cases run); the same command with default
  features is 903 passed / 130 bench cases and with `--all-features` 917 / 130, so the
  compression group's 6 cases (3 sizes × compress/decompress) are the only bench cases the
  gate removes. `cargo test -p frp-core --no-default-features` (without `--all-targets`) also
  exits 0: 609 passed / 2 ignored. `--no-default-features --features compression` exits 0 with
  664 passed. Two CI steps now cover frp-core: `Check frp-core tier test targets compile
  (isolated, no features)` in the `verify` lane (compile half) and `Run frp-core's tests and
  benches with no features (runtime half of frp-core's tier gate)` in the `Tests (unit)` lane
  (runtime half); `docs/developing.md § Binary Variants` states which configuration each
  covers. Neither step covers the 6 of frp-core's 10 test
  targets that are whole-file-cfg'd *empty* in the no-features configuration (`kcp.rs`,
  `xtcp_p2p.rs`; `mux.rs`, `yamux_rst.rs` under `tcp-mux`; `xtcp_quic_sni.rs` under `tls`;
  `ws_tls_stall.rs` under `tls`+`websocket`): each reports 0 tests in this configuration
  (`cargo test -p frp-core --no-default-features --test <t> -- --list` reports 0) and `running
  0 tests` in the runtime step's output.
- [x] **The same no-features runtime class is live in `frp-server` and `frp-client`, and no
  step runs their test targets in that configuration.** Measured in this worktree (macOS
  arm64); the `verify` lane's compile-only siblings
  (`cargo check -p frp-server --no-default-features --all-targets` and the `frp-client` one)
  both exit 0 on the same targets, so nothing gates this:
  - `cargo test -p frp-server --no-default-features --all-targets --no-fail-fast` exits 101.
    The totals are run-dependent because one of the failures below is a flake: two runs here
    measured 432 passed / 40 failed across 8 targets and 433 / 39 / 7, and a reviewer sample
    also reproduced the 433 / 39 / 7 shape. 39 failures are deterministic:
    34 are feature-gated behaviour:
    27 are the `http-proxy` stub — `tests/http_plugin.rs` 22 failed / 1 passed and
    `tests/http_plugin_ping.rs` 4 failed / 1 passed (both files carried no
    `cfg(feature ...)` before this change, measured), plus the lib test
    `control::proxy_ops::unregister_generation_tests::
    stale_unregister_keeps_fresh_user_record` (in `frp-server/src/control/proxy_ops.rs`; its
    `assert_eq!` on `plugin_manager.user_info(...)`) which expects that to be `Some` while the
    `#[cfg(not(feature = "http-proxy"))]` stub (`frp-server/src/plugin/mod.rs:8-34`) makes
    `record_login_user` a no-op (`:29`) and `user_info` return `None` (`:30-32`); the real impl
    is `frp-server/src/plugin/http.rs:132` (`record_login_user` `:200`, `user_info` `:209`).
    The other 7: `test_login_via_websocket` and `test_login_via_tls` in
    `tests/server_protocol.rs`, the two `tls_*` TLS-dial cases in `tests/slowloris.rs`, and
    `test_https_vhost_sni_passthrough`, `test_tls_control_login_not_hijacked_by_https_wildcard`
    and `test_https_group_sni_fan_out_round_robin` in `tests/vhost_https_sni.rs`.
    Controls with the feature on, measured: `--test http_plugin`
    23 passed / 0 failed, `--test http_plugin_ping` 5/0, `--lib unregister_generation_tests`
    49/0, `--no-default-features --features websocket,tls --test server_protocol test_login_via`
    2/0, `--no-default-features --features tls,http-proxy --test slowloris` 5/0 and
    `--test vhost_https_sni` 4/0.
    - 5 `tests/oidc_integration.rs` failures are environmental, not this class: `failed to
      start frps: Os { code: 2, kind: NotFound, message: "No such file or directory" }`
      (`frp-server/tests/common/mod.rs:640`) — this worktree has no `target/debug/frps`.
    - The 40th failure in the larger sample is not a feature residue at all: it is the
      load-dependent flake in `tests/tcpmux_httpconnect.rs` tracked as its own item below,
      which also fails with default features. It is why this breakdown says 39 deterministic
      failures, not 40.
  - `cargo test -p frp-client --no-default-features --all-targets --no-fail-fast` exits 101
    with 313 passed / 2 failed: `test_e2e_tcp_proxy_over_websocket`
    (`frp-client/tests/end_to_end.rs`; the file carried no `cfg(feature ...)` before this change)
    fails on the
    proxy-port wait (`await.expect("proxy port ready")`) and passes with `--no-default-features
    --features websocket` (control: `--test end_to_end` with default features 7 passed /
    0 failed); the other is
    `plugin::static_file::tests::test_static_file_e2e_non_ascii_round_trip`
    (`frp-client/src/plugin/static_file.rs:3471` is the `EILSEQ` write; the line
    moved with the fixes below, and that test now skips the half at runtime and
    passes at default features — see its own `- [x]` entry), which also failed
    with default features (0 passed / 1 failed) at the time of this sample —
    macOS-only, not this class.
  Gating these and adding sibling runtime steps is its own change. **Done-when:** each
  runtime-failing target carries its gate (or the configuration is documented as unsupported)
  and a step runs it.
  Done: fixed in this change. Every runtime failure in the no-features configuration **caused by
  a missing feature gate** now carries that gate, and both crates have a runtime step. Per file,
  with the **minimal** feature floor each gate needs (measured: the passing run enables that one
  feature and nothing else, and removing the gate reproduces the failure below):
  - `frp-server/tests/http_plugin.rs` — whole-file `#![cfg(feature = "http-proxy")]`. Ungated in
    this configuration: 1 passed / 22 failed. Gated: 0 tests here, `cargo test -p frp-server
    --no-default-features --features http-proxy --test http_plugin` 23 passed / 0 failed.
  - `frp-server/tests/http_plugin_ping.rs` — whole-file `#![cfg(feature = "http-proxy")]`.
    Ungated: 1 passed / 4 failed. Gated: 0 tests here, `--features http-proxy --test
    http_plugin_ping` 5 passed / 0 failed.
  - `frp-server/src/control/proxy_ops.rs`
    `control::proxy_ops::unregister_generation_tests::stale_unregister_keeps_fresh_user_record`
    — `#[cfg(feature = "http-proxy")]`. Ungated: `--lib unregister_generation_tests` 48 passed /
    1 failed, `assert_eq!` at `:3814`, `left: None` vs `right: Some("fresh")`. Gated:
    `--features http-proxy` 49 passed / 0 failed.
  - `frp-server/tests/server_protocol.rs` — `#[cfg(feature = "websocket")]` on
    `test_login_via_websocket` (ungated: `WS dial: Transport(Other("WS raw connect read:
    Connection reset by peer (os error 54)"))`; `--features websocket` alone 1 passed /
    0 failed) and `#[cfg(feature = "tls")]` on `test_login_via_tls` (ungated: `TLS dial:
    Transport(Other("TLS connect: Connection reset by peer (os error 54)"))`; `--features tls`
    alone 1 passed / 0 failed). The other 11 cases stay ungated and pass with no features.
  - `frp-server/tests/slowloris.rs` — `#[cfg(feature = "tls")]` on the two TLS cases (plus the
    imports and `test_cert_dir`, which only they use). Ungated both panic on the TLS dial;
    `--features tls` alone 5 passed / 0 failed.
  - `frp-server/tests/vhost_https_sni.rs` — per-item `#[cfg(feature = "tls")]` on the three e2e
    cases; `test_hello_construction_extracts_sni` stays ungated and still runs here. Ungated the
    three fail (`connect to https vhost port: Os { code: 61, kind: ConnectionRefused }` twice,
    `TLS control dial: ... (os error 54)` once); `--features tls` alone 4 passed / 0 failed.
  - `frp-client/tests/end_to_end.rs` — `#[cfg(feature = "websocket")]` on
    `test_e2e_tcp_proxy_over_websocket`. Ungated it panics at the test's
    `await.expect("proxy port ready")`; gated the target is 6 passed / 0 failed here and
    7 passed / 0 failed with `--features websocket` and with default features, so no case is
    lost.
  The gates are on each crate's **own** features, not `frp-core`'s. Measured with
  `cargo check -p frp-client --no-default-features --test end_to_end -v`, `frp-core` is
  compiled with `--cfg feature="websocket"` (and `tls`, `kcp`, …) **on** in that graph — the
  `frp-server` dev-dependency supplies `frp-client`'s default features, which forward
  `frp-core/websocket`, `frp-core/tls`, … — so the feature-off
  `frp-core` stub is not what any of these tests hits. The
  `#[cfg(not(feature = "websocket"))]` arm that drops a WS connection
  (`frp-server/src/service.rs`) and the `not(feature = "tls")` handler that drops a TLS one
  (`frp-server/src/handlers/transport.rs:669`) are frp-server's own.
  Two CI steps now cover the configuration:
  - `Run frp-client's tests with no features (runtime half of frp-client's tier gate)` in
    `Tests (unit)`: `cargo test -p frp-client --no-default-features --all-targets -j 1
    --no-fail-fast`. It belongs in the unit lane because frp-client's test targets need no
    `frps`/`frpc` binary (they drive in-process services).
  - `Run frp-server's tests with no features (runtime half of frp-server's tier gate)` in
    `Tests (server integration)`: `cargo test -p frp-server --no-default-features --all-targets
    -j 1 --no-fail-fast`, with that lane's `FRPS_BIN`/`FRPC_BIN`. The 5
    `tests/oidc_integration.rs` tests need an `frps` binary — measured here with
    `target/debug/frps` present they pass (7 passed / 0 failed in that target), and the item's
    original "5 environmental failures" sample was taken in a tree without one.
  Measured after the gates: `cargo test -p frp-server --no-default-features --all-targets -j 1
  --no-fail-fast` exited 0 with 436 passed / 0 failed in three of five samples (2m08s, macOS
  arm64 warm build); the other two were 435 passed / 1 failed, the single failure being the
  `test_tcpmux_proxy_auth_interior_space_rejected_407` flake (fixed since — see below), which also
  failed with default features. `cargo test -p
  frp-client --no-default-features
  --all-targets -j 1 --no-fail-fast` exits 101 on this macOS host with 312-313 passed and
  1-2 failed — the failures are the two non-class ones recorded below (the `start_paused`
  deadline flake and the macOS-only `EILSEQ` test); the runner was not
  measured for either command.
  Still **not** covered by these steps: (a) the whole-file-cfg'd *empty* test targets — 9 of
  `frp-server`'s 35 `tests/*.rs` (the two `http_plugin*` files were added to that set by this
  change), 6 of `frp-core`'s 10, 4 of `frp-client`'s 40 — compile to nothing in this
  configuration; (b) `frp-client`'s **lib** target is red on macOS in this configuration for the
  two non-class reasons below, so a Linux-green run there is an inference from the existing
  default-feature lane being green, not a measurement; (c) `frpc-tiny`'s test targets, which are
  their own item below.
- [x] **`test_tcpmux_proxy_auth_interior_space_rejected_407` is a load-dependent flake,
  independent of features, and can turn the default-feature suite red.** Assertion:
  `double-space credentials must be rejected: 200 (successHook) then 407, got: "HTTP/1.1 200
  OK\r\nContent-Length: 0\r\n\r\n"`. Root cause confirmed at the source: `frp-server/src/tcpmux.rs:569`
  writes the 200 and `:591` the 407 in two separate `write_all` calls (Go successHook-before-checkAuth
  order, probe-verified against Go v0.71.0), while the helper `read_full_response`
  (`frp-server/tests/tcpmux_httpconnect.rs`) returns at the first `\r\n\r\n` — but returns *every
  byte a read happened to deliver*, so it sees the 407 only if that first read happens to deliver
  the 200 head **and** the whole 42-byte `HTTP/1.1 407 Proxy Authentication Required` status line —
  80 bytes in total (the assertion uses `find`, so a read that stops inside the status line still
  fails). Measured pre-fix on macOS arm64 by three agents independently: across the six
  default-test-threads samples the whole 4-test target failed **43/352** runs — the author 13/72
  (5/40 single-process, 8/32 at 4-way concurrency), the adversarial reviewer 6/72 (4/40, 2/32), the
  independent reviewer 24/208 (9/80, 15/128) — and every one of the 43 failures carried exactly the
  200 in the buffer. The spread between samples is part of the finding: this is a load-dependent
  rate, not a constant, so no single sample is *the* rate. **Concurrency from any source triggers it,
  not only in-process test threads:** a *serialized* `--test-threads=1` run does not flake (0/60),
  but `--test-threads=1` alone does not prevent it — 4 concurrent serialized processes failed 12/32
  and 8/32 (adversarial reviewer) and 5/32 and 6/32 (independent reviewer), and 8 concurrent failed
  5/32. Those `--test-threads=1` arms are a separate measurement and are **not** part of the 43/352,
  which counts only the default-test-threads samples.
  A temporary in-process probe (240 CONNECTs across 8 concurrent instances) measured the split
  directly: the first read carried only the 200 in **34/240 (14.2%)** of connections. **Fixed** on
  the test side only: the reject arm now uses `send_connect_reject` → `common::read_until_eof`, the
  read-to-EOF pattern the sibling `test_tcpmux_proxy_auth` already uses for the same 200-then-407
  pair. The server is untouched, so the wire bytes are unchanged. Measured post-fix: **0/516** runs
  across the three agents (single-process, 4-way and 8-way concurrency; 108 of them counted at
  `--no-default-features`, a deliberately conservative figure — the reviewers' own retained logs
  contain more than that (135 and 148 identified independently), so treat 516 as a floor rather
  than an exact count; the difference is bookkeeping, not failures), same assertion unchanged. The full `cargo test -p frp-server` green was
  re-measured on a quiet tree after both reviewers stopped. One further run during the fix round
  reported
  `3 passed; 1 failed` at `--no-default-features` with the old 200-only signature; its binary was
  overwritten by a concurrent `cargo` rebuild, so the provenance is unrecoverable and it is recorded
  as residue rather than explained away. Adversarial review
  measured the change as **strictly stronger, not weaker**: deleting the server's post-407
  `return;` so the conn is never closed makes the new reader fail 4/4, while the old reader passed
  that mutant 20/20. Reading to EOF is what makes *this* target pin close — it is not the only such
  check in the suite: the sibling `test_tcpmux_proxy_auth` catches the same mutant 3/3 at
  `tcpmux.rs:679`. The done-when's alternative — have the server write both responses in one buffer —
  was rejected: a single `write_all` is not guaranteed to arrive in a single read (TCP is a byte
  stream), so coalescing would not be a guarantee against the split. It would very likely have
  removed the observed split on loopback at this size, but that was reasoned rather than measured;
  and it would have changed the write boundaries of code whose bytes are already probe-verified Go
  parity.
  **Go parity verified end-to-end**, against the real Go frp v0.71.0 binaries (`frps -v` → `0.71.0`;
  the same ones `scripts/compat-test.sh` uses — confirmed independently by two reviewers). A
  double-space CONNECT is answered with the 200 head and then the 407 head on the same connection —
  **149 bytes total = the 38-byte 200 head + the 111-byte 407 head**: `HTTP/1.1 200 OK\r\nContent-
  Length: 0\r\n\r\n` then `HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic
  realm="Restricted"\r\nContent-Length: 0\r\n\r\n` — while correct credentials get a single 38-byte
  200. The recv *chunk boundaries* are timing-dependent and are not the finding: they were observed
  as `[82, 20, 24, 23]` and as `[36, 2, 44, 18, 2, 24, 2, 21]`. Only the 149 = 38 + 111 split and
  the 200-head-first order reproduce. Go v0.71.0 `pkg/util/vhost/vhost.go`'s `handle()` likewise runs
  `successHook` before `checkAuth`.
  **Residue:** the one unreproducible `--no-default-features` failure noted above, whose binary
  provenance a concurrent rebuild destroyed; and the fact that the probe pins the wire order and the
  Go source hook order, not Go's internal write-syscall count.

- [x] **Two observations of `test_tcpmux_proxy_auth` failing are unusable: both fall inside windows
  when a reviewing agent had `frp-server/src/tcpmux.rs` mutants in this same worktree.** They are
  kept here only as a contaminated-measurement record — the test is **not** established as flaky.
  - Observation 1: a full `cargo test -p frp-server` run failed at `tcpmux.rs:698:9`, the byte-exact
    407-head assertion — the `200` arrived (the `:687` `starts_with` assertion passed) and the
    `407 ... Proxy-Authenticate ... Content-Length: 0` head did not.
  - Observation 2: at host load 61-77, 2 of 4 runs of `cargo test -p frp-server --test
    tcpmux_httpconnect --test tcpmux` failed in the untouched `tcpmux` target at `tcpmux.rs:679:18`,
    `timeout waiting for the auth response + close: Elapsed(())` — the 2 s first-read timeout.
  Why neither counts: a reviewing agent mutated `frp-server/src/tcpmux.rs` in this worktree and
  relinked `target/debug/deps/tcpmux-*` during the relevant windows. Observation 2's window is
  bracketed by the artifacts to [16:55:01, 16:58:04] — the `/tmp/r1b` directory mtime at 16:55:01
  and `/tmp/r1_nod` at 16:58:04; more tightly, the gap between `/tmp/r1b`'s last log at 16:55:37 and
  `/tmp/r1_nod`'s first at 16:57:55 — which is **inside** the 16:55 and 16:56 mutation activity.
  Observation 1's own window was not retained: it is inferred from when it was recorded, which is the
  same period, so it is *consistent with* that activity rather than timestamp-linked to it. Deleting that `return;` makes this test fail **3/3 at `:679`** — exactly
  observation 2's message — and **stripping the 407's headers** (measured) makes it fail **3/3 at
  `:698`** — exactly observation 1's site; suppressing the 407 write reaches the same assertion but
  was measured only against the rejection test, so that half is reasoned rather than measured. These
  tests run frps **in-process**, so the binary under test *is* whatever is in `target/`; a mutant
  present at build time is measured as the product. Clean-tree evidence points the other way:
  **0/48** runs of the sibling target under 8-way concurrency (independently reproduced by the
  adversarial reviewer), 0/40 and 0/12 clean runs earlier, and a full `cargo test -p frp-server`
  green re-measured after both reviewers stopped, against a `src/tcpmux.rs` md5-verified pristine.
  **The independent reviewer has since withdrawn its `:679` claim in as many words**, on exactly
  these grounds: unretained logs, unrecoverable provenance, a shared target dir, and a window
  coincident with disclosed mutation of the crate under test.
  **Done-when:** to treat this test as flaky at all, reproduce it on a quiet worktree with no
  concurrent mutation builds and capture the received bytes; otherwise close this as a
  contaminated-measurement record. **Process lesson — the actual finding:** mutating a server in the
  same worktree another agent is measuring contaminates both, silently and in the direction of
  looking like a real flake. Review agents need their own checkout or a frozen revision, and a
  mutation must be reverted *and* the target rebuilt before any measurement resumes.

  Done (branch `chore/close-tcpmux-flake`, based on `main` @ `7e2a0b5`): **closed as a
  contaminated-measurement record**, after the quiet-tree reproduction the done-when asks for.
  Measured on a pristine worktree at `7e2a0b5` — `git status` empty before/between/after every batch
  (that check, not the single-file md5 below, is what covers mutations anywhere in the tree),
  `frp-server/src/tcpmux.rs` md5 `cc646387f9a239c4d3216f85a2fa8935` before and after, both test
  binaries' hashes constant **within that worktree** (`tcpmux` `acad919efdcfb6492fee9025fdc6f06c`,
  `tcpmux_httpconnect` `9e52be1c077f3e8d84ebe9d90852bdc2` — debug binaries embed their build path, so
  the hex is a relink guard for that worktree, not a portable fingerprint), no concurrent
  `cargo`/`rustc`, and no other worktree dirty — **110/110 runs of the observation-2 command exited
  0**: 50 quiet parallel, 20 quiet serial (`-- --test-threads=1`), 30 under 70 busy loops (load
  average ramped 16.9 → 96.8, bracketing the reported 61–77), plus **10/10 of observation 1's target
  alone** (`cargo test -p frp-server --test tcpmux`); a grep for `panicked at` / `test result: FAILED`
  / `error[E` across all 110 logs found nothing, so no failure occurred and there was nothing to
  capture bytes from. **Independently replicated by Reviewer 1: 0/48** (25 parallel on a host shared
  with another reviewer's builds but with no mutation build in this tree, 5 quiet serial, 12 loaded
  with the 1-min average passing through and beyond the band to 160.55, 6 `tcpmux`-alone), with both
  targets listed and the named tests (`test_tcpmux_proxy_auth`, the 407
  test) shown executing. **Reviewer 2 (adversarial) reproduced the mechanism in its own tree** —
  deleting the 407 arm's `return;` fails **3/3** at `tests/tcpmux.rs:679` with observation 2's message
  byte-for-byte, and stripping the 407's `Proxy-Authenticate` fails **3/3** at `:698` with observation
  1's — and ran 19 more green runs (default/2/4/8 threads; 18 under applied load in the ~30 → ~145
  range, plus a baseline at ambient ~11), plus the **true
  observation-1 shape** the author could not run: with `frps` built and `FRPS_BIN` set,
  `cargo test -p frp-server` exits 0 across all 35 targets with `Running tests/tcpmux.rs` and
  `test_tcpmux_proxy_auth ... ok`. **Citation correction:** the two observations cite
  `frp-server/src/tcpmux.rs:698`/`:679`, but those assertions are in `frp-server/tests/tcpmux.rs`
  (`:698` the byte-exact 407 head, `:679` the 2 s first-read timeout; `src/tcpmux.rs:698` is a closing
  brace, not that assertion). **One caveat on the guard itself, measured by Reviewer 2:** empty
  `git status` + a constant source md5 + constant binary hashes do **not** prove the *executed* binary
  was built from pristine source — a mutant built and then reverted (with its mtime restored) survives
  in `target/` and `cargo test` will not relink it, and that run fails at `:698` while every guard
  reads clean. What actually rules that out here is the **direction of the result**: a mutant binary
  makes these runs red, and 110 author runs plus 19 reviewer runs were green, so no mutant was in the
  executed path. Not covered, recorded so the closure is not
  read as stronger than it is: the load was not *held* in the 61–77 band (it ramped through it), a
  near-miss on the 2 s first read was not instrumented, other hosts/CI/`--release`/`--all-features`
  were not exercised, test-thread counts other than default, 1, 2, 4 and 8 were not run, the
  tests' `flock`-based cross-process `allocate_port()` allocator was not analysed as a concurrency
  mechanism in this round — **it has since been observed to collide, recorded in the addendum
  below as evidence and not as an established flake** — mutation+relink+revert *inside* one batch is invisible to
  a per-batch hash check, and a
  green clean tree cannot by itself prove the original two runs were contaminated rather than very
  rare — it only fails to reproduce them in the ~180 attempts above (110 author + 48 Reviewer 1 + 19
  Reviewer 2) spanning quiet and heavily loaded conditions. The process lesson the item names is already enforced in
  `docs/developing.md § Review protocol` ("Mutate in your own checkout, never the tree being
  measured"), so no further durable change was needed.
  * **Addendum (2026-09-26, at the head of `fix/frps-empty-addr`): the `allocate_port()`
    probe→bind window has been observed to collide — recorded as evidence; no test here is
    established as flaky.** Four samples, two signatures, all from the `dashboard_integration`
    binary: (i) **3 collisions in 110 reviewer runs** of that bin — 1 in 55 *with*, 2 in 55
    *without* the three tests that PR added, each sample on a different test; (ii) the author's one
    sample at that head, a run that failed 19/20 with `test_dashboard_proxy_type_and_name_filters`
    panicking at `frp-server/tests/dashboard_integration.rs:1330` with
    `register tcp-one: Some("port unavailable")`. The collisions were observed in bins *with* and
    *without* that PR's new tests — signature (i) on both sides, signature (ii)'s single sample with
    them — so **none of the four is attributable to
    `fix/frps-empty-addr`**. Mechanism (`frp-server/tests/common/mod.rs`, `allocate_port()`): the
    probe binds `127.0.0.1:0`, reads the port and **drops the probe socket**; macOS's ephemeral
    range is 49152–65535, so a concurrent outbound socket in the same test process can take that
    number before the child `frps` binds it, and the child then exits **rc 1
    `Address already in use (os error 48)`** (measured directly: with `127.0.0.1:17740` held,
    `frps -c` on that port exits 1 with exactly that error) — a failure `wait_tcp_port` cannot
    distinguish from a slow start, so it burns its full 15 s and panics `frps bind_port not ready`
    (`common/mod.rs:733`, the site the two `sleep`-based forced-failure runs hit). The `flock` in
    `acquire_port_request_lock()` serialises the probe→confirm→hand-out step only, not the window to
    the eventual bind; a comment at `allocate_port()` now names that window. The author's follow-up
    sampling after the sample above was **0 failures in 15 runs** (6 with and 6 without the three
    new tests, 3 mixed), so this is **one symptom plus a sampling split, not established debt**:
    promotion to its own `[ ]` item waits for a second controlled reproduction, the same bar as the
    `test_tcpmux_proxy_auth` record above.
- [x] **`frp-client`'s `start_paused` socket-deadline tests are flaky on this host at *default*
  features — they can turn the existing default-feature lanes red.** Found while measuring the
  new no-features runtime step; none of them is a feature gate, and none is touched by the
  gating change. Measured on macOS arm64:
  - `plugin::http::tests::http_proxy_head_read_absolute_window_releases_trickler`
    (`frp-client/src/plugin/http.rs`): `cargo test -p frp-client --lib
    http_proxy_head_read_absolute_window_releases_trickler` failed 3 of 3 runs, and `cargo test
    -p frp-client --no-default-features --lib <same test>` failed 6 of 10, with two different
    panic sites — `Ok(Err(e))` → `read error from a trickled head read: Connection reset by
    peer (os error 54)`, and `Err(_elapsed)` → `trickled head read was not released: the 60 s
    absolute window never fired`. The test accepts only `Ok(Ok(0))` (a clean EOF); the
    `Connection reset by peer` arm is the other observed outcome.
  - `plugin::https2http::tests::test_tls_handshake_deadline_releases_handler` and
    `plugin::https2https::tests::test_https2https_handshake_deadline_releases_handler`:
    `cargo test -p frp-client --features admin --lib` — the lib half of the configuration the
    existing `Tests (client integration)` lane runs — failed 3 of 3 runs with `stalled TLS
    handshake was not released: conn still open after 70`
    (`frp-client/src/plugin/https2http.rs:290`,
    `frp-client/src/plugin/https2https.rs:329`).
  **Mechanism, investigated and confirmed — there were THREE scheduling dependencies, not one.**
  **(A) FIN vs RST.** Closing a socket that still has unread inbound bytes makes the OS send RST,
  so the peer's `read` returns `ECONNRESET` — a *successful* release that the old
  `Ok(Err(e)) => panic!` arm reported as failure. Probe: close with the peer's 5 bytes unread →
  `ECONNRESET` 20/20; read them first → `Ok(0)` 20/20. This was the **trickler's** failure form
  (10 of 60 pre-fix runs); the TLS pins' acceptor consumes the 3-byte partial ClientHello on the
  first poll, so they see clean EOF (180/180 measured).
  **(B) Paused-clock auto-advance ordering.** While the clock is paused, tokio's time driver
  parks the I/O driver with a zero timeout and, if that park did not unpark the runtime
  (`!handle.did_wake()` — `tokio-1.53.1/src/runtime/time/mod.rs`), advances the virtual clock the
  *whole* distance to the next timer. With the old single far-away bound (70 s / 300 s) as the
  only timer the TLS pins owned, one park could jump the entire 70 s past the handler's 60 s
  deadline. Instrumented, 12 runs of the old https2http pin: the passing 7 polled the handler at
  virtual t=8 ms; the failing 5 first polled it at t=69.64 s, arming its 60 s window at 129.6 s.
  **(C) Real-time adequacy — found by review, and the reason a naive fix still failed.** The bound
  is virtual, but observing the close needs real time. One slice costs one park ≈ one poll ≈ a few
  µs real, so the old 10 s of virtual slack at 250 ms/slice bought only ~40 polls ≈ **0.2 ms** to
  deliver the FIN/RST. Reviewer 1 measured the fixed-but-two-tier version failing **6/10,394** runs
  at load 10-37, every failure *after* the product deadline had already fired (instrumented:
  `accept_tls_bounded` resolved `timed_out=true` at vt=60.075 s; the client never saw the close in
  the remaining 9.9 s of virtual time = ~0.2 ms real).
  **Fixed** (test-only; no product constant, deadline or behaviour touched — proven by injecting
  `compile_error!` into the helper: `cargo build -p frp-client` and `--all-features` and
  `frpc --bins --all-features` all still succeed, while `cargo test --lib --no-run` fails).
  New `frp-client/src/plugin/test_support.rs` (behind `#[cfg(test)] mod test_support;`) provides
  `assert_peer_closed_within(stream, earliest, bound, what, red)`: a loop of
  `timeout(STEP, read)` with a **uniform `STEP = 1 ms`**, so a virtual `bound` is also a real-time
  allowance (~10,000 polls ≈ tens of ms of real time for the TLS pins, instead of ~0.2 ms);
  it returns on clean EOF or a peer close (`ConnectionReset`/`ConnectionAborted`/`BrokenPipe`),
  panics on `Ok(n>0)` payload, on any other error kind, **before `earliest` minus 1 s of slack**
  (a handler that drops the connection immediately is a regression too — the old shape only
  rejected that by accident, and only when the early drop happened to be an RST), and once
  `elapsed > bound`.
  **Verification.** Pre-fix baselines (three agents, load-stated, all samples): 8-way 500-run
  batches — https2http 88/500, https2https 60/500, trickler 25/500; sequential — trickler 50/60
  (10× arm A), https2http 0/60, https2https 0/60 at load ~3.7, and 60/60, 18/60, 15/60 at load
  175-181. Post-fix, final design: **0/200 per pin at 8-way concurrency with 0 vacuous runs**
  (each run re-checked to have really executed its test — a `0/N` from a binary where the test
  does not exist is worthless, and that trap was hit once during this work). RED intact: deleting
  the deadline wrap in `accept_tls_bounded` (`plugin/mod.rs`) makes both TLS pins fail and deleting
  the head-read wrap in `http.rs` makes the trickler fail, each **3/3** via the helper's own panic,
  with clean per-test attribution. The detection loss the first fix round introduced is closed:
  an immediate-drop mutant (accept returns `Err` at once, dropping the conn with the 3 bytes
  unread) now fails the pins instead of passing them.
  Gates: `cargo fmt --all -- --check` clean; `cargo clippy -p frp-client --all-targets -D warnings`
  clean at default, `--no-default-features` and `--all-features`; `cargo test -p frp-client --lib`
  268 passed / 1 failed (default) and 275/1 (`--features admin`), the single failure being the
  unrelated macOS `EILSEQ` `static_file` test; `scripts/repo-health.sh` exit 0.
  **Residue / not fixed here:** the two TLS pins are `#[cfg(all(test, feature = "tls"))]`, so they
  simply do not exist under `--no-default-features` and cannot redden that lane. `plugin::tls2raw`
  bounds three accepts with the same `PLUGIN_HANDSHAKE_TIMEOUT` (`tls2raw.rs:94`, `:107`, `:127`)
  but has **no** paused-time pin at all, and `plugin/static_file.rs` carries a third copy of the
  60 s absolute head-read window as a literal with no deadline pin — both are coverage gaps, not
  flakes, and are **recorded here rather than fixed**: neither is pinned, so nothing would catch
  their deadlines being removed. If they are to be pinned they need their own item; this change
  deliberately does not touch them. `is_peer_close` accepts `BrokenPipe`, which no probe on
  this host could produce from a `read` (EPIPE is a write-side error) — kept for the pin's
  contract and documented as unverified on a read path. All measurements are macOS arm64.
- [x] **`plugin::static_file::tests::test_static_file_e2e_non_ascii_round_trip` failed on macOS,
  at default features.** Measured: `cargo test -p frp-client --lib
  test_static_file_e2e_non_ascii_round_trip` → `panicked at
  frp-client/src/plugin/static_file.rs:3420:72: called Result::unwrap() on an Err value: Os {
  code: 92, kind: Uncategorized, message: "Illegal byte sequence" }` — that write is now at
  `frp-client/src/plugin/static_file.rs:3471`, the line having moved with the fixes below. The
  line wrote a file
  whose name contains byte `0xFF` (`OsString::from_vec(b"raw\xff.txt".to_vec())`), which this
  host's filesystem rejects with `EILSEQ`. It is an `frp-client` **lib** test, so of the three
  no-features *runtime* test steps (`ci.yml:97` frp-core, `:129` frp-client, `:220` frp-server)
  only `Run frp-client's tests with no features` runs it — the other two are `-p frp-core` /
  `-p frp-server` and build no `frp_client` test target; it also runs in the default-feature
  `Tests (client integration)` lane.
  **Fixed** by skipping only the non-UTF-8-name **half** where the filesystem cannot store such
  a name — the property under test is frp-rs's byte-exact escaping and round-trip, not the
  host's filesystem capability. The write is now `if let Err(e)` and returns early only when
  `e.raw_os_error()` is `EILSEQ`. The earlier "`92` on macOS/BSD, `84` on Linux" wording was
  **wrong for BSD**: per libc's constants EILSEQ is 92 on macOS, 86 on FreeBSD, 85 on NetBSD, 84
  on Linux and OpenBSD (88 on MIPS, 122 on SPARC), so the two matched arms serve macOS and
  Linux/OpenBSD. The arms collide with unrelated errnos (84 = `EOVERFLOW` on macOS, 92 =
  `ENOPROTOOPT` on Linux) but neither is reachable from `std::fs::write` on a regular path — now
  stated in the code comment instead of left implicit. Every other error still
  panics, so a genuine failure cannot be swallowed: the direction is fail-loud (panic), not a
  silent skip. It matches on `raw_os_error` because **no stable `ErrorKind` matches at all** —
  the measured kind is `Uncategorized`, and `ErrorKind::Uncategorized` is
  `#[unstable]`/`#[doc(hidden)]` and cannot be named on stable, so `raw_os_error` was the only
  option rather than a choice against a viable kind match.
  Verified: the test now passes and prints
  `skipping the non-UTF-8 filename half: this filesystem cannot store such a name (Illegal byte
  sequence (os error 92))`, i.e. the skip branch is the one that fires (not a silent pass).
  **Coverage of the skipped hops (this change; both run on APFS, no filesystem capability
  needed):** the `DirEntry` name→bytes hop was extracted into a pure
  `render_listing(entries: &[(OsString, bool)]) -> String` that `render_dir_listing` now calls,
  and `test_render_listing_non_utf8_name_escapes_byte_exact` feeds it a synthetic
  `b"raw\xff.txt"` (plus a `sub\xff` directory) and asserts the whole HTML body byte-exactly,
  including `<a href="raw%FF.txt">`; it also pins the byte-wise **sort key** with the tie-free
  pair `b"a\xff"` / `b"a\xf0\x90\x80\x80"` — raw order puts `F0 90 80 80` before `FF`, a lossy
  comparator collapses `a\xff` to `61 EF BF BD` and moves it ahead (the two keys stay distinct, so
  the flip does not depend on sort stability), and the other three names cannot tell the two keys
  apart (Reviewer 1 F7 / Reviewer 2 N1; the input array is deliberately not in rendered order, so
  the order in the expected body also proves a sort happened at all);
  `test_join_components_non_utf8_component_byte_exact` pins `join_components`'s unix arm on
  `b"raw\xff.txt"` — its only call site is this path and it had **no direct** test before
  (existing e2e tests reached it indirectly, with valid-UTF-8 names only).
  Mutation-checked: restoring the pre-round-16 lossy hop in `render_listing`
  (`name.clone().into_vec()` → `name.to_string_lossy().as_bytes().to_vec()`) makes the new
  `render_listing` test fail, where before this change the entire `frp-client` lib suite stayed
  green under that mutation on macOS (`269 passed; 0 failed`).
  Counts after this change: `cargo test -p frp-client --lib static_file` **33 passed / 0 failed**
  (was 31), `cargo test -p frp-client --lib` **271 passed / 0 failed** (was 269).
  **Still NOT covered on a filesystem that cannot store the name:** the *e2e* half itself. The
  `%FF` request → decode → `join_components` → open → serve chain is unexercised here, as is
  collecting a **non-UTF-8** `DirEntry` — the `read_dir` loop itself does run on APFS for the
  UTF-8 `naïve.txt` entry, and after the split that hop is `ent.file_name()`, an `OsString` →
  `OsString` move with no lossy step in it to get wrong. The new tests pin the pure escaping and
  joining hops they *call*, not the socket-level round trip, so a regression *between*
  `render_listing` and the file open — in the caller, in the request decoder's wiring into this
  handler (`urlencoding_decode("%FF")` is itself unit-pinned at
  `frp-client/src/plugin/mod.rs:2588`), or in the collection loop — remains invisible on this
  host and rests on the `Tests (client integration)` lane on ubuntu-latest, which is exactly
  where the item expected the failure not to appear.
  **Deliberately not done (Reviewer 2 N5, NIT):** `render_listing` borrows `&[(OsString, bool)]`
  and therefore clones each name (`name.clone().into_vec()` at the hop) where the pre-change
  code was zero-copy (`ent.file_name().into_vec()`). Passing the `Vec` by value and iterating
  with `into_iter()` removes that clone and keeps the hop reachable by a synthetic test, so this
  is a viable follow-up. It was left alone because the item is about *coverage*, not listing
  throughput: the saving is one allocation per directory entry, no measurement shows the listing
  path is hot, and the change would re-open a production signature that has already been reviewed
  twice. Recorded here so a later round can do it with a measurement.
- [x] **`frpc-tiny`'s test targets did not compile.** Evidence:
  `cargo check -p frp-client --no-default-features --features tls,tcp-mux --all-targets`
  — exactly the tiny tier for frp-client, measured `['tcp-mux','tls']` — exited 101 with
  `could not compile frp-client (test "plugin_h2") due to 5 previous errors`: `E0433 cannot
  find module or crate 'h2'`, `'http'`, plus an `E0277`. `plugin_h2.rs` was gated
  `#![cfg(feature = "tls")]` only, but its `h2`/`http` imports come from `http2http` (which
  implies `tls` — `frp-client/Cargo.toml`: `http2http = ["dep:h2", "dep:http", "dep:bytes",
  "tls"]`), so in the tiny configuration the gate selected the whole file in while the crates
  it needs were absent.
  **Fixed:** the gate is now `#![cfg(feature = "http2http")]`, with a comment naming the
  crates that actually require it. Verified: the same
  `RUSTFLAGS="-D warnings" cargo check -p frp-client --no-default-features --features
  tls,tcp-mux --all-targets` now exits **0**, and `cargo test -p frp-client --test plugin_h2`
  still builds and passes **6/6** at default features — the target is still exercised where its
  dependencies exist, and at `--no-default-features` it is whole-file-cfg'd *empty* by design
  rather than failing.
  **Gate added** (`ci.yml`, `verify` lane): `Check frp-client tiny test targets compile
  (isolated, tls+tcp-mux)` runs that exact command under `-D warnings`. Without it the tiny
  test targets are checked nowhere, because the `--workspace` tiny step deliberately omits
  `--all-targets` (dev-dependency unification would re-enable both crates' `default` sets and
  silently drop the tier check — see that step's own comment). The neighbouring isolated step's
  comment had already predicted this failure mode ("which is exactly how plugin_h2's
  tls-vs-http2http bug hid"); this closes it.
  **Residue:** because the fix makes the target *correctly empty* in the tiny configuration,
  the new step cannot catch a missing gate *inside* it — its body is only compiled with
  `http2http` on, which the default-feature lane covers. The neighbouring step's caveat lists
  the targets that are whole-file-cfg'd empty in the **no-features** configuration; under this
  step's tiny configuration only 3 of those are still empty (`plugin_h2`, `xtcp_pair_e2e`,
  `xtcp_visitor_failure_e2e` — measured: `peer_xff_registry_e2e` reports 1 test there), so
  those 3 are the set this gate cannot check inside.
- [x] **Measured `-p` configurations that are red under `-D warnings`.** Measured at `846c1b9`
  and re-measured 2026-09-22: all four exit **101**. Fixed in this change by narrowing the `cfg`
  on the definition/import side at every site — no `#[allow(dead_code)]`,
  `#[allow(unused_imports)]` or `#[allow(unused_variables)]` anywhere. No configuration is
  documented as unsupported: all four compile clean at `-D warnings` (done-when met by fixing,
  not by excusing).
  - `RUSTFLAGS="-D warnings" cargo check -p frp-server --no-default-features --features vnet --all-targets`
    → 101: `error: method 'remove_run_id_vnet_routes' is never used` at
    `frp-server/src/state.rs:1876` — its only caller, `frp-server/src/ssh_gateway.rs:1987`,
    is `ssh`-gated, and the whole `ssh_gateway` module is too (`frp-server/src/lib.rs:18`), so
    `vnet` without `ssh` leaves it dead.
  - `RUSTFLAGS="-D warnings" cargo check -p frp-client --no-default-features --features quic`
    → 101 with two errors: `error: unused variable: 'quic_params'` at
    `frp-client/src/nat_hole.rs:521` and `error: field 'quic_params' is never read` at
    `frp-client/src/visitor.rs:371`.
  - `RUSTFLAGS="-D warnings" cargo check -p frp-client --no-default-features --features vnet --all-targets`
    → 101 with two `unused import` errors (`tokio::io::AsyncReadExt`,
    `tokio::io::AsyncWriteExt`) at `frp-client/src/visitor.rs:2900-2901`. `--all-targets` is
    required: those imports live in `#[cfg(all(test, feature = "vnet"))] mod tests`, and the
    bare command without it exits 0.
  - `RUSTFLAGS="-D warnings" cargo check -p frp-core --no-default-features --features kcp --all-targets`
    → 101: `error: unused imports: 'AtomicU64' and 'AtomicUsize'` at
    `frp-core/src/xtcp_session.rs:40` — every use of those two imports is inside `tcp-mux`-gated
    code, while `AtomicBool` on the same line IS used unconditionally (the QUIC session's
    `alive` flag) and stays in the un-gated import. Measured family: `--features kcp,stun`,
    `--features kcp,quic` and `--features vnet,kcp` exit 101 with that same error, while
    `--features kcp,tcp-mux`, `--features kcp,stun,tcp-mux` and `--features tcp-mux` exit 0.
  These four are **intra-crate** feature combinations — a different class from the
  feature-unification defect fixed in `ConnectionType`, which was cross-crate. Why the item
  existed: nothing gated them, and `cargo check --workspace` cannot see them either — feature
  unification across members re-enables each crate's `default` set, so a `-p`-only failure is
  invisible in the lane meant to cover feature combinations. Hence discovery by a measurement
  round rather than by CI.
  **Fixed** — each `cfg` now names exactly the condition that admits its user:
  - `frp-server/src/state.rs:1883` — `#[cfg(feature = "ssh")]` added to
    `remove_run_id_vnet_routes`, on top of the `#[cfg(feature = "vnet")]` already on its `impl`
    block (`frp-server/src/state.rs:1846`): caller and callee now exist under the same pair.
  - `frp-client/src/nat_hole.rs:529` — the `quic_params` binding's `#[cfg(feature = "quic")]`
    → `#[cfg(all(feature = "quic", feature = "kcp"))]`, agreeing with its only consumer
    (`frp-client/src/nat_hole.rs:668`, inside the `all(quic, kcp)` data-plane arm).
  - `frp-client/src/visitor.rs:94-95`, `:375`, `:1200`, `:1251`, `:1842`, `:3728`, `:3771` and
    `frp-client/src/service.rs:2648`, `:2717` — the whole client `quic_params` chain (the
    `VisitorListenerConfig` field, the `XtcpPunchConfig` field, both destructures, both
    punch-config test literals, and the compute/pass sites) moved from
    `#[cfg(feature = "quic")]` to `#[cfg(all(feature = "quic", feature = "kcp"))]`. The value's
    only consumer is the `cfg.quic_params` read at `frp-client/src/visitor.rs:655`, inside that
    same `all(quic, kcp)` arm, and the type it feeds — `frp_core::xtcp_p2p::QuicTunnelSession`
    with its `xtcp_p2p_connect_quic_session*` constructors — is re-exported by frp-core only
    under `#[cfg(all(feature = "kcp", feature = "quic"))]` (`frp-core/src/xtcp_p2p.rs:137`).
    Widening the *use* was therefore not available: under `quic` without `kcp` frp-client has no
    QUIC data plane at all, so the config field must not exist either.
  - `frp-client/src/visitor.rs:2913-2916` — the two `tokio::io` extension-trait imports in
    `#[cfg(all(test, feature = "vnet"))] mod tests` are now each
    `#[cfg(feature = "compression")]`; the only methods they supply are called from that
    module's single `#[cfg(feature = "compression")]` test (`write_all` at `:3147`, `read_exact`
    at `:3152`).
  - `frp-core/src/xtcp_session.rs:40,47` — split into
    `use std::sync::atomic::{AtomicBool, Ordering};` plus a separately gated
    `#[cfg(feature = "tcp-mux")] use std::sync::atomic::{AtomicU64, AtomicUsize};`. Every
    `AtomicU64`/`AtomicUsize` use is in `ReadActivity`, `LiveP2pStream`, `spawn_tunnel_driver`
    or the `#[cfg(all(test, feature = "tcp-mux"))] mod tests`.
  **Verified after the change (raw exit codes):** the four commands above → **0 / 0 / 0 / 0**
  (was 101 / 101 / 101 / 101). `cargo fmt --all -- --check` → 0. `cargo clippy --workspace
  --all-targets --all-features -- -D warnings` → 0. `cargo check --workspace --all-targets`
  (default features, no `RUSTFLAGS`) → 0. `bash scripts/repo-health.sh` → `RESULT: invariants
  hold`, exit 0 (a repo-path/version gate, not a compile gate). Regression sweep at
  `-D warnings`, all exit 0 — including the item's own measured family: frp-core `kcp,tcp-mux`,
  `kcp,stun`, `vnet,kcp`, `tcp-mux`, `kcp,quic`, `kcp,tcp-mux,quic`; frp-client `vnet,tcp-mux`,
  `quic,kcp`, `vnet,compression`, `quic --all-targets`; frp-server `vnet,ssh`, `ssh`. Tests over
  the edited code: `cargo test -p frp-core --lib xtcp_session` → 2 passed / 0 failed / 854
  filtered out, exit 0; `cargo test -p frp-client --features tcp-mux --lib visitor` → 25 passed
  / 0 failed / 246 filtered out, exit 0; `cargo test -p frp-client --features vnet --lib
  virtual_net` (the re-gated imports' module) → 5 passed / 0 failed / 285 filtered out, exit 0.
  Both frp-client counts moved by exactly 2 when #363 added 2 lib tests — they were first written
  as 244/283. They are **per-feature-set** counts: 246 is over **271** lib tests under
  `--features tcp-mux`, while 285 is over **290** under `--features vnet`, because the
  feature-gated test modules change the denominator. **Nothing gates a `filtered out` value**
  (repo-health has no such entry and skips `TODO.md`), so a bare count in durable prose cannot be
  checked later: state the feature set and its total with it, or the number rots.
  **Gate added** (`.github/workflows/ci.yml:495`, `verify` lane): `Check the four measured-red
  intra-crate feature combinations (curated list, NOT the full 2^N space)` runs exactly those
  four commands in one `set -e` block under `env: RUSTFLAGS: "-D warnings"`, in the isolated `-p`
  form that reproduces them. Step body measured green when run verbatim as a shell script
  (exit 0), so the gate is a gate and not a red step.
  **Residue:** the gate pins **only these four combinations**. It is a curated, closed list —
  not the 2^N intra-crate feature space — as its step name, its step comment and this paragraph
  all state, and **every other intra-crate combination remains unmeasured**, including
  combinations of features not named in this item. Three narrower notes: (a) the three extra
  members of this item's measured family (`kcp,stun`, `kcp,quic`, `vnet,kcp`) are closed by the
  same import split and re-measured at exit 0 above, but they are **not** in the gate — only the
  four named commands are; (b) the second command is the bare form the item measured (no
  `--all-targets`), so a *test-target-only* failure of `frp-client --features quic` without
  `kcp` would not be caught (that variant was measured clean at exit 0, but is not pinned);
  (c) a whole-file-cfg'd *empty* target still reads as clean, so the gate bounds the code
  compiled, not coverage. The step's CI wall-clock cost (four extra feature graphs, each a new
  `RUSTFLAGS` fingerprint, inside a 15-minute lane) was not measured here.
  **Commit:** *fix: gate the four measured-red intra-crate feature combinations, and add the gate
  step.* No sha and no parent sha are cited on purpose: this PR is squash-merged, so any sha
  written here is rewritten the moment it lands and becomes a false citation — the text originally
  carried one, and a rebase onto the post-#363 `main` had already invalidated it before the squash
  could. Identify the change by its subject instead.
- [x] **No lane clippy-checks `frp-core` with features off, so two `clippy::*` lints inside
  `cfg(not(feature = …))` code are red in the micro configuration and invisible everywhere else.**
  Measured 2026-09-28 at `47f8fce`:
  `RUSTFLAGS="-D warnings" cargo clippy -p frp-core --no-default-features --all-targets` → **rc 101**
  with exactly two errors:
  * `frp-core/src/encryption.rs:231:5` — `clippy::new_without_default` for `SnappyCompressor::new`,
    inside `#[cfg(not(feature = "compression"))]`;
  * `frp-core/src/transport/mod.rs:1643:21` — `clippy::needless_return`, inside
    `#[cfg(not(feature = "tls"))]`.

  The set is **complete**, so a fix does not have to hunt for a third: the same command with those two
  allowed (`-- -A clippy::new_without_default -A clippy::needless_return`) exits **rc 0** across all
  targets (lib, lib test, every `frp-core/tests/*.rs`, the bench), and neither file is in this branch's
  diff — both were last touched by `96ccca0` (#358). Why no lane sees it: the only workspace clippy lane
  is `ci.yml:84` (`cargo clippy --workspace --all-targets --all-features -- -D warnings`), which
  **compiles both `cfg(not(…))` items out**, and the two isolated clippy steps (`ci.yml:916-917`) are
  `-p frp-server --no-default-features --features dashboard` and `-p frp-client --no-default-features`.
  The isolated step that *does* compile this configuration — `ci.yml:920`'s frp-core tier step — runs
  `check`, i.e. rustc lints only, which is exactly why the `unused_mut` that the restart-only change
  introduced there fired while a `clippy::*` lint cannot. This is the **same gate gap as that CI
  failure, in the other direction**, which is why it is filed rather than quietly fixed.
  **Done-when:** both lints are gone **and** the configuration is gated — add a
  `clippy -p frp-core --no-default-features --all-targets` step (or extend an existing isolated step to
  run clippy as well as `check`) under `RUSTFLAGS="-D warnings"`, so the gap cannot reopen. Precedent for
  the disposition is the sibling item directly above: those four red `-p` configurations were closed by
  **fixing** the code (narrowing `cfg`s), not by excusing it.
  **Constraint on the `needless_return` fix, corrected in review:** this paragraph originally said the
  `return` itself was **load-bearing** and that its absence caused an **E0308 fall-through**. What is
  load-bearing is the `Err` remaining the arm's **tail expression** — which is exactly what deleting the
  `return` while keeping the value does. Measured: the `return`-less form compiles in the bare, `kcp` and
  `websocket` configurations; it is the **`;`-terminated statement** form (value discarded) that is red.
  The expected type comes from the enclosing `match`'s position: the KCP refusal's match is used as an
  expression statement, so its arms are `()`, and a discarded `Err` leaves `T` unconstrained
  (`error[E0282]: type annotations needed`), while the TCP refusal's match is the function's tail, so its
  arms are `Result<IoStream, Error>` and a discarded value is `error[E0308]: mismatched types`. The pin is
  that the tls-off dial still fails with that error rather than falling through.

  **Done** (no sha — a squash-merge rewrites the branch's hashes, so identify this change by its subject,
  *"lint: gate the frp-core no-features configuration and fix the two lints it hid"*):
  * `frp-core/src/encryption.rs`: `SnappyCompressor` gained a real `Default` delegating to `new`
    (implemented, not `#[allow]`-silenced) inside `#[cfg(not(feature = "compression"))]`.
  * `frp-core/src/transport/mod.rs`: the two tls-off dial refusals (TCP, and WSS under `websocket`) drop
    their `return` and keep `Err(..)` as the surviving tail expression; the listen-side refusals are
    untouched (their `return`s are not linted). Three in-code comments were rewritten to the measured
    diagnostics — the KCP arm's `E0282`/`E0308` pair, the enclosing-match discriminator, and by construct
    rather than by line number throughout.
  * `.github/workflows/ci.yml`: a new step **"Lint frp-core tier test targets (isolated, no features)"**
    (`RUSTFLAGS="-D warnings" cargo clippy -p frp-core --no-default-features --all-targets`; rc 101
    before → rc 0 after) plus a sibling **websocket** step, which alone sees the WSS arm's
    `needless_return`: re-adding `return ` to the WSS dial refusal leaves the bare step green and reddens
    that one, which is why the sibling step is what pins it. The pre-existing `check` step is kept because
    two in-tree comments cite it by name.
  * Verified: fmt, both new steps, workspace all-features clippy, the other isolated `check` steps,
    `cargo test -p frp-core --no-default-features --all-targets` (738 passed / 0 failed), the pin in three
    configurations, and `scripts/repo-health.sh`.
  * Review: four rounds, two reviewers each (one independent, one adversarial and briefed to falsify).
    Both round-2 reviewers independently falsified the same **comment claim** — the attribution of the
    KCP/TCP asymmetry to each arm's `else` — and one round-2 review also falsified a line-number figure the
    orchestrator had published, which is why no line number is written into the comments or into the PR
    body as if current.

- [x] **The tls-off dial pin asserts the TCP refusal with a prefix-only `contains`, which both arms'
  messages satisfy.** `dial_server_refuses_tls_when_tls_is_not_compiled` in
  `frp-core/src/transport/mod.rs` asserts the TCP refusal with `contains("TLS support not compiled")` — a
  24-character needle both source literals begin with (the two full strings are **not** prefixes of each
  other: 50 characters are shared and they diverge at the 51st, TCP's `)` against WSS's ` for WSS)`) — so
  swapping the TCP arm's message for the WSS wording leaves the bare-configuration assertion green. (The
  assertion tests `err.to_string()`, which begins `transport error: `, so a start-anchored rewrite would not
  be equivalent.) End-anchoring the TCP assertion **would** discriminate. Measured by
  adversarial review of the no-features clippy fix (mutation `tcp_wssmsg` + the pin under
  `--no-default-features` → rc 0). Filed rather than fixed so that the fix round stayed comment-only.
  **Done-when:** the assertion is end-anchored or negated so the WSS-only wording fails it, with a mutation
  showing the swapped-message case now fails.
  Done: the assertion at `frp-core/src/transport/mod.rs:2535` now reads
  `err.to_string().ends_with("TLS support not compiled (enable the 'tls' feature)")` (`:2536`), replacing the
  24-character prefix-only `contains`. Mutation `tcp_wssmsg` (the TCP arm's literal at
  `frp-core/src/transport/mod.rs:1703` swapped for the WSS wording) + that assertion, via
  `cargo test -p frp-core --no-default-features --lib dial_server_refuses_tls_when_tls_is_not_compiled`:
  rc **101**, panicked at `frp-core/src/transport/mod.rs:2535` with
  `got: transport error: TLS support not compiled (enable the 'tls' feature for WSS)`; the **same mutation
  with the old prefix `contains`** was rc **0** (`1 passed; 0 failed`), which is the gap this closes.
  Unmutated: the same command rc **0** (`1 passed / 0 failed`) and `--features websocket` with `tls` off
  rc **0**. Sweep of `contains("TLS support not compiled")`: one hit (this assertion); the WSS sibling at
  `:2557` already asserts the full WSS literal, and the four `frp-client` plugin literals
  (`… not compiled in`) are asserted nowhere, so no second prefix-only needle. Mutated file restored to
  sha256 `4a80261dbfb0b40728695744b7457455c86771162afe87e661ef40222b0a04c8`. Ledger: **26 open / 107 closed**
  → **25 open / 108 closed** (the `- [ ]` → `- [x]` flip moves the item; total stays 133). No CHANGELOG bullet: its `## Unreleased` sections are user-facing
  (Features/Changed/Fixed/Docs) and recent test/doc-only commits (`c4357fc5`, `66be9ce1`) added none.

- [x] **Pre-existing: no query-parameter-count guard, so >10000 params diverge from Go.**
  Go's `parseQuery` opens with
  `if !urlParamsWithinMax(strings.Count(query, "&") + 1) { return Values{}, err }`
  (`net/url/url.go:1019-1020` in go1.25.12, the shipped binary's toolchain — line numbers
  drift between Go releases, `:980` in go1.27.1; `defaultMaxParams = 10000` at `:1001` in
  go1.25.12), so an over-limit query yields empty
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
  Done: `first_strict_config_param` (`frp-client/src/admin.rs`) now opens with
  `if raw.matches('&').count() + 1 > GO_DEFAULT_MAX_PARAMS { return None; }`
  (`GO_DEFAULT_MAX_PARAMS = 10000`), before any pair is parsed, so an over-limit query takes
  the same "parameter absent" path as the `%zz` case — which means the frp-rs JSON-body
  extension still applies when a body is present (Go reads no body at all, so that channel is
  a frp-rs extension either way). Count, inclusivity and the GODEBUG precision
  (`urlmaxqueryparams`, so the parity target is the shipped binary's default rather than "Go
  in general") are in the `GO_DEFAULT_MAX_PARAMS` doc comment. Pinned by
  `first_strict_config_param_mirrors_go_max_param_guard` (boundary: 9999 `&` -> `Some`, 10000
  `&` -> `None`), `reload_over_max_params_flips_strict_decision_like_go` (handler level: 9999
  `&` -> observed strict, 10000 `&` -> observed non-strict, 10000 `&` + body `true` ->
  observed strict) and `admin_max_query_params_boundary_matches_go` (wire level against the
  unknown-key oracle: 400 / 400 / 200).
- [x] **Pre-existing: `#` in the request target changes strictness.** Go parses request URIs
  with `viaRequest=true`, which never splits a fragment, so `#` stays inside `RawQuery` and
  `GET /api/reload?strictConfig=true#strictConfig=false` is a **200** non-strict reload (the
  value becomes `true#strictConfig=false`, which `ParseBool` rejects). `axum::extract::RawQuery`
  comes from `http::Uri`, which strips the fragment, so frp-rs reads `strictConfig=true` and
  is strict — same endpoint, opposite strictness. **Done-when:** the raw request target is
  used (or the divergence documented at the endpoint), with the `#` case pinned.
  Done: documented and pinned, **not fixed** — the divergence is unrecoverable at this layer.
  `RawQuery` comes from `http::Uri`, which truncates the target at the first `#`
  (`http-1.5.0/src/uri/path.rs:28-29`:
  `if let Some(i) = fragment { src.truncate(i as usize); }`) inside hyper's request-line
  parsing, before any frp-rs code runs; recovering the raw target would mean replacing the
  HTTP stack. Both manifestations are recorded on `first_strict_config_param` (which has the
  `net/url` citation) and in the admin-API prose in `docs/deployment.md`, and pinned by
  `admin_hash_fragment_divergence_is_pinned`
  (`frp-client/tests/reload_malformed_config.rs`) as a known divergence, so a future change
  that "fixes" either one fails the pin and forces the record to be updated:
  `?strictConfig=true#strictConfig=false` -> frp-rs 400 where Go is 200;
  `/api/reload#x?strictConfig=true` -> frp-rs 200 where Go is 404.
- [x] **The admin HEAD/auth placement matches Go only for *authenticated* requests; a measured
  alternative matches on every axis but is deliberately not adopted here.** With the per-route
  `.head(...)` + `.layer(auth)` arrangement in `frp-client/src/admin.rs`, an *unauthenticated*
  HEAD on a registered route is 401 where Go is 405, and an unauthenticated request to an
  unknown path (GET or HEAD) is 401 where Go is 404. Reviewer 2 measured a configuration that
  matches Go on every axis — `.route_layer(auth)` instead of `.layer(auth)` (which alone fixes
  the two unknown-path cells, because middleware added that way runs only when a route matches)
  plus a **route-aware** outermost HEAD layer (which fixes the unauthenticated-HEAD cell):
  8/8 rows on an isolated axum 0.8.9 probe and 14/14 rows on the real admin router over the
  wire; the coordinator reproduced the mechanism. Not adopted here as a deliberate scope
  choice:
  1. `.route_layer` makes unmatched paths bypass auth, so an unauthenticated client gets
     404/405 for an unknown path instead of 401 — it reveals which paths and methods exist.
     axum's own `route_layer` doc names this trade-off ("might otherwise convert a
     `404 Not Found` into a `401 Unauthorized`"). Reviewer 2 measured the sharper form: an
     unauthenticated `GET /api/store/proxies` would answer 401 when the store is enabled and
     404 when it is not, disclosing *configuration state*, not merely path existence. That is
     a security-posture change, and this repo already deviates from Go for security elsewhere:
     a wildcard/unspecified `web_server.addr` is forced to `127.0.0.1` regardless of auth (an
     explicit non-loopback address is honoured only when auth is set).
  2. The HEAD half needs a production route-pattern predicate that matches `{name}` segments
     without over-matching (`/api/proxy/a/b/config`); Reviewer 2's prototype over-matched.
     axum 0.8.9 exposes no route introspection (only `has_routes() -> bool`), so the predicate
     would be a hand-maintained path list — the maintenance hazard
     `frp-core/src/config/strict.rs:280-285` refuses.
  3. `apply_admin_auth` is shared (`frp-core/src/admin_auth.rs:36`), called from
     `frp-client/src/admin.rs` and `frp-server/src/dashboard.rs:3610/3626/3650`, so switching
     it to `route_layer` is not scoped to the frpc admin API.
  **Done-when:** either adopt the alternative with a production route predicate and the
  dashboard's auth posture re-reviewed (accepting the path-existence and configuration-state
  disclosure), or record in
  `docs/deployment.md` that the 401-vs-404/405 unauthenticated divergence is permanent. No sha.

  Done (branch `docs/admin-head-divergence`, based on `main` @ `9007ba7`): closed by the
  **documentation** branch, with the record corrected after the adversarial review falsified its
  first draft. `docs/deployment.md`'s admin-API paragraph now splits the two unauthenticated
  mismatches by kind, and `frp-client/src/admin.rs`'s rationale carries the same correction:
  * the **unknown-path** cell (`401` here vs Go's `404`, GET or HEAD) is **permanent by decision**:
    `401` hides which paths exist, and a matched-routes-only construction (a blanket `route_layer`)
    would answer `404` there and disclose configuration state too — measured on that construction,
    `GET /api/store/proxies` answers `401` with `[store]` configured and `404` without it (the code
    supports it: `/api/store/*` is registered only when the store is enabled);
  * the **`HEAD`-on-a-registered-route** cell (`401` here vs Go's `405`) is **not** an
    impossibility and needs no route predicate: the adversarial review **measured** a construction
    that matches Go on it — per-handler auth on the registered GET/POST routes, the existing
    unauthenticated `handle_head_not_allowed` left on each route's `.head(...)`, and an
    auth-wrapped `Router::fallback` — with an axum 0.8.9 probe (`405` there, unmatched paths still
    `401`), against Go frp v0.71.0's cells measured over the wire. It is rejected because
    authentication then becomes **opt-in per route**: a route added later without the wrapper is
    unauthenticated by default, whereas the single outer layer authenticates every route, present
    and future, by default. Any future fix must first close that fail-open foot-gun (a wrapping
    helper that is the only registration entry point, plus a test that every registered route
    answers `401` unauthenticated — the existing HEAD-405 test already drives the real router over
    a hand-maintained GET-route list, so the barrier is smaller than it looks).
  `apply_admin_auth` is demoted from "reason the cell cannot be fixed" to a scope note: only a
  *blanket* switch to `route_layer` is out of scope, because the frps dashboard calls the same
  helper; the per-handler construction is admin-local. `admin_head_auth_divergence_is_pinned`
  (`frp-client/tests/reload_malformed_config.rs`) asserts the cells over the wire with authenticated
  controls (unknown path `404`, `HEAD` on a registered route `405`) and a positive control that the
  armed config really does move a proxy, so "401 and no reload" cannot pass vacuously; switching the
  live layer to `route_layer` fails it at the unknown-path assertion with a message that names the
  doc update (measured by both reviewers, reverted). **Citation corrections:** this item's
  `.layer(auth)` is not in `frp-client/src/admin.rs` — the layer is applied in
  `frp-core/src/admin_auth.rs` (`apply_admin_auth`) and `admin.rs` reaches it through that helper;
  and the dashboard call sites are `frp-server/src/dashboard.rs:3656/3672/3696`, not the
  3610/3626/3650 written above (verified by grep). Residue: the `GET /api/store/proxies`
  store-on/off pair is **inferred** from the measured matched/unmatched cells plus the conditional
  `/api/store/*` registration (only the Go store-on/off pair and the `route_layer` cells were
  measured end to end), and the Go cells are the review rounds' wire measurements, not re-run in this
  change; this host cannot bind `127.0.0.2`, so the full
  `cargo test -p frp-client --features admin -j 1` lane fails at
  `frp-client/tests/peer_xff_registry_e2e.rs:326` for an environmental reason (that file is not in
  this diff; both reviewers reproduced it).
- [x] **Strict mode accepts unknown fields inside `[[proxies]]` / `[[visitors]]`, where Go
  rejects them — a deliberate, documented divergence that is not in this list and not in the
  user-facing docs.** Measured with identical config text on Go frp v0.71.0 and frp-rs, both
  through `GET /api/reload?strictConfig=true`:

  | unknown field in | Go v0.71.0 | frp-rs |
  |---|---|---|
  | `[auth]` / `[log]` / `[webServer]` / `[transport]` | 400 | 400 |
  | a `[[proxies]]` entry | **400** (`decode proxy at index 0: ... unknown field`) | **200** |
  | a `[[visitors]]` entry | **400** | **200** |

  This is **deliberate, not an oversight**: `section_known_keys`
  (`frp-core/src/config/strict.rs`) documented at the time that sections not listed are not
  recursed into — *"Go's RejectUnknownMembers (pkg/config/v1/decode.go) rejects unknown
  proxy/visitor/plugin fields; frp-rs deliberately does not recurse into them — per-type keys
  would make the check a maintenance hazard, and skipping the recursion is the looser
  direction, keeping valid frp-rs configs loading."* **That quoted rationale is retracted**:
  the key set is per *struct*, not per type, and the recursion landed below (`TODO.md:1193`),
  which deleted the comment this quote came from. The quote is kept only as the historical
  record of what this item set out to correct. The point of this item is that the
  decision lives only in that code comment: it is absent from this known-debt list and from
  the user-facing strict-mode prose in `docs/deployment.md`, which lists "a strict-mode
  unknown key" as a 400 source without the exemption. Consequence: a typo in a proxy or
  visitor block is silently ignored in strict mode — the same silent-config-loss class as the
  camelCase wire-field gotcha.
  **Done-when:** either recurse into the arrays with per-type key sets (Go-faithful; needs a
  maintenance story for new proxy types and their aliases), or state the exemption and its
  rationale in the strict-mode prose in `docs/deployment.md`, so a user knows a proxy-block
  typo will not be caught. No sha.

  Done (branch `docs/strict-proxy-exemption`, based on `main` @ `c00b2e8`): closed by the
  **documentation** branch, with the rationale corrected after the adversarial review falsified the
  first draft. `docs/deployment.md`'s strict-mode prose now states the exemption, its true scope and
  its non-uniform consequence, and `strict_mode_exempts_proxy_and_visitor_array_elements`
  (`frp-core/src/config/tests.rs`) pins it (a `tcp` proxy, a plugin proxy, an `xtcp` visitor and a
  server `[[httpPlugins]]` entry with unknown keys all load; the same key at top level and unknown
  keys in `[log]`/`[auth]`/`[transport]`/`[webServer]` are still rejected), complementing the older
  `test_strict_accepts_unknown_proxy_field_deliberate_divergence` (#273), which pinned only the `tcp`
  half. What the review changed:
  * the first draft's rationale — "per-type key sets … would be a maintenance hazard" — is **false**:
    `ProxyConfig`, `VisitorConfig` and `HttpPluginConfig` are each a *single union struct* that
    already carries Go's camelCase spellings as serde aliases, so the set is per **struct**, and the
    adversarial review generated it mechanically (163 keys over `proxies`/`visitors`/`http_plugins`/
    `plugin`) and wired array recursion with **zero false positives** across 77 blocks / ~92 keys (the
    only two failing tests were the ones asserting the exemption);
    `#[serde(deny_unknown_fields)]` on those structs reaches the same result in ten lines. The record
    now gives the *measured* trade-off instead: that attribute is unconditional (it cannot be keyed on
    `strictConfig`, so it would tighten non-strict loads, which Go leaves loose), while a strict-only
    scan list must track every field and alias, exempt the open maps (`headers`, `response_headers`,
    `annotations`, `metas`) and nested arrays, and has no reflection to prove completeness — a false
    400 blocks a valid config where a missed typo only drops a key. Keeping the loose direction is
    therefore stated as a **choice**, not a missing capability, and the affordable fix is now the
    item below;
  * the consequence is not uniform: an unknown or optional key is dropped silently (`remote_portt =
    7001` loads as `remote_port: 0` — the silent-config-loss class), but a **required** key left unset
    is rejected (`visitor 'v': bind port is required`);
  * the divergence is wider than the reload answer: with strict mode on (Go's default), Go frpc
    **refuses to start** on such a config
    (`decode proxy at index 0: unmarshal ProxyConfig error: json: unknown field
    "bogus_key_in_tcp_proxy"`, measured against the real binary with default flags), where frp-rs
    starts with the key
    dropped; the exemption also covers nested arrays (`healthCheckHttpHeaders`) and nested tables in
    unwalked sections (`auth.tokenSource.exec.env`);
  * the pin's teeth comment was wrong about the mechanism (adding `section_known_keys` arms alone
    changes nothing — the enforcement is `check_strict`'s Table-only recursion guard) and is reworded;
    the reviewer measured that the pin does fail once the arrays are recursed into, with Go-shaped
    messages.

- [x] **Strict mode can be made Go-faithful in the proxy/visitor arrays cheaply — the fix is measured
  and one serde attribute away.** The adversarial review built it during
  `docs/strict-proxy-exemption`: `ProxyConfig` (`frp-core/src/config/client.rs`), `VisitorConfig`
  (same file) and `HttpPluginConfig` (with `PluginConfig`, `frp-core/src/config/server.rs` —
  corrected here: an earlier revision of this item said `frp-server`'s `server.rs`) are single
  union structs carrying
  Go's camelCase spellings as `#[serde(alias)]`, so the key set is per **struct**; generating it
  mechanically (163 keys over `proxies`/`visitors`/`http_plugins`/`plugin`) and recursing into the
  arrays in `check_strict` gives `cargo test -p frp-core --lib config` → 258 passed / 2 failed — the
  only two failures being the tests that assert the exemption — with **zero false positives** across
  77 blocks and ~92 keys. `#[serde(deny_unknown_fields)]` on those five structs produces the identical
  result with no list to maintain, at the cost of also tightening *non*-strict loads (it cannot be
  keyed on `strictConfig`). What is missing is not capability but a decision plus a drift guard.
  **Done-when:** either wire strict-only recursion with a per-struct list and a test that fails when a
  struct field or alias is added without the list (the exemption pins in `frp-core/src/config/tests.rs`
  flip to assert rejection), or record in `docs/deployment.md` — with a measurement, not the retracted
  "per-type" claim — that the false-400 risk of a scan list is the larger cost in this configuration.
  **CLI-surface evidence added 2026-09-26** (measured while closing the exit-code item at `:1503`;
  the done-when above is unchanged): an unknown key inside a `[[proxies]]` block is accepted by
  frp-rs, and the CLI reports it as success or as an unrelated runtime failure.
  * Go v0.71.0 `frpc verify -c badproxy.toml` (valid client config plus `notAKnownProxyKey = 1`
    inside `[[proxies]]`) → stdout `decode proxy at index 0: unmarshal ProxyConfig error: json:
    unknown field "notAKnownProxyKey"`, exit **1**.
  * frp-rs `frpc verify -c badproxy.toml` → `Config file … is valid`, exit **0**; `frpc -c
    badproxy.toml` → logs `frpc (Rust) v0.71.0 connecting...` and exits 1 later, because the
    config was accepted and the *connection* failed. That rc matches Go by coincidence only and
    must not be cited as parity on this row.

  Done (branch `fix/strict-array-parity`, based on `main` @ `97fdd38`): **option (A)** — strict-only
  recursion with per-struct key sets in `check_strict`, plus a drift guard. Measured **first** on both
  binaries (Go frp v0.71.0 darwin/arm64 against the frp-rs `frpc`/`frps` built from this branch), with
  Go's camelCase spellings at every level so a Go rejection is attributable to the injected key:
  * unknown key in an array element — Go rc 1 `decode proxy at index 0: unmarshal ProxyConfig error:
    json: unknown field "notAKnownProxyKey"`; frp-rs before rc 0 (`Config file … is valid`), after
    rc 1 `unknown field "proxies[0].notAKnownProxyKey"`. Same shape for `[[visitors]]`
    (`visitors[0].notAKnownVisitorKey`) and the server `[[httpPlugins]]` array
    (`http_plugins[0].notAKnownHttpPluginKey`; Go's message there carries no index prefix —
    `json: unknown field "notAKnownHttpPluginKey"`). `[[proxy]]`/`[[visitor]]` singular spellings are
    rejected by **both** as unknown *top-level* keys (Go: `json: unknown field "proxy"`), and the
    loader accepts no other array spelling.
  * nested objects inside an element — `[proxies.transport]`, `[proxies.healthCheck]`,
    `[proxies.loadBalancer]`, `[proxies.natTraversal]` and `[[proxies.healthCheck.httpHeaders]]` each
    draw a Go rejection and now draw one from frp-rs too (the normalizer flattens those tables onto
    the element before the check, so their keys are checked as element keys; the header array gets its
    own two-key set). Residual, measured: an unknown key inside `[proxies.requestHeaders]` /
    `[proxies.responseHeaders]` (or the `plugin` equivalents) stays accepted because `normalize_proxies`
    consumes those tables — Go rejects it. Documented, not silently assumed.
  * plugin depth — `[proxies.plugin] notAKnownPluginKey` and `[visitors.plugin]
    notAKnownVisitorPluginKey` now rejected; `[proxies.plugin.requestHeaders] <unknown>` remains
    accepted for the same normalize reason.
  * false-positive sweep — all **160** keys of the six lists (ProxyConfig 67, VisitorConfig 32,
    PluginConfig 39, VisitorPluginConfig 11, HttpPluginConfig 9, HealthCheckHttpHeader 2) placed
    inside their element produce **zero** `unknown field` diagnostics after the change (0/160), and
    the 13 alias/known-key probe blocks (camelCase aliases, snake_case, frp-rs-only
    spellings, known nested tables) plus the repo's whole config suite still load. The prototype's
    "163 keys" over four groups is not reproducible from this tree; this tree extracts 160 over six.
  * the one measured new divergence — Go's `encoding/json` matches field names case-insensitively, so
    Go accepts **and applies** `RemotePort`/`REMOTEPORT`/`remoteport` (measured this round on a real
    Go frps + Go frpc pair: `GET /api/proxy/tcp` reports the requested `remotePort` verbatim for all
    three spellings; the earlier draft only had `verify` rc 0); frp-rs's lists
    match exactly, so strict mode now refuses them (`unknown field "proxies[0].RemotePort" … did you
    mean 'remotePort'?`) where it previously dropped the value silently at rc 0. This mirrors the
    pre-existing top-level behaviour (`SERVERADDR`: Go rc 0, frp-rs rc 1) and non-strict still drops
    the key (`remote_port: 0`).
  * **legacy-shaped sections, the class (second round, both reviewers' block):** the legacy collector
    pushes sections into `proxies`/`visitors` before the check, so Go's *prefix* mechanisms reached
    the new element walk. The collector keys on the **shape** (a top-level mapping carrying `type`),
    not on the `.ini` extension, so it applies to every format — the carriers say so, and the
    non-INI consequence is recorded in `docs/deployment.md`: Go's v1 decoder rejects such a section
    name (`json: unknown field "legacysection"`, exit 1) while frp-rs collects it; measured
    identically for `.toml`/`.json`/`.yaml` at base (exit 0), the round-1 head (exit 1,
    `proxies[0].notAKnownKey`) and now (exit 0). Pre-existing and permissive, so it cannot cause a
    false 400; scoping the collection to INI would mean threading the file format into
    `normalize_client_config` and would remove the top-level-table spelling, so it is recorded
    rather than changed. Swept every prefix/multi-key site in `pkg/config/legacy/*` + `conversion.go` (the
    only ones: `meta_` in `client.go:196`/`proxy.go:198`, `header_` in `proxy.go:244`,
    `plugin_`/`plugin_header_` in `proxy.go:209`/`conversion.go:174`, `oidc_additional_` in
    `client.go:197`, `range:`/`plugin.` section prefixes) → 24 rows, all Go-VALID, **21 refused at the
    first head**. Now all 24 load: `meta_*`→`metadatas`, `header_*`→`headers` (`type = "http"` only,
    as Go), `plugin_header_*`→the plugin's `request_headers` for `http2https`/`https2http`/
    `https2https` only, and every leftover key Go ignores (`[common]`-only keys misplaced into a proxy
    section — **nine**, not the two first recorded: `start`, `log_level`, `log_file`, `log_max_days`,
    `log_way`, `login_fail_exit`, `tcp_mux`, `pool_count`, `privilege_mode`, plus a stray `plugin_*`
    parameter such as `plugin_enable_http2`, a visitor's `meta_*`/`header_*`, and an unknown key in a
    legacy `[plugin.xxx]` server section) is **dropped** by `strip_unknown_legacy_element_keys`, i.e.
    Go's accept-and-ignore. Go's own shipped `conf/legacy/frpc_legacy_full.ini` is vendored
    byte-identically at `frp-core/src/config/fixtures/frpc_legacy_full.ini` and pinned through the
    strict check by `legacy_ini_go_shipped_fixture_passes_strict_mode` (it carried 6 new
    `unknown field` refusals at the first head).
  * `health_check_interval_s` / `health_check_timeout_s` (`pkg/config/legacy/proxy.go:130,136` →
    `conversion.go:204-206`) are renamed onto the v1 fields; when both spellings are present the `_s`
    value wins, matching Go — measured on a real Go frps+frpc pair with a dead local port and the
    health-check log gaps: `_s = 2` → a check every 2.0 s with or without `_seconds = 99`,
    `_seconds = 2` alone → one check then the 10 s default, `_s = 99` + `_seconds = 2` → one check.
    `insert`, not `or_insert`, in `collect_legacy_ini_proxy_sections`.
  * **alias hole (reviewer B):** `child_array_keys` matched only `health_check_http_headers`, so the
    surviving serde alias `healthCheckHttpHeaders` walked past the header-array check. Both spellings
    are now listed; `strict_mode_rejects_unknown_health_check_header_via_both_spellings` pins it.
  * tests flipped: `strict_mode_rejects_unknown_proxy_and_visitor_array_elements` (was
    `…_exempts_…`), `test_strict_rejects_unknown_proxy_field` (was
    `…_accepts_unknown_proxy_field_deliberate_divergence`),
    `case_insensitive_proxy_array_key_is_refused_in_strict_mode` (was `…_is_dropped_…`, now asserting
    refusal in strict and the drop in non-strict), and the CLI counterpart
    `case_insensitive_proxy_array_keys_are_refused_in_strict_mode` in `frpc/tests/cli_inputs.rs`.
    Red evidence: before the flips `cargo test -p frp-core --lib config` was 276 passed / **3 failed**
    — exactly those pins and no other config test; the prototype's 2 failures predate
    `case_insensitive_proxy_array_key_is_dropped_in_strict_mode`. After the flips and the tests added
    in the second round (`cargo test -p frp-core --lib config`): **288 passed / 0 failed**.
  * drift guard — `strict_array_element_keys_match_struct_fields` (`frp-core/src/config/tests.rs`)
    extracts field names, `rename(deserialize = …)` and `alias` values from `client.rs`/`server.rs`
    via `include_str!` and compares both ways with the lists. Red evidence: adding
    `alias = "localPortDrift"` to `ProxyConfig.local_port` fails it with `PROXY_KNOWN_KEYS is missing
    serde keys ["localPortDrift"] of ProxyConfig`. **Hardened in the second round** after reviewer C
    found a container `#[serde(rename_all = "camelCase")]` mutant slipped through: the scanner now
    accepts `pub(crate)`/`pub(super)`/`pub(in …)` fields and `rename(deserialize = …)`, and
    **panics** on `rename_all`/`flatten`/`untagged`/`transparent`/`tag`/`content` or any
    unrecognised serde attribute instead of guessing (it *models* `skip`/`skip_deserializing` by
    excluding the field from the key set, so those must be absent from the lists). Round 3 closes two more
    extractor holes R2 found: a field with **no** visibility modifier (R2's
    `#[serde(default, alias = "driftPriv")] drift_priv: String` on `HealthCheckHttpHeader` compiled,
    left the guard green and made the binary refuse the serde-accepted `driftPriv` — the hardened
    scanner reports `HEALTH_CHECK_HEADER_KNOWN_KEYS is missing serde keys ["driftPriv",
    "drift_priv"]`), and `rename(serialize = "…")`-only, where serde deserializes from the field name
    (measured with a probe: `{"inner":1}` parses, `{"out":1}` does not) so the guard uses the field
    name instead of failing a legitimate edit. A third hole R2 found is closed too: a **raw
    identifier** (`pub r#match: String`) was not recognised at all, so the extractor returned an
    empty set for the struct — serde accepts the stripped name (`match`) and the alias (probe:
    `{"match": …}` and `{"aliasMatch": …}` fill the field, `{"r#match": …}` does not), so the guard
    was green while the binary refused both keys (`unknown field
    "proxies[0].healthCheckHttpHeaders[0].match"`, rc 1 under the mutant). The prefix is now
    stripped, which also fixes the same field in last position carrying `#[serde(flatten)]` (the
    stale attribute list used to go unclassified and the open-ended guard returned a closed set).
    Nine extractor tests now pin the behaviour (five `#[should_panic]`: `rename_all`, `flatten`,
    `flatten` behind a raw ident, an invented attribute, a missing struct, plus the spaced
    `#[serde (…)]` form; and three positive: private fields, the serialize-only case, raw
    identifiers). `#[cfg]`-gated fields are read as always present (safe direction) while
    `#[cfg_attr(…, serde(rename/alias = …))]` is invisible and gives the **false-400** direction on
    the feature-enabled build — both stated in `docs/deployment.md` with the `otel` probe, and
    `strict_known_key_lists_are_all_covered`, which parses `strict.rs` and fails if a `*_KNOWN_KEYS`
    list is not compared by the guard. Red evidence for the new teeth: the `rename_all` mutant that
    previously passed now panics with ``does not model `#[serde(rename_all)]` (container attribute)``.
    The precision is stated in `docs/deployment.md`: the guard does not *model* those transformations,
    it refuses them.
  * `#[serde(deny_unknown_fields)]` was **not** used: it cannot be keyed on `strictConfig`, so it
    would tighten non-strict loads, where Go stays lenient.
  * **carrier corrections from the same round:** `docs/config.md` advertised seven camelCase spellings
    that are not Go names and no longer load (`healthCheckType`, `healthCheckURL`,
    `healthCheckHTTPHeaders`, `healthCheckIntervalS`, `healthCheckTimeoutS`, `healthCheckMaxFailed`,
    and the per-proxy `virtualNet`, which in Go is a *top-level client* key, `client.go:66`); those
    rows now name the nested Go spelling and flag the change. The report's earlier "the retracted
    wording is not repeated anywhere" was wrong — the old closed item at `TODO.md:1140` quoted it
    verbatim and cited the deleted `strict.rs` comment; both are repaired above. The item's own
    `frp-server/src/config/server.rs` path was wrong and is corrected in place.
  * pre-existing legacy-INI gap found while using Go's fixture: a bare numeric INI value for a string
    field (`token = 12345678`, `meta_var1 = 123`) is inferred as a TOML integer by `ini_to_toml` and
    then rejected by serde, so Go's shipped fixture cannot load end to end here. Independent of this
    item (the same failure occurs with the array walk reverted); the fixture test therefore asserts at
    the strict-check layer, and the gap is recorded in the fixture README and as a new open item in
    this file rather than silently worked around.
  * `scripts/compat-test.sh` was **not** run: the diff is config-load only (no protocol, transport,
    encryption or proxy path), so it cannot reach the wire.

- [x] **Legacy INI still diverges from Go in three measured ways (value inference, `[range:...]`
  list and role handling).** Discovered while closing `:1193`; all three are pre-existing (identical
  at `97fdd38` and at the current head) and none of them is caused by the strict-mode array walk.
  `parse_to_toml_value`/`ini_to_toml` turn a bare numeric value into a TOML integer and a
  comma-separated value into a TOML array, but INI (and Go's `gopkg.in/ini`) treats every value as
  a string, so a string-typed serde field fails:
  * `[common] token = 12345678` (Go frp's own `conf/legacy/frpc_legacy_full.ini`) → frp-rs
    `config validation error: invalid type: integer \`12345678\`, expected a string`, exit 1;
    Go `frpc verify -c` exit 0 and the token is the string `12345678`. Same for `meta_var1 = 123`
    (a `metadatas` value).
  * `[common] allow_ports = 2000-3000,3001,3003,4000-50000` (Go's `conf/legacy/frps_legacy_full.ini`)
    → frp-rs `config validation error: invalid type: sequence, expected a string`, exit 1;
    Go `frps verify -c` exit 0.
  * **A comma list inside a `[range:...]` template is silently skipped**, which is worse than a
    type error: the section is *dropped*, not rejected. Measured with
    `[range:x] type = tcp local_port = 6010-6012,6020` (and the same for `remote_port`):
    Go registers **4** proxies (`x_0`…`x_3`, read from `GET /api/proxy/tcp` on a real Go frps);
    frp-rs `frpc verify` reports `Proxies: 0` plus
    `WARN … legacy INI [range:...] section: missing or invalid local_port; skipped` — at the base
    commit and at the current head alike. A simple range (`6010-6012`) yields 3 on both, so the
    trigger is the comma list: `ini_to_toml` splits it into a TOML array and
    `ini_port_numbers` accepts only `String`/`Integer`. Go's own
    `conf/legacy/frpc_legacy_full.ini:196-200` uses
    `local_port = 6010-6020,6022,6024-6028`, i.e. 11 + 1 + 5 = **17** numbers
    (`pkg/util/util/util.go:71` splits on `,`, `pkg/config/legacy/client.go:314-336` renders one
    proxy per number), so **17 range-expanded proxies are dropped** from the shipped fixture —
    a second blocker, alongside the numeric one, for loading it end to end.
  * **A `[range:...]` template with `role = visitor` is misrouted to proxies.** Go dispatches on
    `role` after expanding the template (`pkg/config/legacy/client.go:271` →
    `NewVisitorConfFromIni`), so `[range:rv] type = stcp role = visitor …` builds visitors; frp-rs's
    range branch always appends to `proxies`, and the strict-pass strip then drops the
    visitor-only keys (`role`, `bind_addr`, `bind_port`, `server_name`). Measured with a
    `6010-6012` range: Go rc 0 and its frpc logs `visitor added: [rv_0 rv_1 rv_2]` (three
    visitors; two fail to bind the shared `bind_port = 6000`, which the template gives all of
    them); frp-rs reports `Proxies: 3 Visitors: 0` at the base commit and at the current head
    alike. Pre-existing and net-unchanged versus base — the round-1 head only made it loud
    (`unknown field "proxies[1].role"`) before the strip restored the drop.
  All three classes are pre-existing (independent of the strict-mode array walk: the same files
  fail with the walk reverted) and are why `frp-core/src/config/fixtures/frpc_legacy_full.ini`,
  vendored byte-identically for the strict-check regression test, is asserted at the strict-check
  layer rather than loaded end to end.
  **Done-when:** either keep the INI values as strings for fields the target struct declares as
  strings (a `deserialize_with` that accepts an integer/array and joins it, or an INI-specific
  pre-pass) and let `ini_port_numbers` accept the split array, or record the divergences as
  durable in `docs/config.md`; either way pin both shipped fixtures with a full `frpc verify` /
  `frps verify` load against the Go behaviour above (for the range case, against the registered
  proxy count).

  **Done — fixed, not recorded (2026-09-27).** All three classes are fixed and both shipped fixtures
  load end to end; nothing was left to `docs/config.md` as an open divergence except the
  pre-existing base-0 integer note and the array-literal spelling (below).
  * **Independence re-measured, not inherited.** The claim that the three classes are independent of
    #384's array walk was re-verified twice: (a) with `--strict-config=false` (the walk does not run
    at all) every class is byte-identical to strict mode; (b) a scratch copy of this branch with the
    walk reverted to `Some(toml::Value::Array(_)) => {}` reproduces all three — client fixture
    `invalid type: integer \`12345678\`, expected a string` plus the `WARN … invalid local_port`
    (rc 1), `[range:x] local_port = 6010-6012,6020` -> `Proxies: 0`, `role = visitor` range ->
    `Proxies: 3 Visitors: 0`.
  * **Class 1 — value inference: fixed at the deserialization boundary, not by weakening the
    schema.** `infer_ini_value` is now **lossless through both renderers** (a value becomes an
    integer/float/boolean/array only when *both* `ini_value_text` and the JSON projection reproduce
    the text the file wrote — so `007`, `1.50`, `1e3`, `YES`, `a, b`, `a\,b`, `a.example.com,`,
    `1e19` and `10000000000000000000` stay text). The JSON half matters: Rust's `f64` Display is
    plain decimal where serde_json's `ryu` rendering is exponential, so a check against the TOML
    rendering alone let `meta_id = 10000000000000000000` reach a string field as the **`"1e+19"`**
    serde_json renders (and `token = 0.0000001` as `"1e-7"`) — a string field accepting a
    *different* value than the file wrote, i.e. the class this item exists to fix (R1's MAJOR,
    reproduced here: base rc 1 ``invalid type: floating point `1e-7` ``, the intermediate head
    accepted it, head now reads `"0.0000001"`). Comma lists are split with Go's own
    `Key.Strings(",")` (`key.go:492`, measured on Go v0.71.0: `a\,b` → `["a,b"]`,
    `x\,y,z` → `["x,y", "z"]`, `a.example.com,` → `["a.example.com"]`; base and the first cut gave
    `["a\\", "b"]` and `["a.example.com", ""]`), in the inference, in the deserializer and in the
    two normalizer list conversions. `.ini` inputs are deserialized by a type-directed reader
    (`frp-core/src/config/ini_lenient.rs`, `deserialize_ini`) used only when `detect_format` says
    `.ini`: a string field reads the text Go's `ini.v1` `Key.String()` would give it, a numeric/bool
    field parses it (`Key.Int64()`/`parseBool` spellings), and a slice field splits it with Go's
    `Key.Strings(",")` rules. TOML/JSON/YAML keep strict serde typing, so no numeric `token` in a
    `.toml` became acceptable. The one normalizer conversion that reads a wider spelling set is
    gated on the `.ini` format (`canonicalize_legacy_ini_bools`): `[common] authenticate_heartbeats = 1`
    / `= yes` now adds the `HeartBeats`/`NewWorkConns` scope as Go's `parseBool`
    (`pkg/auth/legacy/legacy.go:25,28` + `conversion.go:31-36,92-97`) does, while a TOML/JSON/YAML
    `= 1`/`= "yes"` stays **ignored** exactly as at base — the first cut applied the wider set in
    every format, which would have silently flipped the scopes the server enforces
    (`frp-server/src/control/proxy.rs:418-425`; R1's scope finding, now covered by
    `test_legacy_ini_bool_scopes_are_ini_only`). Measured on Go v0.71.0
    (`/private/tmp/frp_0.71.0_darwin_arm64`) and at this head: Go `frpc verify -c` = rc 0,
    `frps verify -c` = rc 0; frp-rs base = rc 1 for both
    (`invalid type: integer \`12345678\``, `invalid type: sequence`), frp-rs now = rc 0 for both.
    Go's numeric token is the *string*: with `auth.token = "12345678"` on Go frps, Go frpc with the
    fixture's `token = 12345678` logs `login to server success` (and `12345679` logs
    `token in login doesn't match …`).
  * **Class 2 — range comma list: fixed in `ini_port_numbers`.** It now accepts the split array
    (each element a single port or a nested range string), which is what the INI reader produces for
    a canonical comma list, and the collector is unchanged otherwise. This arm applies to the
    shape-based legacy `[range:...]` collector in **every** config format, not only `.ini` (base
    dropped such an array with the `WARN … invalid local_port`; a JSON
    `"local_port": [6010, "6011-6012"]` now expands) — pinned by
    `test_legacy_ini_range_port_list_accepts_an_array`, which uses JSON. Measured on Go v0.71.0 with a
    real frps + `GET /api/proxy/tcp`: `6010-6012` -> 3 (`x_0`…`x_2`), `6010-6012,6020` -> 4
    (`x_0`…`x_3`); frp-rs base for the second case = `Proxies: 0` + the WARN, frp-rs now =
    `Proxies: 4`. Go's own `[range:tcp_port]` (`local_port = 6010-6020,6022,6024-6028`, 17 numbers)
    now expands to 17 proxies named `tcp_port_0`…`tcp_port_16`, and `[range:udp_port]` to 11.
  * **Class 3 — role dispatch: fixed after expansion, as Go does.** The range branch reads `role`
    from the template and pushes the generated `{prefix}_{i}` elements to `visitors` when it is
    `visitor` (Go `pkg/config/legacy/client.go:252-285` expands first and dispatches on `role`
    after), and records their indices so the legacy strip pass uses the *visitor* key set — the
    visitor-only keys (`bind_addr`, `bind_port`, `server_name`, `sk`, `server_user`) survive;
    `local_port`/`remote_port` (added by the expansion, not named by Go's visitor struct) are
    dropped like Go's `MapTo` ignores them. Measured: Go frpc with a `6010-6012` `role = visitor`
    template logs `visitor added: [rv_0 rv_1 rv_2]`; frp-rs base = `Proxies: 3 Visitors: 0`, frp-rs
    now = `Proxies: 0 Visitors: 3` with `bind_port = 6000` intact on all three.
  * **Both shipped fixtures pinned end to end.** `frps_legacy_full.ini` is vendored byte-identically
    next to the client one (`cmp` against the v0.71.0 tarball copy), and
    `legacy_ini_go_shipped_frpc_fixture_loads_end_to_end` loads the client file through
    `load_client_config(path, true)` — 43 proxies with the exact names Go frpc v0.71.0 logs in
    `proxy added: […]` and 2 visitors (`p2p_tcp_visitor`, `secret_tcp_visitor`) — while
    `legacy_ini_go_shipped_frps_fixture_loads_end_to_end` loads the server file through
    `load_server_config(path, true)`: `auth.token == "12345678"`,
    `allow_ports == "2000-3000,3001,3003,4000-50000"`, two `[plugin.*]` HTTP plugins. Those counts
    are **config-level** (what Go's loader reports); how many of the 43 a server accepts is
    environment-dependent — measured once on Go v0.71.0 with a vhost-only frps, 38 registered, with
    Go's own frpc log naming the causes (health checks against a dead local `:22`/`:80` for `ssh`
    and `web01`, `open ./server.crt: no such file or directory` on one of the two https plugins and
    `router config conflict` on the other — which of the two loses varies — `subdomain is not
    supported because this feature is not enabled in server` for `web02`, and
    `tcpmux with multiplexer httpconnect not supported` for `tcpmuxhttpconnect`). `frps` has no
    `verify` subcommand in frp-rs (pre-existing CLI divergence, `TODO.md:1632`), so the server file
    is pinned at the same `load_server_config` entry point `frps -c` uses; the client file is also
    pinned through the CLI by `frpc/tests/legacy_ini_fixture.rs` (`frpc verify -c` -> rc 0,
    `Proxies: 43`, `Visitors: 2`, no `skipped` warning).
  * **Trap (a) measured:** numeric and boolean INI fields still parse — `server_port = 7000`,
    `log_max_days = 3`, `pool_count = 5`, `local_port`/`remote_port` as integers, `tcp_mux = no` /
    `OFF` / `yes`, and `health_check_interval_s = 10` -> `10` (test
    `test_legacy_ini_values_are_read_by_target_type`); `server_port = abc` still fails the load.
  * **Trap (b) measured:** the visitor-only keys survive the strip (test
    `test_legacy_ini_range_role_visitor_builds_visitors`) and the two shipped visitor sections keep
    `bind_port` 9000/9001 and `keep_tunnel_open`/`max_retries_an_hour`/`min_retry_interval` (fixture
    test).
  * **Residuals recorded in `docs/config.md`** (not open divergences of this item): Go's
    `Key.Int64()` is `strconv.ParseInt(s, 0, 64)` — base 0 — and the dangerous half is the *silent
    different value*, not the refusal (measured on Go v0.71.0 via the dialled port in frpc's log,
    frp-rs head in brackets): `server_port = 07000` → Go 3584 [7000], `= 010` → Go 8 [10],
    `= 0x10` → Go 16 [refused], `= 08` → not a Go integer, so the field keeps the default 7000
    [8]. Pre-existing (the old inference read base 10 too); matching Go fully would also need its
    non-strict "swallow the parse error, keep the default" behaviour, which a serde field cannot
    express. The other residual is the
    `["a", "b"]` array-literal spelling is an frp-rs extension, so a *string* field given that
    spelling reads the comma-joined elements where Go reads the bracketed text (that spelling is not
    Go syntax — measured: Go gives `['["a.example.com"', '"b.example.com"]']`).
  * Red evidence: with only `ini_port_numbers`' array arm reverted, **three** tests fail — the
    client-fixture end-to-end test (its 17 `tcp_port_*` proxies disappear) and the two range tests
    (`Proxies: 0`); with only the `role` dispatch reverted, the visitor test fails
    (`Proxies: 3 Visitors: 0`); with `deserialize_ini` replaced by `serde_json::from_value` for
    `.ini`, the two fixture tests fail with the base errors. Re-measured after the review round,
    together with three mutants for the review fixes themselves — all six single mutants fail, and
    the tree is restored from git between runs: array arm reverted **3** (client fixture + the two
    range tests), `role_is_visitor = false` **1** (visitor test), `.ini` back on the strict serde
    path **2** (both fixtures), `round_trips` reduced to the TOML renderer **2**
    (`ini_value_text_matches_inference`, `test_legacy_ini_values_are_read_by_target_type` — the
    `10000000000000000000` / `0.0000001` rows), `canonicalize_legacy_ini_bools` called for every
    format **1** (`test_legacy_ini_bool_scopes_are_ini_only` — which goes through the real file
    loader, a gap the first version of that test had: it used the content helpers, which bypass the
    gate, and M5 stayed green until the test was rewritten), and the inference back on `split(',')`
    **1** (`test_legacy_ini_slice_values_use_go_strings_semantics`). `scripts/compat-test.sh` was
    **not** run: the diff is config-load only (no protocol, transport, encryption or proxy path) and the
    script generates no `.ini` config at all, so it cannot reach the wire.

- [x] **A legacy section with an invalid `role` is accepted as a proxy where Go exits 1.** Found
  while closing `:1359` (R1), measured on Go v0.71.0 and frp-rs head. Go dispatches a legacy section
  on `role` after expanding a `[range:...]` template and errors on anything but `server`/`visitor`
  (`pkg/config/legacy/client.go:263-284`, `proxy %s role should be 'server' or 'visitor'`):
  `frpc verify -c` is **rc 1** for both `[x] type = tcp role = serverx …` (`proxy x role should be
  'server' or 'visitor'`) and `[range:x] … role = serverx` (`proxy x_0 role should be …`). frp-rs is
  **rc 0** for both — the explicit shape treats any non-`visitor` role as a proxy (pre-existing), and
  the range shape got the same treatment from this item's role dispatch. Pre-existing and
  net-unchanged for the explicit shape; the range shape is now reachable the same way.
  **Done-when:** refuse a legacy section whose `role` is neither `server` nor `visitor` with Go's
  message and exit code, covering both shapes — which means the legacy collector has to be able to
  fail (`normalize_client_config` currently returns `()`), or record the divergence in
  `docs/config.md` with this measurement.
  Reproducer: `/tmp/lip/f5/role_bad.ini` (range) and `/tmp/lip/f5/role_bad2.ini` (explicit) in the
  `:1359` round's probe directory; `frpc verify -c` on each, Go vs frp-rs.
  **Done:** took the Done-when's second branch — the divergence is recorded in `docs/config.md`
  (§ *A legacy section's `role` is not validated*, `docs/config.md:870-897`), **not fixed**.
  Both sides re-measured in this round, stdout and stderr captured separately and the rc read
  directly. Go: the real v0.71.0 binary `/tmp/frp_0.71.0_darwin_arm64/frpc`
  (sha256 `3ce4ba70ffce7da4026940586c5f3454df50814f4c050d6560efc556b3adef48`, `--version` → `0.71.0`)
  is **rc 1** on both reproducers with the message on **stdout** and **0 B stderr** — explicit
  `proxy x role should be 'server' or 'visitor'` (45 B), range `proxy x_0 role should be 'server' or
  'visitor'` (47 B); this matches the source dispatch at `pkg/config/legacy/client.go:263-284`.
  frp-rs head (`cargo build -p frpc` → `target/debug/frpc`) is **rc 0** on both with **0 B stderr**:
  explicit stdout `Config file /tmp/lip/f5/role_bad2.ini is valid` + `Proxies: 1` (99 B), range
  `Config file /tmp/lip/f5/role_bad.ini is valid` + `Proxies: 3` (98 B). The refusal itself is still
  unimplemented — the legacy collector cannot fail as it stands (`normalize_client_config` returns
  `()`), which is why the item closes by documentation. Ledger effect: **closes 1 item**.

- [x] **`frpc` panics on SIGTERM when more than one visitor shares a `bind_port` (pre-existing;
  now reachable from a `[range:...]` template).** Found by R1 while reviewing `:1359`, reproduced
  here on both the base and head binaries. Three `stcp` visitors with the same `bind_port` (the
  legacy template's shape: `[range:rv] … role = visitor … bind_port = <one port>`) start fine; on
  `SIGTERM` the process panics with
  `fatal: panicked at tokio-1.53.1/src/runtime/task/core.rs:427: JoinHandle polled after completion`
  and exits **101** — in the release profile (`panic = "abort"`) that is a crash, not a clean
  shutdown. Measured (3 runs each, Rust frps + frpc, free ports, children reaped):
  head explicit-3 **3/3**, head range-3 **3/3**, base explicit-3 **3/3**, base range-3 **0/3** —
  base's range shape built *proxies*, not visitors, so `:1359`'s role fix is what makes the range
  shape reach it; the explicit shape predates it. Not caused by `:1359` and not fixed by it.
  **Done-when:** `frpc` shuts down cleanly (rc 0, no `panicked at`) with N ≥ 2 visitors sharing a
  `bind_port`, and a regression test pins it for both the explicit and the range spelling.
  Reproducer: `/tmp/lip/probe6.sh <label> <frpc> <frps> <explicit|range> <runs>` from the `:1359`
  round (it also shows base range-3 at 0/3).
  **Done:** root-caused and fixed in `shutdown_visitor_tasks` (`frp-client/src/service.rs`). That
  function's `join_all` polls every visitor `JoinHandle`; the losers of a shared `bind_port` return
  from `run_visitor_listener` at once (`frp-client/src/visitor.rs:1203-1208`), so `join_all` takes
  their output while the winner sits in `accept()`, and the 500ms timeout's abort branch then
  awaited those already-consumed handles a second time — tokio panics on that (`core.rs:427`). The
  abort branch now snapshots `is_finished()` before aborting and awaits only the handles that were
  still pending, so each handle is polled at most once. Measured with the same probes as above
  (Rust frps + frpc, free ports, children reaped; `leftover` empty every run): explicit-3
  **3/3 panics (rc 101) → 0/5 (rc 0)**, range-3 **3/3 (rc 101) → 0/5 (rc 0)**, explicit-2
  **3/3 → 0/3**. The general precondition is *not* the shared port: it is "≥1 visitor task completed
  before the grace window closed while ≥1 was still parked", proven by a distinct-`bind_port` case
  (two visitors, one port held externally) that also panicked **3/3** before and is **0/3** after;
  that case is pinned by the third regression test. Controls, unchanged by the fix: N=1 visitor
  **0/3 both before and after** (rc 0), N=3 visitors on distinct free ports **0/3 both** (rc 0),
  single visitor whose port is externally held **0/3 both** (rc 0). The "one binds, the rest fail"
  shape Go has is kept: every run still logs exactly 2 `Address already in use` lines, and the
  500ms grace is unchanged (skipping a finished handle can only return sooner).
  Go v0.71.0 parity, stated precisely: on the default TCP transport Go is **killed by SIGTERM**
  (rc **143** 3/3, no panic) because it installs its handler only for kcp/quic
  (`cmd/frpc/sub/root.go:206-209`), while logging the same two
  `start error: listen tcp 127.0.0.1:<port>: bind: address already in use`
  (`client/visitor/visitor_manager.go:132`); with `protocol = kcp` and a Go frps `kcpBindPort` the
  same three-visitor config exits **0** (measured). So frp-rs is strictly better on TCP (clean rc 0
  where Go dies by signal) and equal on kcp; the loser shape matches in both.
  Pinned by `frp-server/tests/visitor_multi_sigterm.rs` (explicit, range, and held-port; each sends
  SIGTERM to the real `frpc` and asserts rc 0, no `panicked at`, and the expected loser count) plus
  the in-process `service::tests::shutdown_visitor_tasks_tolerates_a_completed_handle` and
  `shutdown_visitor_tasks_releases_listeners` (`frp-client/src/service.rs`). Red evidence: the
  binary-level file fails **3/3** against a saved pre-fix `frpc` with the exact panic line (the
  rc-0 assertion is never reached), and the first unit test fails on the pre-fix hunk with
  `panicked at … core.rs:427: JoinHandle polled after completion`.
  Class sweep (nothing else has the "poll to `Ready`, then poll again" shape): the only other
  `join_all` teardown — work-conn, `frp-client/src/service.rs:4032` — drops its handles after a
  timeout instead of re-awaiting them; the `timeout(&mut handle)` sites only ever poll again after a
  *Pending* poll (ssh_gateway's `terminate_ssh_session`, the control writer); the `select!` arm on
  `&mut session_task` (`frp-server/src/ssh_gateway.rs:4326`) consumes its one `Ready` and the `None`
  branch is the only path that polls further; and every `JoinSet` drain uses
  `join_next`/`try_join_next`, which remove the completed task from the set, so no task is polled
  twice. Details and per-site reasons: the PR body.

- [x] **`frpc reload` / `frpc status` silently ignore a config that fails to load, and talk to
  `127.0.0.1:7400` instead.** `resolve_admin_connection` (`frpc/src/main.rs:29`) loads the
  config with `load_client_config(path, true)` at `:46` and, on **any** error, falls through to
  the `127.0.0.1:7400` default at `:54-59` with the error discarded (the `if let Ok(cfg)` drops
  it). Call sites: `run_reload` (`:623`) and `run_status` (`:641`). Measured with identical
  config text — a valid config plus one unknown top-level key, with an admin server actually
  listening on the configured `webServer.port`:
  * Go v0.71.0: `frpc reload -c <config>` and `frpc status -c <config>` each print
    `json: unknown field "notAKnownFrpKey"` and exit **1** — no address is ever contacted.
  * frp-rs: both silently retarget `127.0.0.1:7400`
    (`reload failed: connect 127.0.0.1:7400: Connection refused (os error 61)` /
    `status query failed: connect 127.0.0.1:7400: Connection refused (os error 61)`), exit 1,
    and never mention the config error — so a different admin server on 7400 would be driven
    instead, and the user is not told their config did not load.
  `strict = true` here is **Go-faithful** (Go's `frpc reload --help`: "strict config parsing
  mode, unknown fields will cause an errors (default true)"), so the divergence is the silent
  fallback, not the strictness. The daemon's own startup load is strict in both Go and frp-rs
  (measured), so the fallback is reachable whenever the on-disk config changes after the daemon
  has started — exactly the situation `frpc reload` is used in.
  **Done-when:** propagate the load error (Go's exit 1 plus the parse message) instead of
  falling back, or warn and fall back only when the config genuinely has no `[web_server]`
  section, with both cases pinned.
  Done (branch `fix/frpc-cli-config-error`, based on `main` @ `9c1b291`): the first branch of the
  done-when. `resolve_admin_connection` (`frpc/src/main.rs`) now returns
  `Result<AdminConnection, AdminResolveError>` and **always** loads and validates the config when
  `-c` is given, so a load error is propagated instead of dropped. Both refusals go to **stdout**
  via `println!` and exit **1**, matching Go's `fmt.Println` / `os.Exit(1)`
  (`cmd/frpc/sub/admin.go:56-71`, tag `v0.71.0`, refetched during this work):
  `if err != nil { fmt.Println(err); os.Exit(1) }`, then
  `if cfg.WebServer.Port <= 0 { fmt.Println("web server port should be set if you want to use
  this feature"); os.Exit(1) }`. `--strict-config` / `--strict_config` was added to `StatusArgs`
  and is passed to the load (Go inherits it as a persistent rootCmd flag; before, frp-rs answered
  `Error: --strict-config is not expected in this context`). The frp-rs-only
  `--admin-addr` / `--admin-port` / `--admin-user` / `--admin-pwd` flags carry no `.help()` text
  (they do appear in `--help` output, as bare names). **Before this branch** no live doc mentioned
  them: `--admin-addr` appeared nowhere and `--admin-port` only in the archived
  `docs/archive/specs/2026-07-12-error-messages-cli-polish-design.md:183`; this branch adds both
  flags to `docs/deployment.md` § client admin, so they are now documented. They override the
  address **after** a successful load, so `reload --admin-addr X --admin-port Y -c bad.toml`
  reports the config error instead of silently using the flags. That is the deliberate behaviour
  change of this item. The pre-existing rule that the override needs **both** flags is unchanged,
  and an explicit `--admin-port 0` is refused with Go's web-server message rather than treated as
  "not supplied" (falling back to the config port would silently ignore an explicit flag, and
  `connect 127.0.0.1:0` is never valid). The pre-existing connection-error stream and message
  (`reload failed: …` / `status query failed: …` on **stderr**; Go's equivalent is a
  `Get "http://…"` error on **stdout**) is also unchanged — a separate divergence, recorded here
  rather than fixed.

  Measured before → after, frp-rs `target/debug/frpc` built with `cargo build -p frpc`; every row
  re-measured against Go v0.71.0 `/private/tmp/frp_0.71.0_darwin_arm64/frpc` (all reproduced, all
  stdout + exit 1 on the Go side, no exceptions found):

  | case | frp-rs before | frp-rs after |
  |---|---|---|
  | `reload -c badcli.toml` (unknown key) | stderr `reload failed: connect 127.0.0.1:7400: Connection refused (os error 61)`, exit 1 | stdout `unknown field "notAKnownFrpKey" in config file …`, exit 1 |
  | `status -c badcli.toml` | stderr `status query failed: connect 127.0.0.1:7400: …`, exit 1 | same stdout parse error, exit 1 |
  | `reload -c noweb.toml` (no `[webServer]`) | stderr `reload failed: connect 127.0.0.1:0: Can't assign requested address (os error 49)`, exit 1 | stdout `web server port should be set if you want to use this feature`, exit 1 |
  | `reload -c goodcli.toml` (`port = 7499`) | stderr `connect 127.0.0.1:7499: …` | unchanged (`127.0.0.1:7499` still the address) |
  | `reload -c nope.toml` (missing) | silently `127.0.0.1:7400` | stdout `/tmp/probe/nope.toml: failed to read config file: No such file or directory (os error 2)`, exit 1 |
  | `reload --admin-addr 127.0.0.1 --admin-port 7499 -c badcli.toml` | used `127.0.0.1:7499`, config error swallowed | stdout parse error, exit 1, nothing contacted |
  | `status --strict-config=false -c badcli.toml` | `Error: --strict-config is not expected in this context`, exit 1 | flag accepted; with a real port the unknown key is tolerated and the port is dialed |

  Go's parse message wording differs (`json: unknown field "notAKnownFrpKey"` vs frp-rs's
  `unknown field "notAKnownFrpKey" in config file <path>`), and so does the missing-file wording —
  the config-layer error text, not the CLI's; the stream and exit code now match. Two divergences
  are **left in place** and recorded, not fixed: with no `-c` at all Go defaults to `./frpc.ini`
  and exits 1 (`open ./frpc.ini: no such file or directory`, measured) while frp-rs keeps `-c`
  optional and still uses `127.0.0.1:7400`; and the daemon start path uses `EXIT_CONFIG = 2` where
  Go exits 1 (now its own item below). *(The second of those two is closed since — the daemon
  start path exits 1 as of the `TODO.md:1503` item below, measured at head; this sentence records
  the state at this item's merge, not at head.)*

  Pinned by `frpc/tests/admin_cli.rs` (14 tests; `#![cfg(feature = "full")]`-gated because the
  `frpc` bin has `required-features = ["full"]`, so `cargo test -p frpc --no-default-features`
  compiles it to 0 tests) plus 8 unit tests in `frpc/src/main.rs` (the four fallback assertions
  rewritten, two added). Refusal cases bind a `TcpListener` on an ephemeral port, put it in
  `webServer.port`, and assert **0** connections arrived after the child exits; the
  `--strict-config=false` cases assert the connection **does** arrive (count 1). Falsified to prove
  the oracle is live (re-measured after review, same mutation): with the config-branch port-0
  guard disabled (`if false && port == 0`) and the load made lenient
  (`load_client_config(path, false)`), **6 of the 14** integration tests fail
  (`8 passed; 6 failed`, exit 101) — **3 by hanging on a real connection** the oracle was holding
  (`frpc/tests/admin_cli.rs:125`, "did not exit within 5s"):
  `reload_load_error_…`, `status_load_error_…` and
  `reload_bad_config_with_admin_flags_still_reports_the_config_error`; and **3 on the message
  assertion** (`left: ""` vs Go's string) at `:296` `reload_port_zero_…`, `:318`
  `status_port_zero_…` and `:350` `reload_admin_port_zero_override_…`. The `frpc` bin unit target
  stayed `8 passed; 0 failed` for that mutation; disabling the no-config-branch guard as well
  additionally reddens the bin unit test
  `tests::test_resolve_admin_connection_explicit_port_zero_is_rejected` (`7 passed; 1 failed`),
  which is not one of the 14. CI:
  `Run frpc CLI tests (admin address resolution)` / `cargo test -p frpc` in the `Tests (unit)`
  lane (`.github/workflows/ci.yml`) — no lane ran `-p frpc` before, so this also executes the unit
  tests that previously never ran. `cargo test -p frpc` 22 passed / 0 failed (8 unit + 14
  integration; 1.6-2.7 s wall warm on three runs);
  `--no-default-features` compiles clean with the gate. Docs: a paragraph in
  `docs/deployment.md` § client admin states the load-then-refuse behaviour, the required
  `web_server.port`, and that the `--admin-*` flags are an frp-rs extension applied after a
  successful load. Merged as PR **#367**, squash-merged to `main` as `f8f127f` (branch
  `fix/frpc-cli-config-error`).
- [x] **`scripts/repo-health.sh`'s path-reference scanner walked gitignored directories, so the
  local mirror of the `health` job failed whenever any worktree existed.** The scanner used
  `os.walk('.')` from the repo root and pruned only `.git` and `target`
  (`scripts/repo-health.sh:692-693` pre-fix), so it descended into `.worktrees/` and
  `.superpowers/` — both gitignored (`.gitignore:17`, `:20`) and absent from a clean checkout.
  **The reported total was never a stable number** — it tracked how many nested worktrees were on
  disk and how much point-in-time prose each carried. Those three totals are pre-fix readings and
  are not reproducible from the fixed script: the item's author measured 4139 and then **FAIL
  4140** (4136 under `.worktrees/*` + 4 under `.superpowers/sdd/*`) with 20 nested worktrees at
  12:57Z, and the coordinator measured `FAIL 3919` (3915 + 4) earlier still; each nested worktree
  contributed **204-221** refs. The stable facts are the mechanism, the per-worktree contribution,
  and the 4 refs under `.superpowers/sdd/*` (absent paths quoted by that directory's 2026-07 task
  briefs and perf-review report — `issue-185-perf-review-report.md`, self-dated 2026-07-27, and
  `task-4-brief.md` of 2026-07-12; neither has ever been tracked, while `task-4-report.md` (added
  `1dba77a`, removed `8cab62e`) and `progress.md` (added `c46dd50`, removed `ebec91b`) were once
  tracked there and have since been untracked). Two root causes compounded: (a) nested worktrees
  were scanned at all; (b) the exclusions are root-anchored — `p in SKIP_FILES` and
  `p.startswith(SKIP_DIRS)` (`:598-599`, `:699` pre-fix) — so a nested `.worktrees/<x>/TODO.md`,
  `CHANGELOG.md` or `docs/archive/…` was **not** skipped even though the root copy is a deliberate
  point-in-time exclusion, and those files are exactly where the intentional absent paths live. The
  `health` CI job (clean checkout) and an isolated worktree with no nested `.worktrees/` both passed
  with `RESULT: invariants hold` — so a local gate that was red only because the mandated workflow
  was in use was a false positive, and it trained authors to ignore the script (the same trap the
  archive/SKIP list was added to avoid).
  **Done-when:** drive the scan from `git ls-files` (keeping the existing `find` fallback for a
  `.git`-less tree) or prune gitignored paths before walking, falsified by both cases: with a
  nested worktree under `.worktrees/` and a `.superpowers/sdd/` file present, the script exits 0
  and reports the same path counts as the clean checkout; and a genuinely stale backticked path
  added to a tracked file still exits 1. No sha.

  Done (branch `fix/repo-health-tracked-scan`, based on `main` @ `f8f127f`): the first branch of
  the done-when — the file list now comes from the git index. A new `tracked_files()` runs
  `git ls-files -z --full-name --cached` (python3 stdlib `subprocess`, no new dependency). The
  item's parenthetical calls this the "existing `find` fallback"; the path scanner's fallback was
  actually `os.walk` — the `find` one belongs to the toolchain-pin check (pre-fix
  `scripts/repo-health.sh:284`) — and `walk_files()` keeps that `os.walk` (pruning `.git` and
  `target` at any depth, a rule `wanted()` now applies to index paths too so both sources keep
  identical verdicts). `git ls-files -z` is preferred over pruning gitignored directories by hand:
  the index is the file set a clean checkout *tracks* — not *exactly* what it contains, because
  local index state is visible too (an intent-to-add entry is scanned; an unmerged path is listed
  once per stage and is collapsed by path) — so there is no re-implementation of `.gitignore`
  matching, it is one fast call, and it fixes the root-anchoring bug (b) for free. The walk is used
  **only** when there is no `.git` entry at all (not even a dangling symlink); if any `.git` entry
  is present but the index cannot be read the path scan exits 3 instead of silently walking (a walk
  would scan the gitignored state this gate exists to avoid; the wrapping run is red at exit 1), so a
  sparse checkout, or any worktree missing a tracked path, is not certified. `git ls-files` also runs
  with `GIT_DIR`/`GIT_WORK_TREE`/`GIT_INDEX_FILE`/`GIT_COMMON_DIR`/`GIT_OBJECT_DIRECTORY` and any
  `GIT_TRACE*` stripped from the environment, so the list comes from the repository git resolves for
  the script's directory, not from an inherited environment: `git rev-parse --show-toplevel` must
  equal the working directory (`realpath` on both sides) or the path scan exits 3. Submodule contents
  are never scanned —
  the index lists only the gitlink. The index supplies the file *list*; content is read from the
  **worktree**, so a tracked file edited locally is gated at its current content. Paths are
  NUL-split and decoded with `surrogateescape`, so spaces, newlines and non-ASCII cannot be
  mis-parsed or silently dropped. The summary line format and every classification rule (`ROOTS`,
  `normalize`, `classify`, `cargo_features`, `SKIP_DIRS`/`SKIP_FILES`) are unchanged, so no count
  changed meaning. Hits are sorted as `(path, line number)` pairs before printing, so hit *order* is
  path order then line number instead of the old depth-first walk order (per-directory filename
  sort); the counts and the hit *set* are unchanged. Measured in the worktree,
  macOS arm64, warm cache (2.4-2.7 s):
  * clean (no `.worktrees/`, no `.superpowers/`): exit **0**, `ok    272 repo path references
    resolve (file-relative, crate root, then repo root)`, `info  skipped 227 locator-less bare
    ref(s) and 57 locator-less shorthand(s) (no recoverable base); 7 `crate/feature` span(s)`,
    2.4 s wall.
  * case (a) nested worktree + ignored probe: `git worktree add .worktrees/scan-falsify -b
    probe/scan-falsify` (ignored — `git check-ignore -v .worktrees/scan-falsify` →
    `.gitignore:17:.worktrees/`) plus `.superpowers/sdd/probe.md` naming
    `frp-core/src/this-file-does-not-exist.rs` (`git check-ignore` → `.gitignore:20`). The
    **pre-fix** script on that tree exited **1**, `FAIL  222 path reference(s) do not resolve`
    (the nested worktree was at `f8f127f` and contributed 221 refs, the probe 1; with the nested
    worktree at `c75b3a3` the same probe reads `FAIL 224`). The fixed script exits **0** with the
    same count line as the clean run above (no hits in either run: ok 272 / feature 7 / shorthand
    57 / bare 227), 2.4 s wall. Probe worktree removed with `git worktree remove --force` + `git
    worktree prune` and the `probe/scan-falsify` branch deleted.
  * case (b) stale ref in a tracked file: appending a `//` comment naming
    `frp-core/src/this-file-does-not-exist.rs` to tracked `frp-core/src/base64.rs` gave exit **1**
    with `stale: frp-core/src/base64.rs:165` naming that path, and `FAIL  1 path reference(s) do
    not resolve from the referencing file`; `git checkout -- frp-core/src/base64.rs` restored
    exit 0 / `ok 272`. This also pins the index-vs-worktree decision: the file was
    unmodified in the index and the local edit was still caught.
  * fallback: `git archive HEAD | tar -x -C /tmp/rh-nogit`, run from there → exit **0**, `ok 272`
    (the `os.path.lexists('.git')` check returns `None`, so `walk_files()` scans the tarball). A tree
    that *has* `.git` but whose index cannot be read does **not** fall back: a corrupt
    `.git/index` (with `.worktrees/fake/TODO.md` and `.superpowers/sdd/probe.md` present) gives
    exit **1** with `scan error: .git is present but the file list could not be read from the index
    (git ls-files exited 128: fatal: .git/index: index file smaller than expected) — refusing to
    fall back to a filesystem walk that would scan gitignored state; refs not certified`, zero
    `stale:` lines and `FAIL  path-reference scan produced no result (exit 3)`; a `PATH` with no
    `git` at all while `.git` exists gives the same exit-3 shape with `git could not be run:
    [Errno 2] No such file or directory: 'git'`.
  * fail-loud floors, falsified in throwaway copies under `/tmp` (never in the repo): forcing the
    index list to `[]` → `scan error: git ls-files listed no scannable .md/.rs file — refusing to
    report "no stale refs"`; keeping the real list but raising the floor → `scan error:
    implausibly small scan from git ls-files (<N> file(s), <N> span(s); floor 1000000000/100) —
    refs not certified` (the probe patches `MIN_FILES = 10**9`; the message interpolates `%d`, so it
    prints the literal `1000000000`); suppressing the span loop → `scan error: git ls-files examined
    <N> file(s) / 0 span(s) — refs not certified`. The `<N>`s are elided on purpose: the span count
    drifts with any doc edit (readings of this same probe were 12207 at `c75b3a3`, 12210 at
    `80623e3` and 12224 at `526b93e`), so a literal here would be stale on arrival. All three exit
    **3** and surface as `FAIL  path-reference scan produced no result (exit 3) — refs not
    certified` with `RESULT: FAILURES above`. The floors
    apply to the walk source as well, so a partial tarball with fewer than 50 scannable files also
    exits 3 rather than passing. A tracked path
    that cannot be opened (deleted in the worktree, or a mode-160000 gitlink named `*.md`) prints
    `read error: <path>: No such file or directory` and exits 3, no traceback; a gitlink named
    anything else is filtered out by the extension test before it is opened. `git ls-files -s | awk
    '$1==160000'` is empty in this repo today, and `git ls-files` reports 0 paths with spaces or
    non-ASCII, so neither case is live — they are handled and were probed synthetically as above.
  * fix rounds after review (same branch, further commits, none of the reviewed commits amended):
    the fail-closed hole where *any* git failure fell back to the walk silently is closed, as
    above. The `.git` probe is `os.path.lexists`: a dangling `.git` symlink, where `os.path.exists`
    is False but `lexists` is True, now fails the gate instead of walking (a `.git` gitfile whose
    gitdir is gone has `exists` True and already failed closed at `80623e3`). Verdict parity
    for the walk's `target` prune is restored — a synthetic tracked `sub/target/t.md` carrying a
    dead ref is skipped while `sub/x.md` carrying the same dead ref is reported, matching the
    pre-fix script; the interim commit reported both. Unmerged index entries are collapsed by path
    (git lists an unmerged path once per stage; `--deduplicate` exists on git 2.50.1 here and
    reduces 3 → 1, but the collapse is done in python so no git-version floor is introduced) —
    without it the interim commit counted the same hit three times.
    `GIT_DIR`/`GIT_WORK_TREE`/`GIT_INDEX_FILE`/`GIT_COMMON_DIR` are stripped from the environment
    git runs in, so pointing `GIT_INDEX_FILE` at another repo's index no longer certifies this tree
    against a foreign file list (measured: before the fix `ok 272` / exit 0 while the tree's own
    tracked `zdead.md` held a dead ref; after, exit 1 naming `zdead.md`). `subprocess.run` gets a
    60 s timeout and `SubprocessError` is caught, so a hung git exits 3 with a message instead of
    stalling or tracebacking (`TimeoutExpired` is not an `OSError`). Hit order: with hits present
    the pre-fix walk emits `zz.md`, `a/x.md`, `a/b/y.md` (depth-first walk, per-directory filename
    sort) while the index emits `a/b/y.md`, `a/x.md`, `zz.md`; hits are now sorted as `(path, line
    number)` pairs, so `multi.md:1` prints before `multi.md:10`. The earlier "byte-identical output"
    claim in this item and in the first commit's message is not guaranteed once there are hits (a
    single hit is still identical); this paragraph is the correction (the reviewed commits are not
    amended).
  * scope: the scan is now **tracked-files-only**, so an untracked local file naming a dead path is
    no longer gated. Deliberate: the CI `health` job runs on a clean checkout where untracked ==
    absent, so the gate's CI meaning is unchanged. Because any `.git` entry whose index cannot be
    read exits 3, a sparse checkout, or any worktree missing a tracked path, is not certified by
    this gate either — that path is a read error, not a skip (a partial clone
    `--filter=blob:none` materialises every tracked file and does pass). Stated in the
    `scripts/repo-health.sh` coverage comment, `docs/developing.md` § Repository Invariants and
    `CLAUDE.md:209`. No Rust file touched; `bash -n scripts/repo-health.sh` clean and the path-scan
    heredoc `compile()`s.
- [x] **`frpc` has no `stop` subcommand and no `--api-timeout`, so its admin-command surface is
  short of Go v0.71.0.** Go's `cmd/frpc/sub/admin.go:34-50` (tag `v0.71.0`, fetched during this
  work) registers **three** commands — `reload`, `status`, **`stop`** — and gives each
  `cmd.Flags().DurationVar(&adminAPITimeout, "api-timeout", adminAPITimeout, "Timeout for admin
  API calls")` with a 30 s default; `frpc reload --help` on the Go binary prints exactly
  `--api-timeout duration … (default 30s)` and no `--admin-addr`-style flags. frp-rs's CLI
  exposes only `reload` and `status` (`frp-core/src/cli.rs`) and neither accepts `--api-timeout`.
  The server side is already there: `POST /api/stop` is routed (`frp-client/src/admin.rs:882`,
  handler `:548`) and listed in the `docs/deployment.md` client-endpoints table, so only the CLI
  wrapper is missing; `--api-timeout` has no frp-rs equivalent at all. (Found while fixing
  `frpc reload`/`status`; deliberately not implemented there.)
  **Done-when:** add `stop` (POST `/api/stop`, print `stop success` on 200 as Go's `StopHandler`
  does) and `--api-timeout` (default 30 s, applied to the admin HTTP call) to `frpc`, each
  pinned by a CLI test in the style of `frpc/tests/admin_cli.rs`; or record in the feature-surface
  policy why frp-rs deliberately exposes two of Go's three admin commands. No sha.
  Done (branch `feat/frpc-admin-stop`, based on `main` @ `71a4baf`): both halves of the
  done-when. `FrpcCmd::Stop(StopArgs)` mirrors `StatusArgs` minus `--json`; `stop_cmd()` carries
  Go's short text `Stop the running frpc` (`cmd/frpc/sub/admin.go:42`); `run_stop`
  (`frpc/src/main.rs`) resolves the connection exactly like `run_reload` (load errors and a port-0
  `[webServer]` on stdout + exit 1, no connection) and then POSTs `/api/stop` with an empty body,
  printing `stop success` on 200 and `stop failed: …` on stderr + exit 1 otherwise. `--api-timeout`
  is Go's per-subcommand flag (`cmd/frpc/sub/admin.go:47`, default 30 s) and now bounds the whole
  admin HTTP call — connect, write, read — via `tokio::time::timeout`, with the zero deadline
  checked *before* dialing so a refused port cannot win the race; `admin_get`/`admin_post_json`
  previously had no timeout at all. The value parser is a hand-written `time.ParseDuration`
  (units `ns us µs μs ms s m h`, decimal fractions, compound groups, optional sign, bare `0`;
  overflow past `i64::MAX` ns rejected; a negative value becomes `Duration::ZERO` because a
  `Duration` cannot be negative and the only consumer is a deadline) — `Duration: FromStr` is not
  implemented on the pinned toolchain (verified: `rustc 1.98.1`, `error[E0277]: the trait bound
  Duration: FromStr is not satisfied`), and the dependency policy forbids a crate for it.

  Measured here against Go v0.71.0 `/private/tmp/frp_0.71.0_darwin_arm64/frpc`: `frpc --help` lists
  `stop  Stop the running frpc`; `frpc stop --api-timeout=1s -c <cfg, webServer.port = 1>` → stdout
  `Post "http://127.0.0.1:1/api/stop": dial tcp 127.0.0.1:1: connect: connection refused`, exit 1;
  `--api-timeout=0`/`=0s`/`=-1s` → `context deadline exceeded` on stdout, exit 1, i.e. the expired
  context wins over the refused port; rejected values (`1`, `abc`, `1d`, `1S`, `1Ms`, `1e3s`, `Inf`,
  `2562048h`, a 21-digit hour count) → stderr `Error: invalid argument …`, exit 1;
  `frpc verify --api-timeout=1s` → `Error: unknown flag: --api-timeout`, exit 1, and
  `frpc verify --api_timeout=1s` → `Error: unknown flag: --api_timeout` (Go echoes the typed
  spelling), exit 1. A raw-socket capture of the Go `frpc stop` request shows
  `POST /api/stop HTTP/1.1`, `Content-Length: 0`, no body bytes; the frp-rs request matches on
  method, path, `Content-Length: 0` and an empty body (asserted by the mock in
  `frpc/tests/admin_cli.rs`), while the other headers differ. The input class where frp-rs is
  *stricter* is a group sum that passes `2^64`: Go accumulates in a `uint64`, so the running total
  wraps, and Go accepts the input whenever the wrapped total still survives its range checks (the
  last is `d > 1<<63-1`), while frp-rs rejects the first sum that leaves the `uint64` range with
  `time: invalid duration` (checked arithmetic, never a panic). Re-measured on both binaries:
  `9223372036854775808ns9223372036854775808ns`, `9223372036854775808ns` ×4 and
  `9223372036854775.808us9223372036854775.808us` are accepted by Go (wrapped total 0 ns →
  `context deadline exceeded`) and rejected by frp-rs, while `9223372036854775808ns` ×3 is rejected
  by **both** (wrapped total 2^63, so Go's final check fails) — "sum ≥ 2^64" is a superset of the
  divergence class. The two-group case is pinned in `frp-core/src/cli.rs`. The counts come from
  **Reviewer 2's round-2 differential**: 19,612 candidates, 1,564 divergences, all
  Go-accepts/frp-rs-rejects, 0 the other way, 0 panics. On reject-path wording frp-rs matches Go
  only for ASCII: `1d` gives the same inner `time: unknown unit "d" in duration "1d"` on both, while
  `1µ` has Go print `unknown unit "\xc2\xb5"` and frp-rs print `unknown unit "µ"` (measured).
  **The brief this work came from
  claimed Go does not accept the underscore spelling; that is wrong** —
  `frpc stop --api_timeout=abc` errors on `--api-timeout`, so the alias reaches the registered
  flag: `Execute()` installs `config.WordSepNormalizeFunc` globally
  (`rootCmd.SetGlobalNormalizationFunc`, `cmd/frpc/sub/root.go` @ v0.71.0). frp-rs's
  `--api_timeout` is therefore Go parity, not an extension, and `docs/deployment.md` says so.
  (`--admin_addr` is still `unknown flag` in Go because no such flag exists — the `--admin-*`
  frp-rs flags remain extensions.)

  Timeout test, red then green: the pre-fix hang is real — `target/debug/frpc` from `main` (no
  `stop`; `frpc --help` lists 11 commands, `frpc status --help` has no `--api-timeout`) run as
  `frpc status -c <cfg pointing at a listener that accepts and holds the socket>` did not exit
  within 8 s. With `with_admin_timeout` temporarily reduced to a bare `call.await`, the new
  `api_timeout_bounds_a_black_hole_admin_listener_for_each_subcommand` fails:
  `frpc ["reload", "--api-timeout", "1s", …] did not exit within 5s`; with the deadline restored it
  passes for `reload`, `status` and `stop`, and the whole file is 23 passed / 0 failed. End-to-end
  with the real daemon (`cargo build -p frpc --features admin`; `frps` + `frpc` with
  `[webServer] port = 27411`): `frpc stop -c frpc.toml` → stdout `stop success`, stderr empty,
  exit 0; the daemon logged `Stop requested, shutting down` then `frpc shutting down` and exited 0,
  and 27411 was no longer listening — so the CLI stops the client, it does not merely see a 200.
  Unit tests live in `frp-core/src/cli.rs` (default 30 s, the grammar's accepted and rejected
  values, `--api-timeout` absent from `run`/`verify`/single-proxy commands, the underscore alias,
  and `Stop the running frpc` in the help). Carriers corrected in the same branch: the stale
  `frpc CLI — run mode + 9 subcommands matching Go frp v0.69.1` comment in `frp-core/src/cli.rs`
  (the tree had 11 non-run subcommands before this change, 12 after; the comment now names them),
  the `docs/deployment.md` client-admin paragraph, and `CHANGELOG.md`.
- [x] **The `frpc` daemon start path exits 2 where Go exits 1 on the same bad config, and prints a
  tracing line instead of Go's bare parse error.** Measured with identical config text (a valid
  config plus one unknown top-level key), both on **stdout**:
  * Go v0.71.0 `frpc -c badcli.toml` → `json: unknown field "notAKnownFrpKey"`, exit **1**.
  * frp-rs `target/debug/frpc -c badcli.toml` → an ANSI-coloured tracing line
    `ERROR frpc: Failed to load config: unknown field "notAKnownFrpKey" in config file …`,
    exit **2** (`EXIT_CONFIG`, `frp-core/src/lib.rs:193` pre-fix — "bad config file, unknown field,
    invalid value"; that constant's *documentation* now states the live contract, and the `2` in
    this bullet is the pre-fix value this item was filed against, not a head value). Part of what
    was billed as frp-rs's 1-4 CLI exit scheme, which no live doc stated: the only
    prose then was that constant's comment and three archived documents that **state** the scheme —
    `docs/archive/plans/2026-07-12-error-messages-phase-b.md`,
    `docs/archive/plans/2026-07-12-phase-a-errors.md`, and
    `docs/archive/specs/2026-07-12-error-messages-cli-polish-design.md` (const block
    `:83-88`, variant table `:168-173`). A fourth archived document mentions a constant
    without stating the scheme
    (`docs/archive/plans/2026-07-12-profiling-infrastructure.md:436` calls `EXIT_RUNTIME` in a
    snippet), so this is "the three that state it", not a proven-exhaustive list.
  The gap is inside frp-rs, not only against Go: after this branch's `frpc reload`/`status`
  change the two frpc CLI paths disagree — the admin subcommands now exit **1** for a load
  error, exactly as Go does, while the daemon path exits 2. Pre-existing; deliberately not
  changed in that branch.
  **Done-when:** either match Go's exit 1 on the daemon CLI path while keeping the richer
  per-class scheme for whatever it is documented to distinguish, or state in a live doc
  (`docs/developing.md` or `CLAUDE.md`) that `2` is a deliberate frp-rs extension and why —
  with the exit code pinned by a test on both paths (`frpc -c bad.toml` and the admin
  subcommands) so the next change cannot silently re-diverge them. No sha.
  **Done — took the first branch (match Go's 1), measurement below, no sha.**
  * **Go v0.71.0 darwin/arm64, re-measured by the author**: `frpc -c bad.toml` → rc **1**,
    stdout `json: unknown field "notAKnownFrpKey"`; `frpc verify -c bad.toml` → rc **1**,
    same first line; `frps -c badfrps.toml` → rc **1**, same first line. Same configs
    (`notAKnownFrpKey = 1` added to a valid config). The wider surface is also all-1:
    missing file, `-c <directory>`, unparsable field, unknown key inside `[[proxies]]`,
    `--strict-config=foo`, and `reload`/`status`/`stop`; `verify -c <good>` is 0.
  * **frp-rs on real built binaries (`cargo build -p frpc -p frps`)** — before →
    after: `frpc -c bad.toml` **2 → 1**; `frpc verify -c bad.toml` **2 → 1**;
    `frps -c badfrps.toml` **2 → 1**. Same for `-c <missing>`, `-c <dir>`,
    `badport.toml`/`badportfrps.toml` (all 2 → 1). `reload`/`status`/`stop` were already 1
    and stay 1. `frpc -c empty.toml` is a *runtime* stop, not a config failure, and the exit
    code matches: **Go rc 1 at 10.04 s, frp-rs rc 1 at 30.07 s** (re-measured with a 90 s
    bound; an earlier 12 s bound killed the frp-rs child and reported 137 — that reading was
    the harness, not the program). Those durations are the *peer's*: the default config dials
    `127.0.0.1:7000`, which macOS Control Center accepts and never answers; against a port
    that genuinely refuses, both return 1 in ~0.02 s.
  * **A test that goes red without the fix, checked both ways**: reverting the daemon site
    to `EXIT_CONFIG` fails `daemon_bad_config_exits_1_and_names_the_unknown_field`
    (`left: Some(2), right: Some(1)`), and reverting the two `verify` sites fails
    `verify_bad_config_exits_1_and_names_the_unknown_field` and
    `verify_missing_config_exits_1`.
  * **The live doc now states the scheme**: `docs/developing.md` § CLI exit codes — the
    measured Go/frp-rs table, the `--config-dir` divergence, and the `3`/`4` residue.
    `frp-core/src/lib.rs`'s constants carry the same statement at the definition site, and
    the now-uncalled `Error::exit_code()` (which mapped `Config → EXIT_CONFIG` and `Io
    AddrInUse/PermissionDenied → EXIT_BIND` for no caller) was deleted; `EXIT_CONFIG` now
    covers exactly the six `--config-dir` refusal sites (three in `frpc/src/main.rs`, three in
    `frps/src/main.rs`) and nothing else.
  * **Pinned by tests that run the real binaries** (new files, real `CARGO_BIN_EXE_*`):
    `frpc/tests/cli_exit_codes.rs` — `daemon_bad_config_exits_1_and_names_the_unknown_field`,
    `verify_bad_config_exits_1_and_names_the_unknown_field`, `verify_missing_config_exits_1`,
    `verify_good_config_exits_0` (positive control),
    `config_dir_refusals_exit_2_where_go_exits_0` (the divergence, pinned),
    `unresolvable_token_source_exits_3_where_go_exits_1` (the `EXIT_AUTH` pin: Go 1,
    frp-rs 3), `malformed_store_file_exits_4_where_go_exits_1` (the `EXIT_BIND` pin: Go 1,
    frp-rs 4; **renamed** by the later typed-classification change to
    `malformed_store_file_exits_4_regardless_of_the_file_name` — the same pin plus the two-name
    flip control; the name in this line is the one this item landed with), plus
    `tiny::tiny_bad_config_exits_1_like_go` and
    `tiny::tiny_verify_bad_config_exits_1_like_go` under `--features tiny`; and
    `frps/tests/cli_exit_codes.rs` — `bad_config_exits_1_and_names_the_unknown_field`,
    `missing_config_exits_1`, `good_config_starts_and_exits_0_on_sigterm`,
    `config_dir_extension_refuses_nonexistent_dir_with_2`. The admin-side pin already
    existed: `frpc/tests/admin_cli.rs` (23 tests, `reload`/`status`/`stop` load errors
    assert exit 1). Measured: `cargo test -p frpc` 23 + 7 passed, `cargo test -p frps`
    4 passed, `cargo test -p frpc --no-default-features --features tiny --test
    cli_exit_codes` 9 passed, 0 failed.
  * **Executing lanes**: no lane ran a `cargo test` target of the `frps` package, and none
    executed the `tiny` CLI binary, when this item landed — the tier lane only
    `cargo check`ed and the `--lib`/clippy lanes cannot execute either. `.github/workflows/ci.yml`
    gained `Run frps CLI tests (config-failure exit codes)` (`cargo test -p frps`) and
    `Run frpc's CLI exit-code tests under tiny` (`cargo test -p frpc --no-default-features
    --features tiny --test cli_exit_codes`) in the same branch.
  * **Carriers updated**: `CHANGELOG.md` (new first `### Changed` entry — user-visible
    exit-code change), `docs/developing.md` (new § CLI exit codes), `frp-core/src/lib.rs`,
    `frpc/src/main.rs`, `frps/src/main.rs`.
  * **Divergence kept, deliberately**: `frpc --config-dir` with a nonexistent, empty or
    unparsable config exits **2** where Go exits **0** (Go prints `frpc service error for
    config file [...]` and reports success). Exiting 0 for a config that was never loaded
    is a silent success frp-rs does not adopt; the trade is stated in the live doc and the
    behaviour is pinned by a test rather than left to drift. `frps --config-dir` is an
    frp-rs extension flag (Go: `unknown flag: --config-dir`, rc 1).
  * **Still open, recorded rather than claimed**: (a) the output/stream shape — frp-rs
    prints an ANSI tracing line on stdout where Go prints a bare parse error, and `verify`
    prints its refusal on stderr where Go uses stdout (new item below); (b) the `3`/`4`
    codes (new item below); (c) `frpc verify -c <config whose [[proxies]] block has an
    unknown key>` returns 0 while Go exits 1 — tracked by the pre-existing strict-mode
    proxy/visitor-array item at `TODO.md:1168` (recorded by #375), which now also carries
    this CLI-surface measurement; **not** changed or claimed here. Note for the record that
    `frpc -c <that config>` returns 1 both before and after this change, but for the *wrong*
    reason: the config is accepted and the process then fails to connect (a runtime exit),
    not a config refusal. The exit code agrees with Go by coincidence on that one row.
- [x] **`frps --config-dir` never installs the SIGUSR1 handler, so `kill -USR1` kills the server.**
  `frps/src/main.rs:180-248` is the `--config-dir` branch: it spawns one service task per file at
  `:221`, awaits the finished tasks at `:243-247`, and `return`s at `:248` — before the
  single-config path constructs the service at `:312-323` and installs the reload handler at
  `:325-346` (which requests `SignalKind::user_defined1()` at `:330`). With no handler installed,
  SIGUSR1 keeps its default disposition, which is terminate. Reproduced at `a928887` against this
  branch's built `target/debug/frps`: a temp dir holding one valid config
  (`bind_addr = "127.0.0.1"`, `bind_port = 47233`, `[auth] token = …`), started as
  `frps --config-dir <dir>`; the log reached `frps listener started on 127.0.0.1:47233`;
  `kill -USR1 <pid>` printed `… User defined signal 1: 30` and `wait` returned **rc 158**
  (128 + 30), with no reload line in the log — the *default disposition*, not a handler.
  Pre-existing and unrelated to this PR: `git diff 2dea6ba..HEAD -- frps/src/main.rs` is empty.
  Go frps v0.71.0 rejects `--config-dir` outright (`Error: unknown flag: --config-dir`, rc 1), so
  this lane has no Go behaviour to match; it is compared against frp-rs's own `-c` lane.

  Done-when: `frps --config-dir` installs the same SIGUSR1 reload handler as `-c` (or documents
  the divergence and pins it with a test), and a test drives a real `--config-dir` process, sends
  SIGUSR1, and asserts the process stays alive and emits the reload summary.

  Done: fixed in #419 (`eee8f588`). `--config-dir` now installs the same SIGUSR1 handler the
  single-config path does (`frps/src/main.rs:307-355`): one task holds a registry of the live
  `(Arc<Service>, path)` pairs, copies it out under the lock (so the reload cannot block
  registration), and reloads every registered service on each signal, logging one
  `SIGUSR1: <summary>` per service with a `path=<abs>` field naming its file. Measured on a real
  `--config-dir` process at this head: one config (`bind_port = 47233`) logs `SIGUSR1 reload ready
  (pid=…)` (`frps/src/main.rs:321`) before binding, `kill -USR1` logs `SIGUSR1: config reloaded: no
  changes detected`, the process stays alive and `SIGTERM` is rc 0 — the base binary died
  `unix_wait_status(158)` (128 + 30) with no reload record. Pinned by
  `a_config_dir_sigusr1_reloads_every_service` (`frps/tests/warn_delivery.rs:636`) and
  `a_config_dir_process_survives_sigusr1_and_reloads` (`:606`); the fan-out pin's count-based wait
  (`sigusr1_and_wait_for_reloads`, `frps/tests/warn_delivery.rs:246`, 20 s deadline) fails loudly on
  a stalled fan-out — the mutation `svcs.iter().take(1)` (`frps/src/main.rs:330`) reds it rc 101
  `left: 1 right: 2` at `frps/tests/warn_delivery.rs:650`. Adversarial review measured the dangerous
  direction: one run-failure + one healthy file keeps the healthy listener accepting, SIGUSR1 emits
  exactly one summary (the dead entry is dropped from the registry, the live one kept), no deadlock;
  `SIGINT`/`SIGTERM` rc 0; 48 repeat runs green (20 + 20 exact-filter, 8 whole-file), measured by
  Reviewer 1 in its round 1 — not by the adversarial round, which measured the dangerous direction
  above and the mutant matrix instead.
- [x] **`frps --config-dir` exits 0 when every config file fails service initialisation.**
  Same `--config-dir` branch as the item above, and the same reason it is worth recording next to
  it. `frps/src/main.rs:221` pushes the `tokio::spawn` handle *before* the service is
  constructed, so `handles` is non-empty even when every config fails inside the task
  (`:222-232` logs `frps service init failed for [<path>]: …` and `return`s); the
  `if handles.is_empty()` guard at `:239` therefore never fires, `:243-247` awaits the already
  finished tasks, and `:248` returns ⇒ process exit 0. The single-config path exits through
  `process::exit(e.kind().exit_code())` at `:321` instead. Reproduced at `a928887` with the same
  one-file temp dir and **no `[auth]` token** in it (which trips the empty-token refusal):
  * `frps -c <file>` → **rc 3**; log
    `frps init error: security misconfiguration: CRITICAL: [auth].token / auth.tokenSource resolved empty with token auth method — server would accept ALL connections. Set a strong token in the config file.`
  * `frps --config-dir <dir>` → **rc 0**; log
    `frps service init failed for [<path>]: security misconfiguration: CRITICAL: [auth].token …`
    with nothing listening on the bind port.
  * `frps --config-dir <missing-dir>` → **rc 2**; log
    `Failed to read config directory: No such file or directory (os error 2)` — so the directory
    read does refuse non-zero (`frp-core::EXIT_CONFIG`); only the all-configs-failed-to-init lane
    returns 0.

  A supervisor running `frps --config-dir` therefore sees success while nothing is served. This is
  pre-existing and unrelated to this PR (`git diff 2dea6ba..HEAD -- frps/src/main.rs` is empty).
  The comment at `frps/src/main.rs:183-188` calls the non-zero refusals below it "a deliberate,
  measured divergence" from Go; the init-failure path is *not* one of them — it is the rc 0 above
  — which is what makes this read as an oversight rather than a decision.

  Done-when: `frps --config-dir` with every file failing service initialisation exits non-zero
  (the same typed exit-code lane as `-c`), and a test runs a real `--config-dir` process over an
  all-failing directory and asserts the non-zero rc.
  Done: fixed in #419 (`b6b5884a`, `89bc4a4d`). Each spawned task now reports its outcome:
  `Ok(Err(code))` carries the typed construction code (`e.kind().exit_code()`) or `EXIT_RUNTIME`
  when `run()` failed, `Ok(())` only on `Service::run`'s single graceful-shutdown return
  (`frp-server/src/service.rs:2276`). The lane collects them and, when **every** spawned task
  reported `Err` (`frps/src/main.rs:387-390`), exits with the **first spawned** failure's code
  instead of 0; the `run()`-error arm also drops the dead service from the registry first
  (`frps/src/main.rs:275-295`) so a later SIGUSR1 cannot report a reload for a listener that is gone.
  Measured at this head (one fresh free port per row): one config whose `bindPort` is already held →
  `-c` rc **1** and `--config-dir` rc **1** (base: dir rc 0 with zero listeners); all-init-fail (no
  token) → `-c` 3, dir 3; mixed init-fail + run-fail → rc 3, nothing listening; one failure + one
  healthy file → the healthy listener still accepts, `SIGTERM` rc 0. Pinned by
  `config_dir_where_every_service_fails_to_run_exits_like_dash_c` (`frps/tests/cli_exit_codes.rs:633`)
  and `config_dir_where_every_service_fails_init_exits_like_dash_c` (`:581`); deleting the
  `task_failures.len() == spawned` guard (`frps/src/main.rs:387`) reds both (`Some(0)` vs `Some(1)` at
  `:654`; `Some(0)` vs `Some(3)` at `:601`), and a `FRPS_BIN`-retargeted run fails the run pin with
  `left: Some(0) right: Some(1)`. The comment at `frps/src/main.rs:368-370` states "first **spawned**
  failure" exactly and records the pre-existing load-lane divergence (empty-config-file set, or every
  file failing to **load**, is refused earlier at `handles.is_empty()` with `EXIT_CONFIG`/2).
- [x] **The space-separated `--strict-config false` form is an frp-rs extension presented as Go
  pflag semantics, and it parses differently from Go.** Measured on Go v0.71.0 and frp-rs
  (`frp-core/src/cli.rs`), with the same unknown-key config:
  * `frpc reload --strict-config false -c badwithport.toml` → Go: `json: unknown field
    "notAKnownFrpKey"`, exit 1 (strict stays **true**; `false` is left as an unused positional
    argument). frp-rs: the value is consumed as `false`, the unknown key is tolerated and the
    config's port is dialed. Same on `status`.
  * The adjacent form agrees: `--strict-config=false` is lenient on both.
  * `--strict-config foo` → Go ignores the stray token and keeps strict=true; frp-rs rejects it
    (`Error: \`foo\` is not expected in this context`). Go errors only on `--strict-config=foo`
    (`invalid argument "foo" for "--strict-config" flag: strconv.ParseBool: parsing "foo":
    invalid syntax`), where frp-rs's message differs but both exit 1.
  The divergence is **pre-existing** on `run`/`reload` and newly reachable on `status`, whose
  parser this branch added; several `frp-core/src/cli.rs` comments asserted the space form was
  "Go pflag bool semantics" and were corrected (no parser change).
  **Done-when:** either drop the space-separated value form so both binaries agree with Go pflag
  (and update `strict_config_space_separated_value_parses` /
  `strict_config_invalid_value_errors_cleanly`), or state it as a documented extension — in
  `docs/` and in the `--strict-config` help text — with the `=` form staying Go-faithful. No sha.
  **Done (2026-09-26, at the head of `fix/strict-config-space`, after review).** Branch taken:
  **keep the extension, document it and make it loud** — the policy both reviewers independently
  recommended once the silent divergence was on the table. Parsing is unchanged; the space form
  now prints one stderr warning.
  * **Why keep, as the measured trade.** Keeping preserves argv acceptance and every existing
    invocation. Measured rows where that is visible: `frpc verify --strict-config false -c
    good.toml` is rc **0 on both** binaries today (Go strict but the config is valid, frp-rs
    lenient), and `frpc reload --strict-config false -c host.toml` is rc 1 on both (Go's request
    carries `?strictConfig=true`, frp-rs dials the same address) — what differs is *which load
    happened*, not always the exit code. Dropping is cheap (bpaf 0.9.27
    `ParseArgument::adjacent()`), and it would make the divergence impossible to miss, but it
    converts a Go-succeeding argv into an frp-rs failure: measured with the drop branch built,
    `frpc verify --strict-config false -c good.toml` → Go **rc 0** (`syntax is ok`), drop branch
    **rc 1** (``Error: `false` is not expected in this context``) — the load-bearing row, a valid
    config so the argv succeeds on Go; `frpc verify --strict-config false -c badwithport.toml` →
    Go rc 1, drop rc 1 (rc agrees, reason does not); `frpc reload --strict-config false -c
    host.toml` → Go rc 1, drop rc 1. On the **root** command that argv already fails on Go:
    `frps --strict-config false -c goodfrps.toml` → Go **rc 1** (`Error: unknown command "false"
    for "frps"` — no positional, refused before the config is read), head rc 124 (the extension
    starts), drop rc 1 — so there Go and the drop branch agree on the code and the row is
    completeness, not evidence. `frps --strict-config=false` keeps working under the drop branch.
    So dropping trades a behaviour difference for an acceptance difference. The chosen mitigation
    is the warning below; the silent cost of keeping is stated in the docs section.
  * **The warning.** `STRICT_CONFIG_SPACE_FORM_WARNING` (`frp-core/src/cli.rs`) is printed from
    `parse_frps_args`/`parse_frpc_args` after a successful parse, gated by
    `strict_config_space_form_used`: a `--strict-config`/`--strict_config` token immediately
    followed by a token that is not `-`-prefixed and parses as a Go bool — exactly the shape bpaf
    consumes. Exact text: `warning: --strict-config <bool> is an frp-rs extension; Go's pflag does
    not consume the token and stays strict. Use --strict-config=<bool> for identical behaviour.`
    It fires for the space form on all six parsers and never for `=`, bare, absent,
    `--strict-config --config x`, or a non-bool token.
  * **Measured table (2026-09-26, Go v0.71.0 darwin/arm64 vs this branch's binaries).** Client
    config `/private/tmp/goprobe/badwithport.toml` (valid + `notAKnownFrpKey = 1` +
    `[webServer] port = 7499`), plus `good.toml` (valid, no unknown key) and `host.toml`
    (`[webServer] addr = "localhost"`, no unknown key); server configs
    `/private/tmp/goprobe/badfrps2.toml` (`bindPort = 7511`, `auth.token`, the unknown key) and
    `/private/tmp/goprobe/goodfrps.toml` (`bindPort = 7513`, `auth.token`, no unknown key); every
    run through a bounded runner (`rc 124` = the process started and the bound killed it).
    * `frpc reload|status|stop --strict-config false -c bad` → Go rc 1 `json: unknown field …`,
      **no dial**; frp-rs rc 1, dials `7499` (**extension**, warns). `--strict-config=false` → both
      lenient, dial `7499`, silent. `--strict-config foo` → Go rc 1 unknown field (token ignored,
      config still loaded); frp-rs rc 1 ``Error: `foo` is not expected in this context``, silent.
      `--strict-config=foo` → Go rc 1 `invalid argument "foo" … strconv.ParseBool`; frp-rs rc 1
      with the same `` `foo` is not expected `` message. Absent / bare / `=true` → strict on both.
    * `frpc --strict-config false -c bad` (run) → Go rc 1 `Error: unknown command "false" for
      "frpc"` (the root command takes no positional — a correction to the "unused positional"
      wording above, which holds for the subcommands only); frp-rs consumes it and goes lenient,
      connecting to `7500` (warns).
    * `frpc verify --strict-config false -c bad` → Go rc 1 unknown field; frp-rs **rc 0**
      `Config file … is valid` (warns). **Position does not matter**: `verify -c bad
      --strict-config false` reproduces the same rows (Go rc 1 unknown field, frp-rs rc 0).
    * **Repeated flag** (new): `verify --strict-config=true --strict-config=false -c bad` → Go
      **rc 0** `syntax is ok` (pflag is last-wins, so lenient) vs frp-rs rc 1 ``argument
      `--strict-config` cannot be used multiple times in this context``; the reverse order
      (`=false =true`) → Go rc 1 unknown field (last-wins, strict) vs frp-rs rc 1, the same
      repetition refusal. This is why the Go-faithful `=` claim is qualified to a **single
      occurrence**: it does not hold for a repeated flag. No warning either way (no value is
      parsed).
    * **Empty value** (new): `--strict-config=` → Go rc 1 `invalid argument "" … ParseBool`, frp-rs
      rc 1 ``Error: `` is not expected in this context``. `--strict-config ""` → with the
      unknown-key config Go rc 1 unknown field (the empty token is a positional) and frp-rs rc 1
      `` `` is not expected``; with the **valid** config Go **rc 0** (`syntax is ok` — the token is
      ignored) while frp-rs is still rc 1, because bpaf does not consume an empty value. That is a
      second, pre-existing "frp-rs stricter than Go" divergence on the same flag, in the opposite
      direction, recorded rather than fixed. No warning (nothing consumed).
    * `frps --strict-config=false -c badfrps2.toml` → both start (lenient, rc 124).
      `frps --strict-config false` → Go rc 1 `Error: unknown command "false" for "frps"`; frp-rs
      consumes it and starts (extension, warns). `frps --strict-config=foo` → rc 1 both, Go pflag
      text vs frp-rs's message. Go's `frps` **does** carry the flag (`strict config parsing mode,
      unknown fields will cause errors (default true)` in `frps --help`), so frps is in scope and
      covered; Go's `frps verify` subcommand has no frp-rs counterpart and is not part of this item.
    * **Per-flag, not CLI-wide:** `frps --tls-only=false -c goodfrps.toml` → Go rc 124 (accepted,
      starts) vs frp-rs rc 1 ``Error: `false` is not expected in this context``; same for
      `--enable-prometheus=false`, `--disable-log-color=false` and `--dashboard-tls-mode=false`
      (four probed, not a sweep). The "`=` spelling is Go-faithful" rule therefore does not
      generalise past the flags routed through the shared bool-value parser — new item below.
  * **Carriers.** `--strict-config` help text from one definition (`strict_config_parser` in
    `frp-core/src/cli.rs`, used by `frps` and `frpc` `run`/`verify`/`reload`/`status`/`stop`): the
    bare-form line names the Go-faithful spellings, says frp-rs additionally consumes a
    space-separated value "which Go's pflag does not", and says a warning is printed; the `=BOOL`
    line names the Go-faithful value spelling. The warning line itself is a `pub const` so the
    binary tests import the same string. `docs/developing.md` § `--strict-config`: the
    space-separated value form carries the full table (warning column included), the measured drop
    branch, the per-flag caveat and the reasoning; `docs/deployment.md` states it in the
    user-facing admin-CLI paragraph; `CHANGELOG.md` records the warning under Unreleased § Changed
    and the documentation under § Docs.
  * **Tests.** `strict_config_space_separated_value_parses` and
    `strict_config_invalid_value_errors_cleanly` (`frp-core/src/cli.rs`) pin the documented
    behaviour: the extension and its Go divergence (all six parsers, both spellings, Go's
    `ParseBool` value grammar) and the refusal message for **both** non-bool spellings (with a note
    that `parse_go_bool`'s own `invalid boolean value` text is never user-visible — bpaf backtracks
    and the leftover token is what gets reported). The four Go-faithful forms (absent / bare /
    `=true` / `=false`) are pinned across all six parsers; the warning by
    `strict_config_warning_text_is_the_documented_line` (exact text),
    `strict_config_warning_detection_matches_the_consumed_shape` (the argv shapes that must and
    must not be detected) and, on the real binaries, `space_form_warning_fires_on_each_frpc_parser`
    (one row per `frpc` parser plus the silent `=` rows) and
    `space_form_strict_config_warns_on_stderr` (`frps/tests/cli_exit_codes.rs`); the help text by
    `strict_config_help_text_states_the_extension`, which now pins **each entry separately**
    (rendered const + an independent literal meaning), so neither a deleted value-form `.help()`
    nor an inverted bare-form help passes — both mutants were run and fail. End-to-end, on the real
    binary: `verify_strict_config_spellings_match_their_measured_rows` (`frpc/tests/cli_inputs.rs`,
    rc + which load happened + the warning for every spelling, both repeated-flag orders, both
    empty-value spellings and the position row) and
    `reload_space_separated_strict_config_is_consumed_as_the_value` /
    `reload_bare_strict_config_stays_strict_and_never_connects` (`frpc/tests/admin_cli.rs`; the
    consumed value is proven by the mock admin receiving the connection, its control by a strict
    refusal that dials nothing). Red evidence: help entry removed → the help test fails; the bare
    entry inverted → the help test fails; `status_cmd` back on a plain `.switch()` → the uniform
    value loops fail on the `frpc status` label; the value branch dropped → both real-binary tests
    fail; the warning disabled at either entry point, or forced on unconditionally → the warning
    tests fail in the corresponding direction; and a Go-semantics binary fails the extension rows
    by measurement (the `verify --strict-config false` row is rc 1 there, rc 0 here).
- [x] **Bool flags registered as bpaf switches refuse the pflag `=value` spelling Go accepts.**
  Pre-existing, and the **opposite direction** from the `--strict-config` item above: frp-rs is
  *stricter* than Go on argv Go accepts. Measured 2026-09-26 on Go frp v0.71.0 (darwin/arm64) vs
  this tree, with a valid server config (`/private/tmp/goprobe/goodfrps.toml`: `bindPort = 7513`,
  `auth.token`) and a bounded runner, so `rc 124` = Go accepted the flag and started:
  * `frps --tls-only=false -c goodfrps.toml` → Go rc 124 (starts and listens) vs frp-rs rc 1
    ``Error: `false` is not expected in this context``.
  * `frps --enable-prometheus=false -c goodfrps.toml` → Go rc 124 (starts) vs frp-rs rc 1, the same
    message.
  * `frps --disable-log-color=false -c goodfrps.toml` → Go rc 124 (starts) vs frp-rs rc 1, the same
    message.
  * `frps --dashboard-tls-mode=false -c goodfrps.toml` → Go rc 124 (starts) vs frp-rs rc 1, the same
    message.
  * The four rows above are the **measured examples of a class, not an exhaustive list**: the sweep
    is this item's done-when.
  * The space-separated form is *not* the divergence here: `frps --tls-only false -c goodfrps.toml`
    → Go rc 1 `Error: unknown command "false" for "frps"` (root command, no positional) vs frp-rs
    rc 1 ``Error: `false` is not expected in this context`` — both refuse, for different reasons.
  Cause: these flags are bpaf `.switch()`es, which take no value, while Go registers them with
  pflag's bool machinery (`--flag`, `--flag=true`, `--flag=false`). The `--strict-config` item
  above solved exactly this shape for one flag by routing it through a shared bool-value parser
  (`strict_config_parser`), and its `=` spelling is Go-faithful because of that; the rule does not
  generalise to any flag still on `.switch()`. The class also covers Go bool flags frp-rs does not
  register at all: Go's `frpc tcp` spells this pair `--ue`/`--uc`, and Go **accepts** them
  (`frpc tcp --ue=false -c <cfg>` → rc 1 `name should not be empty`, i.e. the flag parsed and the
  failure is post-parse), where frp-rs implements neither and refuses the token
  (``Error: expected `--local-port=PORT`, got `--ue` ``). `--use-encryption=false` itself has no Go
  behaviour to match — Go answers `Error: unknown flag: --use-encryption`, rc 1 — while frp-rs has
  the flag and refuses the `=` spelling for its own reason: ``Error: expected `--local-port=PORT`,
  got `false` `` for exactly that argv (the message names `--remote-port` only once `--local-port`
  has already been supplied).
  **Done-when:** **sweep** every bool flag on `frps`/`frpc` (the four measured above are examples,
  not the set), give each the `=value` spelling Go accepts (the shared value-parser shape, or a
  sweep over the switches), and pin one representative per binary end-to-end in the style of
  `frps/tests/cli_exit_codes.rs`; or record each remaining one as a deliberate divergence in the
  feature-surface policy and say the list is complete. No sha.
  **Done (2026-09-26, at the head of `fix/bool-value-spelling`).** Swept, fixed, residue recorded.
  The long form — every row Go vs base head vs this head, and the carriers — is
  `docs/developing.md` § `--flag=<bool>`.
  * **The sweep is complete, and the count is ten** (not the four probed above):
    `frps --tls-only`, `--enable-prometheus`, `--disable-log-color`,
    `--dashboard-tls-mode`, `-v`/`--version`; `frpc --disable-log-color`,
    `-v`/`--version`; `frpc tcp --use-encryption`, `--use-compression`;
    `frpc status --json`. At the base head `grep -n "\.switch()" frp-core/src/cli.rs`
    returned those ten sites — the eleven lines include one doc comment. All ten now go
    through one parser, `go_bool_flag!` (`frp-core/src/cli.rs`): `parse_go_bool`'s grammar
    on an `.adjacent()` value branch plus the bare `.flag(true, false)` fallback, so the
    space-separated form stays refused exactly as before. No `.switch()` is left in the code —
    the seven remaining `grep` matches in that file are all comments or doc comments.
  * **Measured** on Go v0.71.0 (darwin/arm64) with per-row valid configs and a bounded
    runner (rc 124 = started and killed), Go / base head / this head:
    `frps --tls-only` `=true`/`=false`/`=1`/`=0` — 124/124/124/124 → 1/1/1/1 → **124 all
    four**; `--enable-prometheus` and `--disable-log-color`, the same four spellings, the
    same move; `frps --version=false`/`=0` — 124 → 1 → **124**, `=true`/`=1` — 0 → 1 →
    **0**; `frps -v=false` — 124 → 1 → **124**; `frpc --version=false`/`=0` — 124 → 0
    (it printed the version) → **124**; `frpc --version=foo` — 1 → 0 → **1**;
    `frpc --nope=1 --version` — 1 → 0 → **1**; `frpc tcp --ue=false` (Go's name) vs
    `--use-encryption=false` — 124 → 1 → **124**, and `--uc`/`--use-compression` the
    same. `=foo` is rc 1 on both sides everywhere (Go's `ParseBool` text, frp-rs's
    leftover-token text), and `frpc status --json=false` goes from an argv error to the
    admin-port refusal, i.e. the value is consumed.
  * **Two corrections to this item's own text.** (a) `--dashboard-tls-mode` is **not** a
    Go bool: it is a **string** flag that accepts any value (`=auto`, `=disable`,
    `=bogus` and the empty value all start frps, rc 124) and whose bare form consumes the
    next token (`frps --dashboard-tls-mode -c cfg` → `unknown command "<cfg>"`, rc 1).
    frp-rs models the field as a bool, so only the bool-shaped values — which Go happens
    to accept as strings — can be honoured: `=true`/`=false`/`=1`/`=0` move 1 → **124**,
    while `=auto`/`=disable`/any string stay rc 1 here and rc 124 there. A modelling
    divergence, recorded, not a value-spelling one. (b) `--json` is frp-rs-only (Go
    answers `unknown flag: --json`, rc 1, for every spelling), so its value form is an
    frp-rs extension and its help says so.
  * **A regression the first review round caught, and the fix.** `.adjacent()` cannot be
    used with a **short** on the value branch: `ParseArgument` pushes the named argument
    onto `State::path` as soon as it *attempts* a token, so that branch reported one level
    deeper than the flag branch and `this_or_that_picks_first`
    (`bpaf-0.9.27/src/structs.rs:296-350`) returned its error even when the flag branch had
    parsed the token. Measured: with the short in both branches, `frps -vtrue`/`-vh`/
    `-vtok`/`-vp7000` — pflag *shorthand clusters* that set `-v` and re-parse the rest,
    rc 0 on Go **and rc 0 at the base head** — all became rc 1. Fixed by giving the short
    to the flag branch only and expanding pflag's `-v=<bool>` spelling to
    `--version=<bool>` before bpaf sees argv (`expand_bool_short_value_form`), which is
    the same variable under pflag, and never past a `--`, so `frps -- -v=false` still
    names `-v=false` exactly as the base head did. Measured now, Go / base / this head:
    `-v` 0/0/0, `-v=<bool>` 124/1/**124**, `-vtrue` 0/0/**0**, `-vh` 0/0/**0**,
    `-vtok` 0/0/**0**, `-vp7000` 0/0/**0**, `-vfoo` 1/1/1, `-v0` 1/1/1 (Go
    `unknown shorthand flag: '0' in -0`, here `` `-v0` is not expected `` — rc agrees,
    message shape only). The entry points now build bpaf's `Args` by hand
    (`cli_args`/`run_cli`) so the rewrite has a place to live; they reproduce
    `OptionParser::run` exactly (`print_message(100)`, `exit_code()`, argv[0] dropped the
    way `Args::current_args` drops it, `set_name` only when argv[0] yields a UTF-8 file
    name — never a hardcoded program name, which made `frpc` print `Usage: frps …` for an
    unreadable argv[0] in the first revision of this fix). Help and error output were
    diffed byte-for-byte against the previous build over 14 argvs **and** over four
    argv[0] shapes; the only differences are the intended usage-line spelling, the two
    new help entries and the nameless usage line bpaf itself renders when argv[0] is
    unreadable. Residual, recorded rather than fixed: because the rewrite precedes the
    parse, a *rejected* `-v=<bool>` can be reported under its long name — measured,
    `frpc status -v=false -c <cfg>` is rc 1 `` `--version` is not expected ``, where the
    base head printed the version and exited **0** (the speculative-`exit` defect this
    branch fixes; no diagnostic at all) and the first-revision head said `` `-v` `` (rc 1,
    the token being the short `-v`); Go exits 1 too (the persistent flag parses and
    `status` dials).
  * **A second defect, found by the sweep and fixed here.** `frpc`'s version check lived
    in a bpaf `.map()` closure on `frpc_parser()`'s run branch, and bpaf's `ParseOrElse`
    evaluates **every** alternative on a forked state, so at the base head
    `frpc --nope=1 --version` and `frpc verify --version` printed `frpc 0.71.0 (Rust)`
    and exited **0** (Go: rc 1 `unknown flag: --nope`; rc 0 with `verify` actually
    verifying). The check now runs in `parse_frpc_args` after `run()` returns, as
    `parse_frps_args` already did.
  * **Deliberately left divergent**, each measured and in `docs/developing.md`
    § `--flag=<bool>` (not in the feature-surface policy: its tiers are transport/proxy
    surfaces, and a CLI flag-spelling row would misfile there — the `--strict-config`
    divergence is carried in `docs/developing.md` § CLI exit codes for the same reason):
    the space-separated form is still refused (Go refuses it on the root commands —
    `unknown command "false"`, rc 1 — ignores it on `frpc tcp` (rc 124) and consumes it
    for the string flag `--dashboard-tls-mode` (rc 124); matching the last two would mean
    consuming a token Go's bool never consumes); a repeated flag is refused where Go is
    last-wins (rc 124 both orders); `frpc --disable-log-color` sits on the client root
    where Go registers it on its eight single-proxy subcommands (`tcp`, `udp`, `http`,
    `https`, `stcp`, `xtcp`, `sudp`, `tcpmux`) and their `visitor` forms, not the root;
    `--json` has no Go counterpart; Go's proxy-subcommand bools `--ue`/`--uc`
    (`--use-encryption`/`--use-compression` here) and `--tls-enable` are not implemented
    at all — measured, all four are on all eight of those subcommands (and `--ue`/`--uc`/
    `--tls-enable`/`--disable-log-color` on `stcp|xtcp|sudp visitor`), plus cobra's
    `completion <shell> --no-descriptions`, and Go accepts them (`--tls-enable=false …`
    → 124, `=foo` → 1) where frp-rs refuses the name; `--help`/`-h` is a Go pflag bool
    (`--help=false -c cfg` starts, rc 124) and is bpaf's built-in here (prints help,
    rc 0); the help *shape* also differs — frp-rs renders two entries per bool flag
    (`--flag=BOOL` and `--flag`) and a `(--version=BOOL | [-v])` usage alternative where
    Go prints one `-v, --version` line; and at that head `frpc verify --version` was rc 1 where
    Go is rc 0 (with a valid `-c`; with no `-c` Go is rc 1 too) — one row of the
    persistent-root-flag class then tracked by the `frpc` eight-single-proxy-subcommands item
    (`TODO.md:2173`, since closed by the persistent-rootCmd-flag work, which registers all five
    flags on the twelve subcommands: `frpc verify --version -c <valid>` is rc 0 again and
    `frpc tcp --version …` starts the proxy).
    Measured for that class at that head: `frpc tcp --version --local-port … --remote-port …` was
    the same shape, Go 124 / base 0 / head 1, while `reload|status|stop --version` moved
    0 → 1 and already **matched** Go's rc 1 there.
  * **Tests.** Parser level (`frp-core/src/cli.rs`):
    `every_go_bool_flag_accepts_the_pflag_value_spellings` (absent, bare, all ten
    `strconv.ParseBool` spellings and the underscore aliases, across all ten sites from
    one `GO_BOOL_SITES` table), `every_go_bool_flag_refuses_non_bool_values_and_the_space_form`
    (`=foo`, `=` and the space form, each pinned on the user-visible message),
    `every_go_bool_flag_help_states_its_own_spelling` (the rendered `--help` of all four
    surfaces, per flag, including which Go claim the call site's macro form makes, and
    the `(--version=BOOL | [-v])` usage alternative the docs quote) and
    `every_go_bool_flag_rejects_a_repeated_flag`; the rewrite's own unit test also pins
    that a `--` stops it and that `-c=x`/`-t=v`/non-UTF-8 tokens are passed through. Real binary, all asserting what
    happened and not only the rc: `version_flag_value_spelling_decides_what_happens`,
    `version_short_shorthand_clusters_and_equals_spelling_match_go`,
    `tls_only_false_value_starts_and_listens` and
    `disable_log_color_value_spelling_is_applied`
    (`frps/tests/cli_exit_codes.rs`) plus `version_flag_value_spelling_decides_what_happens`
    and `disable_log_color_value_spelling_is_consumed` (`frpc/tests/cli_exit_codes.rs`).
    What each proves, because a review round found one claiming more than it shows:
    `tls_only_false_value_starts_and_listens` waits for a real listener before SIGTERM (so
    "started" is not inferred from an rc), but with `-c` the transport section of the
    config is authoritative, so it pins argv **acceptance**, not that `false` reached the
    service — its doc comment now says so; `disable_log_color_value_spelling_is_applied`
    pins the value actually being **applied** (`--disable-log-color=false` leaves ANSI
    escape sequences in the child's output — 140 on the author's host, 260 on a
    reviewer's, which is why the assertion is "some vs none" and not a count —
    while `=true` leaves none);
    `version_short_shorthand_clusters_and_equals_spelling_match_go` pins the `-v`
    shorthand grammar that the review round's regression broke (`-vh` help,
    `-vtrue`/`-vtok`/`-vp7000` version, `-v=false` reaching the loader, `-vfoo`/`-v0`
    rc 1). Red evidence: with `frp-core/src/cli.rs` reverted to the base head, all four
    original real-binary tests fail; `--tls-only` back on `.switch()` fails the parser
    test, and the value branch rendering the switch help fails the help test.
  * **CI counts.** The four new tests in the guarded `frps/tests/cli_exit_codes.rs` move
    its literals 5 → **9**; the two new `frpc` tests are ungated, so they run in both
    lanes and move the `tiny` lane's `frpc/tests/cli_exit_codes.rs` literal 9 → **11**
    (the default-features list goes 7 → 9, which no lane counts). Both pairs in
    `.github/workflows/ci.yml` are updated in the same commit.
- [x] **Three pre-existing `frpc` CLI inputs Go accepts and frp-rs does not** (all measured on
  Go v0.71.0 and on `main` @ `9c1b291`'s frpc as well as this branch's, so none is introduced by
  the `reload`/`status` fix):
  * **`-c` twice.** `frpc reload -c noweb.toml -c goodcli.toml` → Go is last-wins and dials the
    second config (`Get "http://127.0.0.1:7499/api/reload…": dial tcp 127.0.0.1:7499: connect:
    connection refused`); frp-rs (both binaries) exits before loading with
    ``Error: argument `-c` cannot be used multiple times in this context``.
  * **Capitalised `[webServer] Port`.** `Port = 7499` → Go's JSON decoding matches the field
    case-insensitively and dials `127.0.0.1:7499`; frp-rs errors
    `unknown field "web_server.Port" in config file … — did you mean 'port'?`. On the pre-fix
    binary the same config silently fell back to `127.0.0.1:7400` (the load error was swallowed),
    so only the error message is new here — the mismatch with Go is not.
  * **Empty `webServer.addr`.** `addr = ""` → Go dials `127.0.0.1:<port>`
    (`WebServerConfig.Complete()` fills the empty addr, `pkg/config/v1/common.go:71-72`);
    frp-rs dials `":<port>"` and fails with `failed to lookup address information: nodename nor
    servname provided, or not known`.
  **Done-when:** match Go on all three (last-wins `-c`, case-insensitive config keys, default the
  empty `addr` to `127.0.0.1` at the CLI/load boundary) with a CLI test per case in the style of
  `frpc/tests/admin_cli.rs`, or record each as a deliberate divergence in the feature-surface
  policy. No sha.
  **Done (2026-09-26, at the head of `fix/frpc-cli-inputs`).** Two matched, one recorded.
  * **`-c` twice → matched.** Every frpc config argument now goes through `config_arg()`
    (`frp-core/src/cli.rs`), bpaf's `.last()`, so `run`/`verify`/`reload`/`status`/`stop` are all
    last-wins like Go's pflag `StringVarP`. Measured, Go vs frp-rs-now: `status -c noweb.toml -c
    p7499.toml` → both dial `127.0.0.1:7499`; reverse order → both print `web server port should be
    set if you want to use this feature`; `verify -c noweb.toml -c p7499.toml` → both report
    `p7499.toml`; `--config p7499.toml -c p7498.toml` → both dial `7498`; `-cp7498.toml` and
    `-c=p7498.toml` → both dial `7498` (bpaf already accepted both spellings); `-c ""` → both rc 1
    without falling back to 7400; dangling `-c` → both rc 1. Before: rc 1,
    ``argument `-c` cannot be used multiple times in this context``, nothing loaded.
  * **Empty `webServer.addr` → matched on the client.** `ClientConfig::complete_with_heartbeat_set`
    (`frp-core/src/config/client.rs`) fills the **empty string** with `127.0.0.1`, mirroring Go's
    `ClientCommonConfig.Complete() → WebServer.Complete()`
    (`pkg/config/v1/client.go:96` → `pkg/config/v1/common.go:71-72`). Measured: `status -c
    emptyaddr.toml` (`addr = ""`, `port = 7499`) → both dial `127.0.0.1:7499`; before, frp-rs
    printed `connect :7499: failed to lookup address information`. Only the empty string is
    completed — `" "` still reaches the dialer verbatim and fails (the guard against a `trim()`),
    while `"0.0.0.0"`/`"::1"`/`"localhost"` pass through as Go does. **The server side is a
    separate surface, fixed after this block:** Go's `ServerConfig.Complete()` runs the same
    `WebServer.Complete()` (`127.0.0.1`) at `pkg/config/v1/server.go:107` *before* the
    `Port > 0 → "0.0.0.0"` line at `:116-117`, so that line is dead; when this block was written,
    Go frps bound `127.0.0.1:7597` where frp-rs (`--features dashboard`) bound `*:7597`. That was
    filed as its own item below and is now **fixed and measured** — see that item's `Done` block;
    the assertions live in `server_web_server_addr_empty_is_completed_to_localhost`
    (`frp-core/src/config/tests.rs`) and in `dashboard_explicit_empty_addr_binds_loopback_only` /
    `dashboard_absent_addr_binds_loopback_only` (`frp-server/tests/dashboard_integration.rs`).
  * **Case-insensitive keys → recorded divergence, not fixed.** Go's `encoding/json` matches field
    *and table* names case-insensitively at every level, including inside `[[proxies]]` — measured:
    `ServerAddr`/`SERVERADDR`, `[WebServer]`, `[webServer] Port`, and `LocalPort`/`RemotePort`
    inside `[[proxies]]` all load on Go and are used. A bounded `#[serde(alias)]` set is not parity
    (aliases are exact strings), so the fix would be a canonicalising pre-pass or per-field aliases
    for every permutation across the whole tree; measured instead and stated with its scope in
    `docs/developing.md` § CLI inputs. The wording there is measured cell by cell and is deliberately
    **not** the earlier blanket "refused (strict) or mis-defaulted (lenient)": strict mode refuses a
    mis-cased key only in the walked sections (top level, `[auth]`/`[log]`/`[webServer]`/
    `[transport]`), while a mis-cased key inside a `[[proxies]]`/`[[visitors]]`/`[[httpPlugins]]`
    element is silently dropped **even in strict mode** (`frpc verify` rc 0; the exemption in
    `frp-core/src/config/strict.rs:277-285`, its consequences already in `docs/deployment.md:709-746`,
    pinned by `strict_mode_exempts_proxy_and_visitor_array_elements` and now also by the CLI test
    `case_insensitive_proxy_array_keys_are_dropped_in_strict_mode`). In non-strict mode the dropped
    key may later error (`web server port should be set …`, `missing field \`name\``) *or* silently
    change a default frp-rs uses (`ServerAddr`/`ServerPort` → `0.0.0.0:7000` where Go uses the file's
    values). The doc names what *is* matched (snake_case + the documented camelCase aliases) and that
    the divergence is every casing difference on both frpc and frps, not one struct.
  * Tests: `frpc/tests/cli_inputs.rs` (19 CLI tests, real `CARGO_BIN_EXE_frpc` + a one-shot
    loopback mock; red-run without the fix: 12 of the 17 pre-existing ones fail — the two case-2
    pins added in review pass on both sides, because they pin the divergence that is not being
    changed), parser tests in `frp-core/src/cli.rs`,
    and `frp-core/src/config/tests.rs`
    (`client_web_server_addr_empty_is_completed_to_localhost`,
    `client_web_server_addr_explicit_and_absent_are_unchanged`). Doc claims in `docs/developing.md`
    § CLI inputs and `CHANGELOG.md`.
- [x] **An empty `webServer.addr` still binds frps to `0.0.0.0`, where Go binds `127.0.0.1`.** Found
  while closing the frpc item above; the two-step in `frp-core/src/config/server.rs` is the opposite
  order from Go's, so Go's `0.0.0.0` branch is dead and frp-rs's `127.0.0.1` step is missing.
  * Go v0.71.0 `ServerConfig.Complete()` (`pkg/config/v1/server.go:101-126`): line 107 calls
    `c.WebServer.Complete()` → `Addr = util.EmptyOr(Addr, "127.0.0.1")`
    (`pkg/config/v1/common.go:71-72`), **then** `:116-117` runs
    `if c.WebServer.Port > 0 { c.WebServer.Addr = util.EmptyOr(c.WebServer.Addr, "0.0.0.0") }` —
    which can never fire, because the address was just filled.
  * Measured with `[webServer] addr = ""`, `port = 7597`, `user`/`password` set: Go frps logs
    `dashboard listen on 127.0.0.1:7597` and `lsof -nP -iTCP:7597 -sTCP:LISTEN` shows
    `TCP 127.0.0.1:7597 (LISTEN)`; frp-rs frps (`--features dashboard`) logs
    `Dashboard listening on 0.0.0.0:7597` and shows `TCP *:7597 (LISTEN)`.
  * `frp-core/src/config/server.rs` reproduces only the second half: it assigns `0.0.0.0` when the
    port is set and the address **is empty**, and no earlier step fills `127.0.0.1`. The divergence
    is therefore the **explicit `addr = ""`** case only — an *absent* `addr` key never reaches that
    branch, because the serde field default already supplies `127.0.0.1` and the `is_empty()` guard
    is then false (measured: an absent `addr` binds `127.0.0.1` on both, i.e. already parity; pinned
    by the second assertion of
    `server_web_server_addr_empty_stays_wildcard_a_recorded_divergence`). For the explicit empty
    string it is a reachable security-relevant divergence (an admin/dashboard listener on every
    interface where Go keeps it loopback), not just a docs defect.
  **Done-when:** match Go — complete `web_server.addr` to `127.0.0.1` on the empty string first, and
  delete or neutralise the `0.0.0.0` branch — with a test asserting the bound address for `addr = ""`
  and for an absent `addr` (not merely the config field), and update the `docs/developing.md`
  § CLI inputs paragraph that currently records the divergence. If a deliberate exception is kept
  (a server that *must* expose the dashboard on a wildcard address for an empty value), say so with
  the measurement and the reason instead; do not leave the current claim that frp-rs "already does"
  what Go does. No sha.
  **Done (2026-09-26, at the head of `fix/frps-empty-addr`).** Matched Go; no deliberate exception.
  * **Fix.** `ServerConfig::complete` (`frp-core/src/config/server.rs`) now fills the **empty**
    `web_server.addr` with `127.0.0.1` unconditionally (Go's `WebServer.Complete()` does not look at
    the port), and the `Port > 0 -> "0.0.0.0"` assignment that Go's dead `:116-117` branch
    corresponds to is **deleted**, not left as a second step. An absent `addr` key still goes through
    the serde default (`127.0.0.1`) and every explicit non-empty address is used verbatim.
  * **Measured, same config for both binaries** (`[webServer]` with the `addr` varied, one free
    dashboard port and one free `bindPort` per row, `user`/`password`, plus an `[auth]` token —
    without credentials frp-rs force-binds loopback and the wildcard cells would be false),
    Go v0.71.0 vs frp-rs `frps --features dashboard`, both started by a bounded probe that
    SIGTERMs the child, address read back with `lsof -nP -iTCP:<port> -sTCP:LISTEN`:

    | `addr` | dashboard port | Go v0.71.0 | frp-rs before | frp-rs now |
    |---|---|---|---|---|
    | `""` | 17701 | `dashboard listen on 127.0.0.1:17701`; `TCP 127.0.0.1:17701 (LISTEN)` | `Dashboard listening on 0.0.0.0:17701`; `TCP *:17701 (LISTEN)` | `Dashboard listening on 127.0.0.1:17701`; `TCP 127.0.0.1:17701 (LISTEN)` |
    | absent | 17703 | `dashboard listen on 127.0.0.1:17703`; `TCP 127.0.0.1:17703 (LISTEN)` | `127.0.0.1:17703` (serde default) | `127.0.0.1:17703` |
    | `"0.0.0.0"` | 17705 | `dashboard listen on 0.0.0.0:17705`; `TCP *:17705 (LISTEN)` | same | same |
    | `"::1"` | 17707 | `dashboard listen on [::1]:17707`; `TCP [::1]:17707 (LISTEN)` | same | same |

    No listener was left behind: after the probes, `lsof -nP -iTCP:17700-17710 -sTCP:LISTEN` was empty
    and no `frps -c /tmp/fer/...` process remained.
  * **Tests.** The old pin
    `server_web_server_addr_empty_stays_wildcard_a_recorded_divergence` is replaced by
    `server_web_server_addr_empty_is_completed_to_localhost` (`frp-core/src/config/tests.rs`), which
    asserts `""` → `127.0.0.1` with and without a port, `"0.0.0.0"`/`"::1"`/`"10.1.2.3"` verbatim, and
    the absent-key default. The **bound address** is asserted by three new spawn tests in
    `frp-server/tests/dashboard_integration.rs` (`dashboard_explicit_empty_addr_binds_loopback_only`,
    `dashboard_absent_addr_binds_loopback_only`, `dashboard_explicit_wildcard_addr_binds_every_interface`),
    which run the real `frps` binary from this lane's `FRPS_BIN` (built `--features dashboard`), read its
    post-bind `Dashboard listening on …` line, connect to `127.0.0.1`, and probe a non-loopback local
    IPv4: refused for both loopback cases, accepted for the explicit `0.0.0.0` case — that last test is
    the positive control for the probe (a host where the probe could never connect fails there rather
    than letting the two loopback assertions pass vacuously). Red evidence: before the fix the config
    test failed with `left: "0.0.0.0", right: "127.0.0.1"` and the empty-addr spawn test failed with
    `Dashboard listening on 0.0.0.0:<port>` (19 passed / 1 failed in the dashboard bin); after, 20
    passed. Helper added: `common::CapturedFrps` / `common::frps_binary` (`frp-server/tests/common/mod.rs`).
  * **Carriers.** `docs/developing.md` § CLI inputs rewritten (the paragraph no longer records a
    server-side divergence and carries the measured table above), `docs/config.md`'s two `webServer.addr`
    rows (server and client admin API) no longer say "Empty string binds to all interfaces", the stale
    server-divergence comment in `frp-core/src/config/client.rs` and the `WebServerConfig::addr` doc
    comment in `frp-core/src/config/server.rs` now state the Go order, `CHANGELOG.md` gained the
    user-visible binding-change entry (and the frpc entry no longer claims `frps` is unchanged), and this
    item is ticked. The historical `CHANGELOG.md` entry in the
    `v0.7.1 — Go frp v0.70.1 Source-Level Compatibility Audit` section (`web_server.addr` from
    `""` to `127.0.0.1`) is point-in-time and was left alone.
- [x] **The rest of the server-side completion is not Go's: an empty `bindAddr` is not filled, and
  an empty `--dashboard-addr` bypasses `complete()` entirely so the dashboard cannot start.** Both
  found while fixing the empty `webServer.addr` above; both fail *closed* (a refused start, or a
  dead dashboard on a live control listener). **Neither gap widens or adds any listening socket:**
  measured with the real binaries and `lsof -nP -iTCP:<port> -sTCP:LISTEN`, base `--bind-addr ""`
  exits 1 having bound **nothing**, and base `--dashboard-addr ""` with credentials leaves the
  control listener up while the dashboard port has **no socket** — so the impact of both is
  availability only (a refused start, a dashboard gap on an otherwise live server), and the
   `--proxy-bind-addr`/proxy-listener widening recorded below is a *separate*, deliberate
  consequence of matching Go. Both gaps are otherwise Go-divergent.
  * **(a) `--dashboard-addr ""` is applied after `complete()`, so the dashboard is handed
    `:<port>`.** `frps` loads and completes the config (pre-fix tree:
    `frp-core/src/config/file.rs:25` calls `cfg.complete()`), then applies CLI overrides
    (pre-fix `frps/src/main.rs:191`; both are the **base** tree, `80199f4`/`04959b1`). On this
    branch the load is un-completed instead (`frp-core/src/config/file.rs:22`), the override call is
    `frps/src/main.rs:209` and the completion is `frps/src/main.rs:212` — all three given for the
    tree this branch freezes). The dashboard-addr assignment itself is
    `frp-core/src/cli.rs:2309-2311` in both trees — with no `-c`/`--config-dir` the flag value is
    therefore written **after** the completion that would have filled it. Measured at the head of
    `fix/frps-empty-addr`, cwd holding a `frps.toml` (`bindPort = 17720`,
    `[webServer] port = 17721`, `user`/`password`) and argv `frps --dashboard-addr ""` (dashboard
    build): the control listener comes up on `0.0.0.0:17720`, then
    `Dashboard web UI starting on :17721` and `ERROR frp_server::service: Dashboard server failed:
    failed to lookup address information: nodename nor servname provided, or not known`;
    `lsof -nP -iTCP:17721 -sTCP:LISTEN` is empty while the process stays alive. Go v0.71.0 with the
    same config and flag logs `dashboard listen on 127.0.0.1:17721` and listens there; in Go's
    flags-only shape (`frps --bind-port 17726 --dashboard-addr "" --dashboard-port 17721 --token …
    --dashboard-user admin --dashboard-pwd adminpass`, no `-c`) it also completes to
    `127.0.0.1:17721`. Without credentials the divergence is **masked** by the existing no-auth
    force-bind: the same argv against a config without `user`/`password` logs
    `binding to 127.0.0.1:17723 (localhost only)` and listens on `127.0.0.1:17723`, i.e. it looks
    Go-correct for the wrong reason. Measured while reproducing, same code path, noted here rather
    than filed separately: without `-c` frp-rs *requires* `./frps.toml` and exits
    `frps.toml: failed to read config file: No such file or directory (os error 2)` (78 B, one bare
    line on stdout; re-quoted — the `Failed to load config: ` prefix was removed by the CLI
    output-shape round later in this file) in a
    directory without one, where Go runs flags-only.
  * **(b) `bindAddr = ""` is not completed to `0.0.0.0`.** Go's `ServerConfig.Complete()` has
    `c.BindAddr = util.EmptyOr(c.BindAddr, "0.0.0.0")` at `pkg/config/v1/server.go:110`; frp-core's
    `ServerConfig::complete` (`frp-core/src/config/server.rs`) has no equivalent, so the empty
    string reaches `TcpListener::bind`. Measured with `bindAddr = ""`, `bindPort = 17724` and an
    `[auth]` token: frp-rs exits 1 with `ERROR frps: frps error: failed to lookup address
    information: nodename nor servname provided, or not known` and binds nothing; Go v0.71.0 logs
    `frps tcp listen on 0.0.0.0:17724` and `lsof` shows `TCP *:17724 (LISTEN)`. The serde default
    already supplies `0.0.0.0` for an **absent** key, so only the explicit empty string is affected.
  **Done-when:** add the `bind_addr` completion (Go `server.go:110`) and make the CLI-flag values
  pass through the same completion Go applies — an empty `--dashboard-addr` must end up
  `127.0.0.1` for the dashboard (Go `server.go:107` → `common.go:71-72`), not `:<port>`, and an
  empty `--bind-addr` must end up `0.0.0.0` — with a bounded spawn test per shape (own free ports,
  credentials set, `--features dashboard` where the dashboard is read) asserting the bound address,
  plus a Go-binary measurement row per shape. Absent flags keep the configured/serde value, and the
  no-auth force-bind stays as it is.
  **Done (commit `fix/server-addr-completion`).** Order, not a special case: `frps/src/main.rs`
  now loads the file **un-completed** (`config::load_server_config_uncompleted`, new in
  `frp-core/src/config/file.rs`; `load_server_config` is the completing wrapper it used to be),
  overlays the flags, and only then calls `cfg.complete()`. Go's ordering is per lane, and the
  flags-only lane is the one frp-rs's override lane mirrors **in order** — overlay, then complete
  (`cmd/frps/root.go:77-83`) — though not in **values**: Go pre-seeds every pflag default into the
  struct (`pkg/config/flags.go:230-255`), while frp-rs keeps the file's values except where a flag
  overrides them. The `-c` lane builds a fresh `svrCfg`
  (`pkg/config/load.go:313`), unmarshals the file into it and completes that (`:318-321`) — the
  pflag-bound struct is dropped, so Go ignores the flags there (frp-rs does too). So *every*
  completed input the CLI can write is filled
  (`bind_addr`, `bind_port`, `proxy_bind_addr`, `web_server.addr`) instead of only the dashboard
  address, which is why re-running `WebServer.Complete()` at the CLI site was rejected: it would have
  fixed one of the four sites and left `--bind-addr ""`/`--bind-port 0` broken. (Second rejected
  alternative, raised in review: a three-field re-fill of `bind_addr`/`bind_port`/`web_server.addr`
  *after* the overrides, keeping the file's `proxy_bind_addr` inheritance. That is smaller, but it
  reproduces base's split brain — control on the override, proxies on the file — which is exactly the
  inconsistency the row below measures; `complete()` itself is idempotent, so the precise objection to
  "call `complete()` twice" is narrower than "not re-runnable": a second call after a post-completion
  `bind_addr` override cannot recover Go's `proxy_bind_addr`, because the first call already consumed
  the empty value.) `ServerConfig::complete` gained Go's `BindAddr = util.EmptyOr(BindAddr, "0.0.0.0")`
  (`server.go:110`) *before* the `ProxyBindAddr` inheritance (`:112-114`) and the `BindPort` fill
  (`:111`), so `bindAddr = ""` in a file is filled too.
  Re-measured at `80199f4` + the fix, Go v0.71.0 vs frp-rs, same config file per row, own free
  ports, `[auth]` token and `[webServer] user`/`password`, socket read with
  `lsof -nP -iTCP:<port> -sTCP:LISTEN`:
  * `--dashboard-addr ""` → Go `127.0.0.1:19802` / frp-rs before `:19802` + `failed to lookup
    address information`, **nothing listening** / now `127.0.0.1:19802` (`TCP 127.0.0.1:19802`).
  * `--bind-addr ""` → Go `*:19805` / before exit 1, nothing bound / now `*:19805`.
  * `--bind-port 0` (found by sweeping the other overrides; same class) → Go tries `0.0.0.0:7000`
    (`create server listener error … 7000: bind: address already in use`) / before bound an
    ephemeral port (`frps starting on 127.0.0.1:0`) / now `127.0.0.1:7000`.
  * `bindAddr = ""` **in the file**, no flag → Go `*:19815` / before exit 1 / now `*:19815`.
  * `--config-dir <dir>` with `bindAddr = ""` in the file (same fill, different lane — the loader
    split left this lane on the completing `load_server_config`, but the fill itself changes it):
    before **rc 0 with nothing bound**, now `*:19881` listening. Not "silent": the pre-fix run did
    emit `ERROR frps: frps service error for config file [...]: failed to lookup address
    information` on stdout — the defect is that the **exit code was 0** for a service that never
    bound. No byte total is quoted for this or for the log-shape rows below: the config path
    appears twice in that line, so the total is a function of the harness's path length (the same
    shape measured 1489 / 1540 / 1654 B under three different path lengths). With the path held
    fixed, consecutive pre-fix runs are byte-identical — which is what makes "the code emits this
    line" the reproducible claim, and any cross-harness total difference a path artifact rather
    than a code difference. Go has no `frps --config-dir`
    (`Error: unknown flag: --config-dir`, rc 1), so the analogue is Go's `-c` lane, which binds
    `0.0.0.0` for the same file.
  * Absent-flag controls: `--dashboard-addr` absent keeps the file's `127.0.0.1:19802` (Go's
    flags-only absent flag binds `0.0.0.0:19802`, because pflag writes its flag default straight
    into `c.WebServer.Addr` — `pkg/config/flags.go:238` — so `WebServer.Complete()`'s `EmptyOr`
    cannot fire; frp-rs has no flags-only mode, so there is nothing to match); `--bind-addr` absent
    keeps the file's `127.0.0.1:19807` on both.
  * Other-override sweep, corrected by measurement (reviewer R2 F2): `bind_addr`, `bind_port`,
    `proxy_bind_addr` and `web_server.addr` are the fields *this* `complete()` fills. The other
    overrides are not order-sensitive — each either feeds no completion or cannot disagree with one:
    `auth.token`, `allow_ports`, the port numbers, `max_ports_per_client` and the dashboard TLS
    paths are read by nothing in `complete()`; `tls_only` **is** read
    (`frp-core/src/config/server.rs:539`, `if !self.tls_ca_file.is_empty() && !self.tls_only`), but
    the only write there sets it `true` and the CLI's `--tls-only` also sets it `true`, so no order
    can make them disagree. (The Go entry for `tls_only` is true for a different reason:
    `Transport.Complete()` does not read `TLS.Force`.) **`log.*` is different and
    the first version of this entry was wrong about it:** Go's `ServerConfig.Complete()` calls
    `c.Log.Complete()` (`pkg/config/v1/server.go:105`) which is
    `To = EmptyOr(To, "console")`, `Level = EmptyOr(Level, "info")`, `MaxDays = EmptyOr(MaxDays, 3)`
    (`pkg/config/v1/common.go:119-123`), and `frps`'s CLI writes all three. frp-core's
    `ServerConfig::complete` has **no** log completion, and the serde defaults only fire on an
    absent key, so an explicit empty value survives: measured, `frps --log-level ""` and
    `frps --log-file ""` each produce **zero bytes on both streams** while the listener still comes
    up (base and head alike), where Go v0.71.0 with `--log_level ""` still logs at `info`
    (282 bytes of startup lines). This is **pre-existing**, not a regression of this change; it is
    filed as its own item (see below) rather than fixed here, because closing it is a behaviour
    change that needs its own compat rows.
  * **`proxy_bind_addr` inheritance — a measured behaviour change that the first version of this
    entry wrongly called "not observable" (reviewer R2 F1).** `complete()` now derives
    `proxy_bind_addr` from the **post-override** `bind_addr`, which is Go's order (`Complete()` runs
    after the flags are bound), so a `--bind-addr` that differs from the file's `bind_addr` now moves
    the proxy listeners with the control listener. Measured with a real registration and
    `lsof -nP -iTCP:<port> -sTCP:LISTEN -a -p <pid>` (file has no `proxyBindAddr` key; the `-c` shape
    ignores the flags on Go, hence its own row):

    | file `bind_addr` | argv | Go v0.71.0 proxy listener | base proxy | head proxy |
    |---|---|---|---|---|
    | `127.0.0.1` | no flag | `127.0.0.1:19872` (`-c`) | `127.0.0.1:19862` | `127.0.0.1:19862` |
    | `127.0.0.1` | `--bind-addr 0.0.0.0` | *no Go equivalent — Go ignores flags with `-c`* | `127.0.0.1:19862` while its **own control** was `*:19861` | `*:19862` (follows the override) |
    | `0.0.0.0` | `--bind-addr 127.0.0.1` | *(Go `-c` ignores the flag: `*:19874`)* | `*:19874` while its control was `127.0.0.1:19873` | `127.0.0.1:19874` |
    | flags-only | `--bind_addr 127.0.0.1` | `*:19852` (pflag's `proxy_bind_addr` default is `0.0.0.0`) | — | — |

    **Decision: keep the post-override inheritance.** It is what Go's single `Complete()` call on the
    bound struct does, and it removes base's internal inconsistency (base moved the *control* listener
    to `--bind-addr` while leaving the proxy listener on the file's address — in the first row above
    the proxy stayed loopback-only after the operator asked for the wildcard). The observable change
    is therefore "the proxy listener follows `--bind-addr`", in both directions: widening when the
    flag widens, narrowing when the flag narrows. Anyone who wants the proxy plane pinned independently
    can set `proxyBindAddr` explicitly, as before. The earlier `--proxy-bind-addr ""` probe that looked
    unchanged used `--bind-addr 127.0.0.1` equal to the file value, which cannot see this; that is the
    error the reviewers caught.
  **Tests.** `frps/tests/cli_completion.rs` (new, unguarded file — the guarded
  `frps/tests/cli_exit_codes.rs` count is untouched at 16; executed by the new
  `Run frps CLI completion tests (merged-config completion order)` step in `.github/workflows/ci.yml`,
  which is `--test cli_completion` and therefore moves no guarded count): six bounded spawns, each
  with `RUST_LOG=info`, stdout/stderr drained on reader threads and the child killed+reaped by a
  `Drop` guard. Ports: five of the six shapes own theirs via `free_port()`;
  `cli_bind_port_zero_is_completed_to_default` deliberately hard-codes `bind_port = 19845` because
  the flag under test (`--bind-port 0`) is then completed to `7000` and 19845 is never bound.
  The shapes: `--dashboard-addr ""` (credentials set, asserts the dashboard's
  own `Dashboard listening on 127.0.0.1:<port>` line, no `failed to lookup address information`, and
  that both the control and dashboard ports accept a real connection), its absent-flag control,
  `--bind-addr ""` (asserts `frps listener started on 0.0.0.0:<port>`), its absent-flag control,
  `--config-dir <dir>` with `bindAddr = ""` (the lane that never overlays flags; base exited **0 with
  nothing bound**), and `--bind-port 0` (asserts the completed `:7000`). Red evidence, re-measured by
  both reviewers and by the author: pointed at a pre-fix **dashboard** binary via `FRPS_BIN` with
  `--features dashboard` → **2 passed / 4 failed** (6 tests — the reviewers measured 2 passed / 3 failed
  against the 5-test version of this file), the four failures carrying exactly the measured
  pre-fix log (`Dashboard web UI starting on :<port>` + `Dashboard server failed: failed to lookup
  address information`; `frps error: failed to lookup address information`). The same file against a
  pre-fix **no-dashboard** binary (built from a pre-fix tree with the *default* features — `cargo
  build -p frps`, or equivalently `--no-default-features --features full`, the same **dependency** graph; note
  `--no-default-features` alone produces **no** `target/debug/frps`, because the bin is declared
  `required-features = ["full"]`) is **3 passed / 3 failed** —
  `cli_empty_dashboard_addr_binds_loopback` **passes** pre-fix there, because with the dashboard
  compiled out there is no empty address handed to a listener; the dashboard regression is therefore
  covered **only** under `--features dashboard`, which is why the CI step passes that flag. Both
  absent-flag controls pass in every configuration and the fixed binary is 6/6 in both.
  Completion-level pins: `server_bind_addr_empty_is_completed_to_wildcard` and
  `server_completion_must_run_on_the_merged_cli_config` in `frp-core/src/config/tests.rs`.
  **Carriers.** `docs/developing.md` § CLI inputs gained § 2b (the ordering rule, the measured
  per-shape table — including the `--config-dir` row and the proxy-listener rows — and the three
  non-claims: the flags-only absent-flag Go divergence, the `proxy_bind_addr` post-override
  inheritance now being observable, and frp-rs's missing flags-only mode), `docs/config.md`'s
  `bind_addr`/`bind_port`/`proxy_bind_addr` rows now state the empty/zero completion and its order,
  and `CHANGELOG.md` gained the user-visible entry naming the changed shapes **including the
  proxy-listener consequence**. Swept
  `grep -rn "failed to lookup address information\|Dashboard web UI starting" docs TODO.md
  CHANGELOG.md frp-core/src frps/src`: the remaining hits are this item's own historical
  measurements, the frpc admin-address one (`docs/developing.md:1151`, the client-admin table's
  `[webServer] addr = ""` row — `| "" | dials 127.0.0.1:7499 | … | connect :7499: failed to lookup
  address information |`; the separate `frpc reload | stop -c …` row is `:1098`), and the code/log
  sites themselves.
  (Other hits with the same phrase belong to *other* items' history, not to this item's sweep:
  `TODO.md` `:2339`/`:2360`, and `CHANGELOG.md` `:382`
  (`admin server failed: failed to lookup address information …`) — that one *is* a sweep hit too,
  but it is the frpc admin-address history the sentence above already accounts for.)
- [x] **`frps` has no `Log.Complete()`: an explicit empty `--log-level`/`--log-file` silences its
  **logging** (the listener still comes up), where Go falls back to `info`/`console`.** Go's `ServerConfig.Complete()` calls
  `c.Log.Complete()` (`pkg/config/v1/server.go:105`), which is
  `To = util.EmptyOr(To, "console")`, `Level = util.EmptyOr(Level, "info")`,
  `MaxDays = util.EmptyOr(MaxDays, 3)` (`pkg/config/v1/common.go:119-123`). frp-core's
  `ServerConfig::complete` (`frp-core/src/config/server.rs`) has no log completion and the serde
  defaults on `LogConfig` fire only when the key is **absent**, so an explicit empty string
  survives into `init_logging` (`frps/src/main.rs`), and `frps`'s CLI writes all three fields
  (`override_server_config`: `--log-file`, `--log-level`, `--log-max-days`). Measured (real Go
  v0.71.0 vs frp-rs on this branch, own free port, `[auth] token` set):
  * frp-rs `--log-level ""` → **0 bytes on stdout and 0 on stderr**, listener up on
    `127.0.0.1:19891`; frp-rs `--log-file ""` → the same; frp-rs with neither flag → its normal
    **7** `INFO` startup lines before any signal (1498 B; the run's 11-line / 2434 B total is
    reached only after the harness's SIGTERM appends 4 graceful-shutdown lines).
  * Go v0.71.0 `--log_level ""` → still logs its startup lines at `info` (3 lines; byte totals
    vary by run); the same for `--log_file ""` and for the no-flag control.
  Found while sweeping the CLI overrides for the completed-input hazard above (the sweep's first
  version wrongly called `log.*` "already correct"). **Pre-existing**, not a regression of that
  change; not fixed there because it is a behaviour change needing its own Go-binary rows.
  **Done-when:** add the `Log.Complete()` fill to `ServerConfig::complete` (empty `to` → `console`,
  empty `level` → `info`, zero `max_days` → 3, in Go's position at `server.go:105`) with a bounded
  spawn test per shape that asserts the server still logs, plus a Go-binary measurement row each for
  `--log-level ""`, `--log-file ""` and `--log-max-days 0`; absent values must keep the serde
  default, and `--log-format` has no Go completion (verify that before touching it).
  Done on `fix/log-complete` at `4c3112a` (based on `05d62c4`). `LogConfig::complete`
  (`frp-core/src/config/server.rs`) is the three `util.EmptyOr` fills; it is called from
  `ServerConfig::complete` as the **first** field completion (Go's slot: `server.go:105`, after
  `Auth.Complete()` at `:102`, before `Transport`/`WebServer`/`SSHTunnelGateway` at `:106-108`) and
  from `ClientConfig::complete_with_heartbeat_set` — the **sibling slot**, see the client note below.
  The raw CLI values are also treated as absent when empty (`resolve_log_level` /
  `resolve_log_file` in `frp-core/src/logging.rs`), because Go binds each flag to its own default
  (`pkg/config/flags.go:161-163`) so `--log_level ""` reaches `LogConfig.Complete()` as the zero
  value, not as a literal empty level.
  **Measured** (this box, 2026-09-28, Go v0.71.0 `/private/tmp/frp_0.71.0_darwin_arm64/frps`,
  base = clean `main` build, own CWD and own free port per case — Go's flags-only lane needs an
  **empty** CWD (a `frps.yaml` there would be discovered and win), while frp-rs's override lane needs
  a `./frps.toml` holding the bind/auth keys and **no** `[log]` section, because frp-rs has no
  flags-only mode: with an empty CWD it exits rc 1 printing `frps.toml: failed to read config file`
  (78 B stdout, 0 B stderr) — stdout and stderr redirected
  to **separate** files and counted in bytes **before any signal** — the totals after SIGTERM are
  reported separately because the graceful-shutdown lines land there; rc read from `wait` on the
  direct child, never through a pipe):
  * config-file lane (`-c`, Go YAML / frp-rs TOML, `[log]` values identical, all with
    `bindAddr`/`bind_port` + token): Go is 273 B stdout / 0 B stderr / **3** INFO records / listener
    up in **all five** shapes (a `grep -c .` over the raw stream says 4 — the trailing ANSI reset
    counts as a line; the record count is 3); frp-rs **base** is 0 B/0 B for `level = ""` (listener
    up), 1498 B/0 B for `absent` and for `to = ""` (that shape was **never** silent: `resolve_log_file`
    already mapped an empty *config* value to console — the earlier "0 B/0 B and a file created" row
    here was wrong and is corrected), and `maxDays = 0` is 1498 B/0 B **with retention disabled**;
    frp-rs **head** is 1498 B/0 B and 7 records in every shape, with no log file created.
  * flags-only lane (`frps --bind-port <free>` + one log flag; own **empty** CWD for Go, own
    `./frps.toml` without a `[log]` section for frp-rs, see the preamble): Go `--log-level ""`
    / `--log-file ""` / `--log-max-days 0` each 282 B stdout / 0 B stderr / 3 INFO records / listener
    up (`--log-format ""` is `Error: unknown flag: --log-format` + usage, 2368 B **stderr**, rc 1);
    frp-rs **base** `--log-level ""` → 0 B/0 B and `--log-file ""` → 0 B/0 B **plus a
    `frps.log.2026-09-27` written in the CWD** (2434 B after SIGTERM), `--log-max-days 0` →
    1498 B/0 B with cleanup disabled; frp-rs **head** all three → 1498 B stdout / 0 B stderr /
    7 records / listener up / no file created. Absent values are unchanged (1498 B before and after).
  * **Go's retention field has no startup observable at all**, which is why the rows below are an
    frp-rs-local aged-file fixture: `clearFiles()` has exactly one caller — `rotate()`
    (`golib@v0.8.2/log/output_rotatefile.go:103`) — reached only from `dailyRotate`'s 0:00 boundary
    (`Init` `:60-70` starts `go fw.dailyRotate()` at `:68`; `:178-199`, `if nextHour.Hour() == 0` at
    `:193` → `fw.Rotate()` at `:194`), and `pkg/util/log/log.go:53-58` only constructs the writer and
    calls `Init()`. So the Go `--log-max-days 0` row (282 B / 3 records) cannot discriminate this
    field, and frp-rs's **synchronous startup sweep is itself a pre-existing timing divergence** from
    Go (Go sweeps at midnight only). `clearFiles()` returns early for `Mode == Daily && MaxDays <= 0`
    (`:242-244`), so zero/negative disabling cleanup is Go-true.
  * `--log-max-days 0` / `[log] max_days = 0` has a **synchronous** observable on frp-rs that the byte
    rows above cannot show: `init_tracing` runs `cleanup_expired_logs` at startup when `max_days > 0`.
    With `[log] to = "logs/frps.log"` and a backdated `logs/frps.log.2020-01-01` (mtime on the epoch):

    | shape | `d3a16d2` (pre-this-round) | head |
    |---|---|---|
    | no flag (defaults to 3) | deleted | deleted |
    | `--log-max-days 0` (CLI) | **SURVIVED** | deleted |
    | `--log-max-days=-1` (CLI) | survived | survived (only the zero value is filtered) |
    | `[log] max_days = 0` (file) | deleted | deleted |

    i.e. the config half was fixed by the first commit and the **CLI** half was not: `frps`/`frpc`
    read `cli.log_max_days.or(cfg.log.max_days)`, and the flag's `Some(0)` beat the `3` that
    `LogConfig::complete` had just written. Both binaries now go through
    `logging::resolve_log_max_days`, which filters the CLI zero value (Go's `util.EmptyOr(0, 3)`,
    `pkg/config/flags.go:163` + `common.go:122`) and passes a negative value through.
  Pins: `log_config_absent_keys_keep_serde_defaults_and_empty_ones_are_filled`,
  `log_config_completion_leaves_format_alone`,
  `server_and_client_config_completion_both_fill_the_log_section`,
  `resolve_log_level_treats_empty_cli_value_as_absent`,
  `resolve_log_file_treats_empty_cli_value_as_absent`,
  `resolve_log_max_days_treats_zero_cli_value_as_absent`,
  `rust_log_outranks_the_configured_level` +
  `parse_level_maps_known_and_unknown` (`frp-core/src/config/tests.rs`,
  `frp-core/src/logging.rs`), and the bounded spawn file `frps/tests/log_completion.rs`
  (5 tests; **0 passed / 5 failed** against a pre-fix `FRPS_BIN` — and **4 passed / 1 failed**
  against `d3a16d2`, the single failure being the CLI `--log-max-days 0` arm, which is what isolates
  this round's fix — all five green at the head).
  **A recorded divergence: an empty `--log-level ""` does not mean the same thing on the two
  binaries when the file sets a non-default `level`.** The fall-through rule is one rule
  (`resolve_log_level` treats `Some("")` as *not supplied*), but the value it falls through to
  differs, because only `frps` overlays its CLI flags onto the loaded config: `frps` writes the empty
  flag into `[log] level` and completion fills it to `"info"`, while `frpc` (which never overlays its
  CLI flags) keeps the file's value. Measured at the head with `[log] level = "warn"` +
  `--log-level ""` (own dir and free port, both streams separate, 3 s settle, pre-signal, raw-stream
  bytes): `frps` → **1498 B / 7 records, all `INFO`, 0 `WARN`**, listener up; `frpc` → **0 `INFO`
  records**, and the composition of what it does log depends on the client's `login_fail_exit`
  (default `true`) and on whether a server is live — all three measured with `[log] level = "warn"`,
  one tcp proxy, each identical with and without `--log-level ""`: live server (proxy registers)
  **478 B / 1 record / 1 `WARN`** (the TLS-verification-disabled banner); no server with
  `login_fail_exit = false` **624 B / 2 records / 2 `WARN`** (retries); no server with no
  `login_fail_exit` line, i.e. the default `true` **569 B / 2 records / 1 `WARN` (login failed) +
  1 `ERROR` (`frpc error: …`)**, because the client gives up instead of retrying. Controls: `frps`
  with `warn` and no flag → 0 B / 0 records (the empty flag is what raises it to `info`); with no
  `[log] level` in the file both resolve to `"info"`. **The pair to quote is `0 INFO`; the
  composition is a property of the shape, so every carrier names its shape.** Filed as its own item
  below — the fix would be `override_server_config` skipping an empty `--log-level`, i.e. a product
  call about which lane frps mirrors, not a completion bug.
  **`--log-format` was verified and deliberately not touched**: Go v0.71.0's `LogConfig`
  (`pkg/config/v1/common.go:103-117`) has no `Format` field and the real binary refuses the flag
  (measurement above); frp-rs's `--log-format` is an extension and `resolve_log_format` already maps
  `""` → `"text"`.
  **The client sibling had the same hole and is fixed in the same commit**: Go's
  `ClientCommonConfig.Complete()` calls `c.Log.Complete()` (`pkg/config/v1/client.go:94`), and that
  path runs for every client load — `config.LoadClientConfigResult` → `result.Common.Complete()`
  (`pkg/config/load.go:392`), i.e. the `-c` lane too, not the server's flags-only exception. Measured
  on frpc against a live frps (own ports, both streams separate): base with
  `[log] to = "" level = "" maxDays = 0` (the level is what silences it) or `level = ""` alone in the
  config → **0 B/0 B with the TCP proxy listening**; base with `to = ""` alone → 2380 B / 10 records,
  i.e. the client's file half was already console (same as the server's, see the corrected row above);
  head → 2380 B stdout / 0 B stderr / 10 records in every shape, identical to the absent control.
  Carriers: `docs/config.md` `[log]` rows (`level`/`file`/`max_days` now state the completion and that
  an explicit empty/zero is filled; `format` says it is an frp-rs extension with no Go completion and
  the old "console (default, stderr)" slip is corrected to stdout), `CHANGELOG.md` under `### Fixed`,
  and the CI step `Run frps's log-completion spawn tests`
  (`cargo test -p frps --features dashboard --test log_completion`) — the fourth `frps` **target**
  (its third *test* target, after `cli_exit_codes` and `cli_completion`; the fourth is the bin unit
  target), which no lane executed before.
  Guards: **none moved.** `frps/tests/cli_exit_codes.rs` is untouched, so `env.FRPS_CLI_TESTS` stays
  `"27"` (`.github/workflows/ci.yml`, `-- --list` = 27) and `FRPC_TINY_CLI_TESTS` stays `"11"`
  (`-- --list` = 11; the default-feature frpc file lists 10). Gates at the head: fmt clean, clippy
  `-p frp-core -p frps -p frpc --all-targets --all-features -D warnings` clean, `cargo test -p
  frp-core --lib` 961/0, `cargo test -p frps` 0+6+27+4/0, `cargo test -p frpc` 8+25+10+34+7+1/0,
  tiny `cargo test -p frpc --no-default-features --features tiny --test cli_exit_codes` 11/0,
  `bash scripts/repo-health.sh` rc 0. `scripts/compat-test.sh` is **not relevant**: this is a
  config-completion change on the logging surface and moves no wire byte.
- [x] **P1 — An empty `--log-level ""` means `info` on `frps` and "the file's level" on `frpc`, so the
  two binaries disagree whenever the config sets a non-default `level`.** Found while closing the
  `Log.Complete()` item above and deliberately **not** fixed there (the reviewers classified it as a
  product call, and this item is the record of it). Only `frps` overlays its CLI flags onto the loaded
  config (`FrpsArgs::override_server_config` in `frp-core/src/cli.rs`); `frpc` does not, so on `frps`
  the empty flag is written into `[log] level` and `LogConfig::complete`
  (`frp-core/src/config/server.rs`) then fills it to `"info"`, while `frpc`'s resolver falls through
  to the file's value. Measured at `96f97e9` with `[log] level = "warn"` + `--log-level ""`, own dir
  and free port per case, both streams captured separately, 3 s settle, counts taken pre-signal,
  raw-stream bytes: `frps` → **1498 B stdout, 7 records, all `INFO`, 0 `WARN`**, listener up;
  `frpc` → **0 `INFO` records in all three shapes measured**, with the composition set by the client's
  `login_fail_exit` (default `true`) and by whether a server is live: **478 B / 1 record / 1 `WARN`**
  (live server, proxy registers — the TLS-verification-disabled banner), **624 B / 2 records /
  2 `WARN`** (no server, `login_fail_exit = false`, retries), **569 B / 2 records / 1 `WARN` + 1
  `ERROR`** (no server, no `login_fail_exit` line so the default `true` gives up). Each of the three is
  identical with and without `--log-level ""`. Controls in the same run: `frps` with the config's
  `warn` and **no** flag → 0 B / 0 records, i.e. the empty flag is what raises it; with **no**
  `[log] level` in the file both resolve to `"info"`, which is why the default-config paths agree.
  Each binary's outcome is defensible on its own (`frps`'s is Go's zero-value outcome for a flag bound
  to its own default, `pkg/config/flags.go:161`; on Go's client the flag does not exist on the run
  path at all — `--log_level` is registered only for the `frpc <type>` subcommands,
  `pkg/config/flags.go:161-163` via `cmd/frpc/sub/proxy.go:56`, and in SSH mode,
  `pkg/ssh/server.go:285`, so the Go binary answers `Error: unknown flag: --log_level`, rc 1, 1343 B
  stderr, with and without `-c`), and frp-rs's two lanes simply differ.
  **Done-when:** decide which lane `frps` mirrors and make the rule true on both — either
  `override_server_config` skips an **empty** `--log-level`/`--log-file`/`--log-max-days 0` (leaving
  the file's value, which aligns `frps` with `frpc` and with Go's `-c` lane) or `frpc` gains the
  overlay (aligning it with `frps` and Go's flags-only lane). Whichever is chosen needs a Go-binary
  row per lane (Go's flags-only `--log_level ""` → `info`; Go's `-c` with `[log] level: warm` and the
  flag ignored → `warn`), a spawn test per binary pinning the chosen outcome, and the
  `docs/config.md` `[log] level` row rewritten to one consequence-free sentence. Until then the
  divergence is stated in `docs/config.md`, in `resolve_log_level`'s doc comment
  (`frp-core/src/logging.rs`) and here.
  **Done (2026-10-01, at `4b9c9951` on `fix/cli-flag-binding`, PR #427).** The first branch of the
  Done-when: `FrpsArgs::override_server_config` now skips an **empty** `--log-level`/`--log-file`
  and a **zero** `--log-max-days`, so the file's `[log]` values survive instead of being completed
  to `info`. Measured post-fix with `[log] level = "warn"`: the implicit-config lane with
  `--log-level ""` → **0 `INFO`** records (was 11 pre-fix), `-c` with `--log-level ""` → 0 `INFO`,
  `--log-level info` → 11 `INFO`. That matches Go's `-c` lane, which discards the whole
  pflag-bound struct (`/tmp/frp-go-src/cmd/frps/root.go:67-83`: `--log-level ""`/`info`/`trace`
  all emit 0 records) and matches `frpc`. Pinned by
  `frp-core/src/cli.rs::log_flag_zero_values_do_not_override_the_config_file` (`frp-core/src/cli.rs:4496`)
  and `frps/tests/cli_completion.rs::cli_empty_log_level_keeps_the_config_files_level`
  (`frps/tests/cli_completion.rs:644`). Two adjacent divergences stay open and are filed at the end
  of this file: **R1** (`-c` plus a **non-empty** log flag is still honoured here, Go discards it)
  and **R2** (the implicit-config lane has no Go counterpart). `--log-format` keeps its
  write-through (**R3**).
  **Done (2026-10-01, at `5e2f2398`, PR #440).** The rest of the Done-when: the `docs/config.md`
  `[log]` rows now state what an explicitly supplied empty/zero *flag* means against Go's two lanes,
  per field, and the resolution-order list (`docs/config.md:1006-1012`) says an empty `--log-level ""`
  falls through to the file's value on both binaries. Both binaries carry spawn pins that assert the
  emitted records instead of an exit status: `frps/tests/log_completion.rs::
  cli_empty_log_level_does_not_raise_the_files_warn` uses `[log] level = "warn"` plus a written
  `[web_server.tls] enable = true`, so "inert-key `WARN` present, banner `INFO` absent" pins the level
  at exactly `warn`, with a third arm passing `--log-level info` as the banner's own control (the
  11-`INFO` figure in the paragraph above counts that arm's post-`SIGTERM` lines; 7 records precede
  the signal, `docs/config.md:84`);
  `::cli_empty_log_file_keeps_the_files_destination` requires the records to land in
  `logs/frps.log.<date>` and not on stdout; `::cli_zero_log_max_days_keeps_the_files_retention`
  requires a five-day-old rotation file to survive `--log-max-days 0` under `[log] max_days = 7` and to
  die under `--log-max-days 3`. `frpc/tests/log_completion.rs::
  cli_empty_log_level_does_not_raise_the_files_warn` is the client control (`login_fail_exit = false`,
  spelled `loginFailExit` in the test's TOML; against a closed port it makes attempt 1 log a `WARN`,
  and the test waits on that record), so a
  write-through `frpc` overlay — which does not exist today — is what would red it.
  `frp-core/src/cli.rs::cli::tests::log_flag_zero_values_do_not_override_the_config_file` gained the
  assertions it lacked (four `assert_eq!`s in two groups): the three
  zero values still parse as *supplied* (it is the overlay, not the parser, that treats them as
  absent), and `--log-max-days=-1` survives `complete()` — only the zero value is filtered. The
  `frpc` count guard is new (`.github/workflows/ci.yml:712` `expected=1`, in the step this PR adds);
  the `frps` step already carried the same three checks with `6` written into every count comparison
  and message (the `Running tests/…` grep and the failure header carry no count), so there the delta
  is the hoist to the single `expected=9` (`:921`) and the 6 → 9 move for the three spawn pins this
  PR adds. Each guard proves the target ran, that `-- --list` counted that
  many, and that the summary read `test result: ok. N passed; 0 failed`, with direction-naming
  `::error::` text — a cfg-disabled integration file prints `running 0 tests` /
  `ok. 0 passed; 0 failed` and exits 0, which a bare invocation cannot tell from success. The Go rows
  behind the prose (v0.71.0 `-c`: `--log_level ""` and `--log_file ""` leave the records as if the
  flag were omitted — the two `--log_file ""` rows carry the same three records, and with the port and
  the `-c` path held constant their bytes differ only in Go's per-record millisecond timestamps (an
  identical argv re-run differs the same way), so only the record set is claimed, not the byte total —
  while `--log_max_days 0` emits no
  comparable bytes at startup, so its retention effect is only observable later, through
  `golib@v0.8.2/log/output_rotatefile.go:103`; `cmd/frps/root.go:66-84` discards the pflag-bound
  struct; the flags-only lane completes the empty values via `util.EmptyOr`) are in the PR body and
  the commit messages. The old test name this PR retires,
  `max_days_zero_is_completed_to_three_on_the_cli_and_in_the_file`, becomes
  `max_days_zero_does_not_disable_cleanup_on_the_cli_or_in_the_file`
  (`frps/tests/log_completion.rs:927`). It stood at two sites outside this item: `TODO.md:4361` at
  base `fdb39c6b` (this PR's insertion moved the repaired text to `:4406`), repaired here, and
  `docs/history/development-log.md:84`, repaired in the devlog commit that follows this one.
- [x] **Two test-harness hazards: a feature swap that breaks the dashboard lane silently, and
  `FrpsHandle::start` orphaning its child on the panic path.**
  * **(a) `cargo test -p frps` and a clippy run that compiles `frps` replace `target/debug/frps`
    with the no-dashboard artifact** — the same path the dashboard tests resolve through `FRPS_BIN`
    (`frp-server/tests/common/mod.rs`) — and nothing in the resulting failure says so. Measured at
    the head of `fix/frps-empty-addr`: `grep -ac "Dashboard listening on" target/debug/frps` is `1`
    right after `cargo build -p frps --features dashboard`, `0` after `cargo test -p frps` (16 s),
    and `0` after `touch frps/src/main.rs && cargo clippy -p frps --all-targets --all-features`
    (18 s); the same marker through `strings target/debug/frps | grep -c "Dashboard listening on"`
    is `2 → 0` (the two hits are the plain and the TLS format string — same conclusion, the count is
    tool-dependent, so name the tool). A clippy run with nothing to rebuild leaves the previous
    artifact in place (measured: the fully cached gate run finished in 0.4 s and the marker stayed
    `1`). With the swapped binary, `cargo test -p frp-server --features dashboard --test
    dashboard_integration` reports **0 passed / 20 failed**, every test with
    `frps dashboard_port not ready: "port N not ready after 15s"` — and one such run at this head
    (46.54 s) left **17 orphaned `frps` children** (`PPID 1`, still `LISTEN`, until killed), i.e.
    the swap is exactly what produces hazard (b)'s orphan wave; the file's three
    `CapturedFrps`-based tests are among those 20 and their children were reaped (measured
    separately: the same forced failure grew the orphan count by 0 there). CI is safe only because
    its lane builds `frps --features dashboard` immediately before running
    (`.github/workflows/ci.yml`); the author hit the trap while producing this PR's measurements and
    both reviewers reported it in review.
  **Done-when:** make the failure self-explaining — e.g. `common::frps_binary()` verifies the
  resolved binary carries the dashboard listener and panics with "rebuild `frps --features
  dashboard`" when it does not — pinned by a test that asserts the message, with the build ordering
  also recorded where a local run reads it. Do not close it by making the dashboard tests skip when
  the feature is missing.
  * **(b) `FrpsHandle::start` can orphan its child.** It spawns `frps`, `.expect()`s the bind-port
    and dashboard-port waits (`frp-server/tests/common/mod.rs:733` and `:738` at this head), and
    only then constructs the handle whose `Drop` kills and reaps — so a panic in those waits leaves
    a live `frps` behind with `PPID 1` and its `TempDir` already removed. Reproduced **2/2** at the
    head of `fix/frps-empty-addr` with the real binary and the swapped (no-dashboard) `FRPS_BIN`:
    `cargo test -p frp-server --features dashboard --test dashboard_integration test_dashboard_healthz`
    (which selects `test_dashboard_healthz` and `test_dashboard_healthz_readiness`) failed both
    tests at `common/mod.rs:738` (`frps dashboard_port not ready`), and `ps` then showed two
    `/…/target/debug/frps -c /var/folders/…/frps.toml` processes with `PPID 1`, both still `LISTEN`
    on their bind ports (`lsof` count 2) until they were killed. The new `CapturedFrps` (same file)
    does **not** have the shape — it is constructed before any wait, and in the same forced-failure
    setup (two tests panicking against the same no-dashboard `FRPS_BIN`) the orphan count grew by
    **0**.
  **Done-when:** construct the kill-on-drop guard before the first wait in `FrpsHandle::start` (or
  kill in the `expect` path), with a test that forces the failure and asserts no child outlives the
  test; and sweep the strays earlier runs left (done at this head — batches of ~65, 34 and 2
  children killed, 0 `frps` processes and no listeners remaining — because a leaked child also
  holds its port for the next run).
  Done on `fix/harness-hazards` at `6b7c892` (based on `97a8d7e`). (a)
  `common::frps_binary()` now scans the artifact it resolved for
  `Dashboard listening on` and panics with the rebuild instruction when it is absent;
  `frp-server/tests/frps_binary_guard.rs` pins the **message** (the rebuild literal, the path it
  checked, the marker name), the silent unreadable/missing-binary branch, and two positive controls
  (a file carrying the TLS-format-string marker must pass; this lane's real artifact must exist and
  carry the marker). The check is compiled only when the test target has the `dashboard` feature,
  compiles and spawns nothing, and no test skips. Marker flip re-measured here with both tools
  named: `grep -ac "Dashboard listening on" target/debug/frps` **1 → 0** and
  `strings target/debug/frps | grep -c "Dashboard listening on"` **2 → 0** across a
  `cargo test -p frps`, and a plain `cargo build -p frps` flips it too — **even the 0.16 s cached
  no-op**; a clippy run does not (measured: `touch frps/src/main.rs && cargo clippy -p frps
  --all-targets --all-features` left the artifact byte-identical, same size and mtime). On the
  **fixed** head a swapped artifact fails fast instead of waiting out 20 × 15 s: `0 passed; 20
  failed`, every failure the guard's message, `finished in 1.58 s` (8.5 s wall including the
  compile of the edited test target) and **0 children** left. For contrast, the **pre-fix tree**
  (`97a8d7e`) reported the same `0 passed; 20 failed` with `frps dashboard_port not ready` after
  **45.6 s** and left the 17 children below. Cost measured before caching: one full read+scan is
  **28.83 ms** for the dashboard artifact this lane resolves (81,444,248 bytes) and 61.45 ms for
  the 71,033,304-byte no-dashboard one (cold, just after a link) — the scan stops at the first hit,
  so where the marker sits matters as much as size; with 46 spawn sites across 5 test binaries the
  verdict is cached per process, keyed by the exact path plus `(len, mtime)`, and no shipped test
  can observe that cache (every `cargo test` binary is a fresh process — stated in the code). The
  residual that a swap preserving both is invisible is stated in the code. Ordering recorded in
  `docs/developing.md` § Testing → “The `dashboard` lane: build ordering” and in the `frps_binary`
  doc comment. (b) `FrpsHandle::start_with_timeout` constructs the kill-on-drop guard before the
  first wait; `frp-server/tests/frps_handle_orphan.rs` forces the dashboard wait to fail
  (TEST-NET-1 dashboard address + `[web_server]` credentials + `[auth].token`, so frps stays alive
  holding the control port), asserts the child it observed bound is gone and the port rebindable,
  and names + reaps any survivor with pid and command before failing. Pre-fix wave re-measured here,
  delta-scoped: **17** children at `PPID 1` with **20** listeners after one swapped-artifact lane
  run, and **+0** for the three `CapturedFrps` tests as the control. Both new tests were shown red
  on the reverted guard (a) / reverted ordering (b) and green after, leaving 0 strays
  (worktree-scoped census). Sweep: `frp-server/tests/common/mod.rs` has exactly two spawn sites —
  `FrpsHandle::start` (fixed) and `CapturedFrps::start` (already guard-first with no wait inside,
  its +0 control measured); the same shape in `frp-server/tests/v2_quic_r2r.rs`
  `FrpsProcess::start` is fixed as well (verified by running the test, which skips without an
  `frpc`). The `cli_exit_codes` files were not touched, so `env.FRPS_CLI_TESTS` /
  `env.FRPC_TINY_CLI_TESTS` stay at 16 / 11 (both re-measured with the guard's own `-- --list`
  pattern). `CHANGELOG.md` gets no entry: test-harness only, no user-visible behaviour. The same
  shape elsewhere in the tree is **not** closed by this item — it has its own item immediately
  below.
- [x] **`frp-server/tests/reload_integration.rs` has seven unguarded spawn sites and can orphan its children on a panic path.**
  Done on `fix/reload-guards` at `d151fda` (based on `095b83a`, #396), two commits:
  `f31a4c9` the guard + its test, `d151fda` the residual sweep; the review fix in `(e)`
  landed after both, so the branch head is one commit later.
  Evidence: `.spawn()` at `:262`, `:272`, `:504`, `:523`, `:741`, `:750`, `:781` (frps/frpc pairs
  plus one more frps). None is wrapped in a kill-on-drop guard — the children are killed by explicit
  `kill()`/`wait()` calls at the end of each test body (`:355-358`, `:635-638`, `:767-768`,
  `:802-805`) — so any panic above those lines leaves the child running with `PPID 1` and its port
  held. Constructed during review of the fix above, on `fix/harness-hazards` at `6b7c892`: with
  `FRPC_BIN` pointing at a mode-644 file, `workspace_bin`'s `.exists()` check passes and the
  `Command::spawn` at `:272` fails, so the `.expect(..)` at `:273` panics, the cleanup at `:355`
  never runs, and the already-started `frps` survived at `PPID 1` holding its port; the control
  (a working `frpc`) passed with 0 strays. The
  shape that closes it is already in `frp-server/tests/common/mod.rs`: `FrpsHandle` and
  `CapturedFrps` construct the guard before the first wait and their `Drop` kills **and** reaps.
  Same class, found in the same sweep and also unguarded: `frpc/tests/admin_cli.rs`
  `expect_one_connection` (spawn at `:193`) panics `oracle accept failed` at `:207` with the child
  still alive — its timeout path at `:210` does kill — and the `try_wait().expect(..)` panic paths
  in `frps/tests/cli_exit_codes.rs` (`:87`, `:258`, `:284`), `frpc/tests/cli_exit_codes.rs` (`:96`)
  and `frpc/tests/admin_cli.rs` (`:135`) have a live child and no kill-on-drop.
  **Done-when:** every spawn in `reload_integration.rs` is wrapped in a kill-on-drop guard
  constructed before the first wait (a `common` helper or a local RAII type), with a test that
  forces a spawn or wait failure and asserts no child outlives the test — in the style of
  `frp-server/tests/frps_handle_orphan.rs` — or the file is deleted in favour of `common`'s
  handles; and the admin_cli/cli_exit_codes residuals are either guarded or recorded as deliberate.
  **Done (2026-09-28, at `d151fda`).** (a) `frp-server/tests/common/mod.rs` gains
  `ChildGuard::new(child)`: constructed on the line after `spawn()` returns and before the first
  wait, `Drop` kills **and** reaps, idempotent with an explicit `kill_and_reap()`, and its doc
  states what it does not cover (`Drop` never runs on `abort`; it signals the direct child only).
  All seven spawn sites (`:259`, `:271`, `:504`, `:524`, `:744`, `:755`, `:787` at this head) are
  wrapped; the end-of-body `kill()`/`wait()` pairs became `kill_and_reap()`. (b) The new test
  `reload_integration.rs::spawn_failure_does_not_orphan_the_child_started_before_it` forces the
  item's own shape — a mode-644 copy of the resolved `frpc`, so `.exists()` passes and `spawn`
  fails `EACCES` — inside `catch_unwind` so the guard's `Drop` runs during the unwind, then
  asserts the observed `frps` pid is gone (`kill -0`), its port is not accepting and is
  rebindable, killing a regression's survivor by pid before failing (style:
  `frp-server/tests/frps_handle_orphan.rs`, which observes a `JoinError` instead because its
  failing wait is async). (c) Measured from the shell after the harness exited, both arms the
  item's shape and nothing else (a temporary target, deleted before the commit): unguarded
  `pgrep -x frps` **0 → 1**, `ps` showing `PPID 1` (`38280 1 /tmp/rg-target/debug/frps …`) and
  `lsof` the port still `LISTEN`; guarded **0 → 0**, port free; control arm proves the shape is
  `EACCES` on a real binary. (d) Residuals **guarded**, not recorded: the `try_wait().expect(..)`
  panic paths in `frps/tests/cli_exit_codes.rs` (item `:87`/`:258`/`:284`) and
  `frpc/tests/cli_exit_codes.rs` (item `:96`) now go through a local `try_wait_or_kill` that kills
  + reaps on the error path before panicking — the item's allowed "kill in the expect path" form —
  as do `frpc/tests/admin_cli.rs`'s `wait_with_timeout` and `expect_one_connection` (its
  `oracle accept failed` arm now kills first; the timeout arm already did), plus two same-class
  `wait_with_timeout` sites not in the item (`frpc/tests/cli_inputs.rs`,
  `frpc/tests/cli_persistent_flags.rs`). At this head the `try_wait_or_kill` call
  sites are `frps/tests/cli_exit_codes.rs:118,441,467` and `frpc/tests/cli_exit_codes.rs:132`, and
  the wait helpers' calls are `frpc/tests/admin_cli.rs:152`, `frpc/tests/cli_inputs.rs:238`,
  `frpc/tests/cli_persistent_flags.rs:207` — cite those, not the pre-helper lines, whose numbers
  move whenever a helper is inserted above them. The one exception, recorded as deliberate:
  `frpc/tests/admin_cli.rs` `connections_after_exit`'s `oracle accept failed` runs *after* the
  child exited, so no live child is in scope. (e) Review fix F1: the new test **fails closed** —
  where its three siblings `return` when the binaries are absent, it `panic!`s with the build
  instruction, because it is the only artifact pinning this file's guards and a skip would report
  `ok` while asserting nothing (measured: at `9ba609a` with `FRPS_BIN`/`FRPC_BIN` at nonexistent
  paths `1 passed … finished in 0.00s`; after the fix `0 passed; 1 failed`, rc 101). No test was
  added or removed in a guarded lane: `env.FRPS_CLI_TESTS` stays **27** and
  `env.FRPC_TINY_CLI_TESTS` stays **11**, both re-measured with the guard's own `-- --list`
  pattern. No `CHANGELOG.md` entry: test-harness only.
  `scripts/compat-test.sh` is not relevant (no wire surface). Full evidence, including the orphan
  table and a "least sure" section: `/tmp/reload-guards-report.md`.
- [x] **`scripts/compat-test.sh` leaks its children: a full run left 83 reparented Go processes, and
  the first reviewer measured 167 in one run.**
  This is the same class as the two items above (`TODO.md`'s "Two test-harness hazards" and the
  `reload_integration.rs` orphan item) but in `scripts/`, **outside the test harnesses those items
  swept**.
  Measured here 2026-09-28, immediately after a green `bash scripts/compat-test.sh` (86 passed,
  0 failed, rc 0): `pgrep -x frps | wc -l` → **33**, `pgrep -x frpc | wc -l` → **50** (**83** total),
  every one with `PPID 1` and every one a `/tmp/frp_0.71.0_darwin_arm64/{frps,frpc} -c
  /tmp/frp-compat-test/<scenario>/…` process — i.e. the harness's **Go** children, still holding
  their listeners. All 83 were reaped by explicit pid (matched on the
  `/tmp/frp-compat-test/` and Go-binary path in their command line, never by name alone). The first
  reviewer's full run left **167** reparented Go processes, reaped the same way. A third piece of
  evidence, from CI rather than a local run: **#397's** failed Cross-Compat run had the runner
  terminate **two dozen** orphans.
  The script's own cleanup is `cleanup()` (`scripts/compat-test.sh:164`) and `cleanup_pids()` (`scripts/lib/compat-stray-guard.sh:57`), a
  `kill` over a `PIDS` list plus a bounded wait and `kill -9`; the leak is the paths that do not
  reach it — a `run_go` background child that has already been reparented when the trap runs, or a
  scenario that aborts between spawn and `track_pid`.
  **Done-when:** a green full run leaves `pgrep -x frps` and `pgrep -x frpc` at **0** afterwards, by
  the script's own means (e.g. a process-group kill per scenario, or a `pkill`-free pid-file sweep
  over the scenario's own children) rather than by hand, pinned by a check that counts strays after
  a full run and fails when the count is non-zero. Do **not** close it with `pkill -x frps`: the
  repository's stray rules forbid name-only kills.
  **Done (2026-09-30, at `10a86d3a` on `fix/test-harness-strays`, based on `971e0fa0`).** One
  commit, `10a86d3a` "fix(compat): exec the Go servers so tracked pids are the servers". (a) Root
  cause, seen in vivo: `run_go()` (`scripts/compat-test.sh:137`) is a shell function, so each
  backgrounded `run_go … &` call forked a **subshell**; `track_pid $!` recorded that wrapper
  (`bash`) and `cleanup_pids` killed only it, leaving the real Go servers reparented — the
  before-census's Go children carried wrapper pids as `PPID` (17046/17091/17230, sampled while
  the run was still alive; once the wrappers exit and the script is gone the orphans reparent
  to `PPID 1`, which is the census the item above records) while the Rust
  children's `PPID` was the main script. Fixed by `exec`ing inside `run_go`
  (`scripts/compat-test.sh:137-141`), with the invariant stated in the comment above it (`:135-136`):
  all 90 call sites were audited and every one is backgrounded, so `exec` cannot replace the script
  shell. (b) The done-when asked for the script's own means and forbade name-only kills: the new
  pkill-free `scenario_strays` (`scripts/lib/compat-stray-guard.sh:90`) + `assert_no_strays` (`:150`) match a process name **and**
  the run's own `$TEST_DIR/` prefix, subtract a baseline captured at `:143`, print `pid ppid command`
  for each survivor, reap by those exact pids and return non-zero; the `EXIT` trap (`scripts/compat-test.sh:188`) runs
  `cleanup_pids` and lets the guard set the status. (c) Measured with
  `bash scripts/compat-test.sh --ci` (the `GO_FRP_V2=1` this recipe first carried was
  **inert** — V2 is gated by `ensure_go_frp_v2` on the Go binaries being present,
  `scripts/compat-test.sh:149-161`, and the workflow no longer sets it): **before** (pristine
  `971e0fa0`) `86 passed,
  0 failed`, rc 0, 3 m 23 s, and then `pgrep -x frps` = **33** / `pgrep -x frpc` = **50** (**83**
  strays, every one `PPID 1`, every one `/tmp/frp_0.71.0_darwin_arm64/{frps,frpc} -c
  /tmp/frp-compat-test/<scenario>/…`); **after** `86 passed, 0 failed`, rc 0, 3 m 30 s,
  `frps` = **0** / `frpc` = **0**, zero guard errors in the log. (d) Teeth: deleting the single
  `exec` makes `--test go-to-rust-tcp-plain` exit 1 and report
  `  30478     1 /tmp/frp_0.71.0_darwin_arm64/frpc -c /tmp/frp-compat-test/go-to-rust-tcp-plain/frpc.toml`;
  with `exec` the same filter exits 0. (e) Gates: `bash -n scripts/compat-test.sh` ok; the
  `-- --list` inventory is still **86**, so the "86 scenarios" figures at `docs/architecture.md:186`
  and `docs/developing.md:688` stay true; `cargo fmt --all -- --check` rc 0,
  `RUSTFLAGS="-D warnings" cargo clippy --workspace --all-targets --all-features` rc 0,
  `bash scripts/repo-health.sh` → `RESULT: invariants hold`. No `CHANGELOG.md` entry: developer
  script only, matching the #415/#416 repo-health precedent — the suite's scenario count, wire
  surface and CLI are unchanged. Residue filed, not fixed: the XTCP helper's pre-existing
  `pkill -f "frpc -c"` / `pkill -f "frps -c"` (`scripts/compat-test.sh:4343-4344`, inside
  `run_xtcp_test` at `:4331`) — pattern kills of the class this item forbade for its own children.
- [x] **`frps/tests/log_completion.rs` is a load-dependent flake: the child never writes its log
  file inside the readiness window.**
  Found by the first reviewer on this branch (the file is **outside** that change's diff, and it
  landed in **#396**, the `log_completion` step): **2 of 7** runs failed, panicking at
  `frps/tests/log_completion.rs:502` — the first arms of
  `max_days_zero_does_not_disable_cleanup_on_the_cli_or_in_the_file` (named
  `max_days_zero_is_completed_to_three_on_the_cli_and_in_the_file` when the failure was observed),
  whose failure text is
  `aged_file_survives`'s readiness panic (`:465-496` on the pre-fix tree; `:513`/`:524` after
  the fix below: *"no fresh `logs/frps.log.<date>` was written
  within {READY_TIMEOUT:?}, so the child never reached the appender"*). So the atomicity that test
  needs — a backdated `logs/frps.log.2020-01-01` plus a *fresh* daily file written by the child — is
  racy under load, and the assertion that then fails is about **retention**, reported as if the
  retention decision were wrong.
  **Not reproduced here:** 7/7 passes with `--exact --nocapture` on an idle host, and 5/5 further
  passes running the whole file under four `yes` processes of CPU load (12 runs, 0 failures). The
  reviewer's 2/7 is the evidence; this note records the non-reproduction rather than disputing it.
  **Done-when:** the readiness wait is made deterministic (e.g. wait for the appender's own line, or
  retry the aged-file arm) or the timeout is raised with the load recipe named, pinned by a looped
  run under load — with the CI lane's own guard literal (`log_completion`'s step counts **5** in
  `.github/workflows/ci.yml`, not one of the two `env.*_CLI_TESTS` values) moved in the same commit
  if tests are added or removed.
  **Done (2026-09-30, at `58812ebf` on `fix/test-harness-strays`, based on `971e0fa0`).** One
  commit, `58812ebf` "fix(tests): wait for the appender's own record in log_completion". (a) The
  item's repro, re-run here: 10 sequential
  `cargo test -p frps --features dashboard --test log_completion` at load average 39–41 from sibling
  builds → **8 pass, 2 fail**, panicking at `frps/tests/log_completion.rs:539` (the config-file
  retention arm) and `:502` (the control no-flag arm); the baseline clean run was `5 passed` in
  3.24 s. (b) Root cause, exactly as the item suspected: the readiness wait proved only that a fresh
  `logs/frps.log.<date>` *existed*, and `tracing_appender::rolling::daily` creates that file at
  `frp-core/src/logging.rs:378` **before** `cleanup_expired_logs` runs at `:401-402`, so the
  retention assertion could be read before the retention decision — the same defect in both arms.
  (c) Fix: the wait is now for the appender's **own record** — `fresh_log_reached_appender`
  (`frps/tests/log_completion.rs:485`) requires the fresh file's contents to contain
  `STARTUP_MARKER` (`:91`, the first line `frps` emits after `init_tracing` returns;
  `frps/src/main.rs:461`, `init_logging` at `:444`), and `aged_file_survives` (`:501-537`) fails fast with
  `{tag}: frps exited ({status}) before the appender recorded {STARTUP_MARKER:?} in …` instead of
  waiting out the full `READY_TIMEOUT` when the child dies first. (d) Pin + teeth: the new test
  `readiness_gate_needs_the_appenders_own_record` (`:605`) requires that an empty dir and a dir
  holding only an old-dated file do **not** satisfy the gate (`:614`) while a file carrying the
  marker does (`:644`); the two stated mutations are an existence-only predicate (reds the first
  assertion) and dropping the aged-file exclusion (reds the second). (e) The CI lane's own guard
  literal moved 5 → **6** in the same commit (`.github/workflows/ci.yml:472-473`, `:476-478`, `:480`,
  with the guard's success line at `:486` and the prose at `:453`/`:459`)
  after the step's own `-- --list` counted 6; `env.FRPS_CLI_TESTS` / `env.FRPC_TINY_CLI_TESTS` are
  untouched. No `CHANGELOG.md` entry: test-harness only, as the sibling items above (and as #396,
  which introduced this file). Residue filed, not fixed: `frpc/tests/warn_delivery.rs` — measured
  here, it does **not** read a rotation file (its contract at `:52-57` is the two captured streams),
  so this item's fix does not apply to it; what it shares is a fixed settle: `SETTLE = 500 ms`
  (`:92-94`) is slept at `:214` after `wait_for_marker` (`:219` defines it; the call is `:213`)
  sees the startup marker, and only
  then are the exact per-stream counts snapshotted — the same class of load-dependent assumption,
  never re-measured under load (8 tests in that file).
- [x] **`frpc`'s eight single-proxy subcommands reject `-c`/`--config`, which Go accepts and
  ignores.** Go's `-c` is a persistent rootCmd flag, so every subcommand parses it; the single-proxy
  commands simply never read the value. frp-rs's bpaf parsers for `tcp`/`udp`/`http`/`https`/`stcp`/
  `xtcp`/`sudp`/`tcpmux` do not define it.
  * Measured: with a proxy name supplied so Go gets past its own validation,
    `frpc tcp --local-port 5 --remote-port 6 --proxy-name x -c noweb.toml` → Go v0.71.0 starts the
    single proxy (killed by this measurement after 3 s, `try to connect to server...` on stdout);
    frp-rs exits 1 with ``Error: `-c` is not expected in this context``. The same holds for `udp`.
    Dropping `-c` from the frp-rs argv makes both behave the same, so the flag is the only
    difference.
  * Three further argv shapes are the same "what persists into which subparser" question and are
    recorded in `docs/developing.md` § CLI inputs rather than fixed: `status -c
    --strict-config=false -c p7498.toml` (Go rc 1 dialling 7498, frp-rs ``-c` requires an
    argument`), `status -c p7498.toml -- -c p7499.toml` (Go rc 1 dialling 7498, frp-rs
    `` `-c` is not expected``) and `status -c p7498.toml --config-dir cDir` (Go rc 1 dialling 7498,
    frp-rs `` `--config-dir` is not expected``). All measured at the head of
    `fix/frpc-cli-inputs` against Go v0.71.0.
  **Done-when:** accept `-c`/`--config` (and, to be Go-faithful, the other persistent root flags,
  including `--config-dir`, and `-`-prefixed values after `-c`) on the eight single-proxy parsers
  and the admin subcommands and ignore the file, or record each refusal as a deliberate divergence
  in `docs/developing.md` § CLI inputs with these measurements. The `-c` last-wins work above covers
  the **five** config-consuming parsers (`run`, `verify`, `reload`, `status`, `stop`) — that wording
  must not be read as covering these shapes or those eight subcommands. No sha.
  **Done (2026-09-26, at the head of `fix/frpc-proxy-persistent-flags`).** All five persistent
  rootCmd flags (`-c`/`--config`, `--config-dir`, `--strict-config`, `--allow-unsafe`,
  `-v`/`--version`) are registered on the twelve `frpc` subcommand parsers and dropped; of the three
  recorded shapes, two are matched and one is recorded as a divergence of a different rule.
  * **What was measured before implementing.** Go frp v0.71.0 darwin/arm64, a loopback probe
    listener on the command's `--server-port` (single-proxy) or on the `-c` config's
    `[webServer] port` (admin), a fixed proxy name so Go passes its own validation, and every child
    bounded (start, observe 3 s, SIGTERM, SIGKILL, reap). Appending any of `-c noweb.toml`,
    `--config noweb.toml`, `--config-dir cDir` (present or missing), `-c a -c b`,
    `-c --strict-config=false`, `-c missing.toml`, `--strict-config`/`--strict-config=false`,
    `--allow-unsafe TokenSourceExec`, `--version`, or a repetition of any of them — to `tcp`,
    `https` and `tcpmux` (three different local parsers) reaches `try to connect to server...` and
    connects on Go, byte-identical in observable to the same argv with the flag removed. frp-rs
    exited 1 with ``Error: `-c` is not expected in this context`` (and the analogous message for
    each other flag) before this change. The admin commands behave the same for
    `--config-dir`/`--allow-unsafe`/`--version`: `status -c p7498.toml --config-dir cDir` dials
    17498 on Go, was refused here, and dials 17498 now; `verify -c p7498.toml --config-dir cDir
    --allow-unsafe X --version` is rc 0 on Go and is rc 0 now.
  * **Shapes 1 and 3 are matched.** `status -c --strict-config=false -c p7498.toml` dials 17498 on
    both — pflag consumes the dash-shaped token as `-c`'s **value**, then the later `-c` overwrites
    it. bpaf classifies tokens first and only refuses the ones it reads as flags (`--long`, `-x`,
    `-c`, `-a=b`; measured at the base head it already took `-foo.toml`/`-nonexistent.toml`/`-=v`
    as values — `split_os_argument`, `bpaf-0.9.27/src/arg.rs:118-215`, then `disambiguate_short`,
    `bpaf-0.9.27/src/args.rs:183-250`; `State::take_arg` at `:670-694` takes only
    `Word`/`ArgWord`), so `rewrite_config_dash_values` attaches exactly the config-selecting
    occurrences (`-c`, `--config`, `--config-dir`, `--config_dir`) before bpaf sees argv; it stops
    at the first real `--`. The rewrite was frpc-only at that head — the item was frpc-scoped; the
    frps half was measured and filed as its own item, now fixed by making the rewrite a shared pass
    (the `frps` half item below).
  * **Shape 2 stays divergent, with its measurement.** `status -c p7498.toml -- -c p7499.toml`
    dials 7498 on Go (everything after `--` is positional and ignored) and is rc 1 `` `-c` is not
    expected in this context`` here. It is a *positional-args* rule, not a persistent-flag one: Go
    ignores positional args on every `frpc` subcommand — measured, `status extra` loads
    `./frpc.ini` and `tcp … extra` starts the proxy — while frp-rs refuses a leftover token with or
    without `--`. It is not half-fixed, because accepting only the `--` form is not Go-faithful and
    accepting bare words would swallow unknown flags Go rejects (`tcp -c -- -foo` is
    `unknown shorthand flag: 'f' in -foo`, rc 1). The rewrite adds one instance of the same rule:
    when the value taken for `-c` is itself flag-shaped, the flag's own argument is left behind as a
    positional — measured, `frpc tcp … -c --config-dir cDir` starts on Go and is rc 1
    `` `cDir` is not expected`` here, `frpc tcp … -c --strict-config false` starts on Go and is
    rc 1 `` `false` is not expected`` here. Recorded in `docs/developing.md` § CLI inputs.
  * **Pins.** `frpc/tests/cli_persistent_flags.rs` (7 tests) runs the real binary: all eight
    commands with all five flags appended reach the probe port; repeated flags; the dash-shaped
    value on `status`; `--config-dir` ignored by `status`/`reload`/`stop` (a second probe on the
    directory's own config port must stay silent); `verify` rc 0 with the flags; dangling `-c` and
    `--strict-config=foo` still refused; and the positional divergence pinned. Red at the base head
    (source reverted, test file kept): **6 of 7 fail** — the positional pin passes on both trees by
    design. Parser-level tests in `frp-core/src/cli.rs` cover all eight parsers, repetition, the
    strict-config value grammar, the `tcp --help` listing and the rewrite's exact scope.
  * **Carriers.** `CHANGELOG.md` (Unreleased → Fixed, user-visible argv change);
    `docs/developing.md` § CLI inputs gained the persistent-flag section and the `--flag=<bool>`
    section's recorded `--version`/`--allow-unsafe`/`--config-dir` divergences are marked matched.
    No sha.
- [x] **The `frps` half of the `-c <dash-value>` rule: Go's pflag consumes a `-`-prefixed token as
  `-c`'s value, frp-rs's `frps` parser does not.** `parse_frps_args` was untouched by `TODO.md:2173`
  (frpc-only, as the #378 `-c` last-wins work was). Measured on Go frps v0.71.0 darwin/arm64 and
  this head's `frps`, every child bounded:
  * `frps -c --strict-config=false` → Go rc 1 `open --strict-config=false: no such file or
    directory`; frp-rs rc 1 `` `-c` requires an argument `FILE` ``.
  * `frps -c -x` → Go rc 1 `open -x: no such file or directory`; frp-rs rc 1 `` `-c` requires an
    argument `FILE`, got a flag `-x`, try `-c=-x` to use it as an argument ``.
  * `frps verify -c --strict-config=false` → Go rc 1 `open --strict-config=false: no such file or
    directory` (Go has `frps verify`; frp-rs did not at this head — its own item below, **now
    closed**, and the flip this row predicted is in that item's Done block); frp-rs rc 1
    `` `-c` requires an argument `FILE` `` because the `-c` failure is reported before the
    unknown-command one.
  * A control that is a *different* divergence: `frps --config-dir --strict-config=false` → Go rc 1
    `unknown flag: --config-dir` (Go frps has no such flag); frp-rs rc 1 `` `--config-dir` requires
    an argument `DIR` `` (frp-rs extension flag, recorded in `docs/developing.md` § CLI exit codes).
  **Done-when:** apply `rewrite_config_dash_values` to `parse_frps_args` (or lift it into a shared
  pre-parse pass used by both binaries) and pin the three `-c` rows against Go v0.71.0, or record
  each refusal as a deliberate divergence with these measurements. Implementing `frps verify`
  changes which error the third row reports, so sequence the two.
  **Done (2026-09-27, on `fix/frps-dash-value` off `f5437e6`; head sha in the PR).** The shared
  pre-parse pass was chosen over a second call-site copy: `parse_frps_args` and `parse_frpc_args`
  both compute `let parse_argv = prepared_cli_argv(&argv)` (one small function wrapping
  `rewrite_config_dash_values`) and hand it to `run_cli`, so the `--`-awareness and the four-flag
  scope cannot drift between binaries. Measured on Go frp v0.71.0 darwin/arm64 against
  the frp-rs binaries, bounded children, free ports and the "before" column re-measured with the
  source reverted to the base head (`f5437e6`) — not quoted from the rows above:
  * The three `-c` rows now **agree on rc and on the path they name**: `frps -c
    --strict-config=false` → rc 1, `--strict-config=false: failed to read
    config file: No such file or directory (os error 2)` (Go: `open --strict-config=false: no such
    file or directory` — message shape differs, the recorded divergence). Re-quoted: the
    `Failed to load config: ` prefix this row was written with was later removed by the CLI
    output-shape round, which leaves the bare line on stdout. `frps -c -x` → rc 1
    naming `-x`; `frps -c --` → rc 1 naming `--`, which is what Go does (`open --: no such file or
    directory`) because pflag takes the separator token as the value.
  * Boundary measured, same pair: `-c --bind-port` (a *known* frps flag) → rc 1 naming
    `--bind-port` like Go, was the parser refusal; `-c -zzz`, `-c -`, `-c=-x`, `-c=-nonexistent.toml`
    and `--config=-x` were already on the load path and are unchanged; a dangling `-c` still refuses.
    `frps -- --strict-config=false` (and `frps -- -c p.toml`, base == head) still refuses the
    positional with `` `--strict-config=false` is not expected in this context`` — and here the
    divergence is **larger than the message shape**: re-measured on Go v0.71.0 with a free port,
    `frps -p <free> -- --strict-config=false` and `frps -p <free> -- junk` **start the server**
    (`frps started successfully`, still alive at 5 s, killed) because cobra takes everything after
    `--` as positional args and `frps`'s `RunE` ignores them; `unknown command "…"` fires only for a
    positional **without** `--` (`frps junk`, `frps -c <valid> junk`, `frps --strict-config false`
    are all rc 1 `unknown command`, measured). The earlier `rc 1` reading of this row came from
    probing without `-p`, which lands on the default `:7000` that macOS Control Center holds — a
    standalone-process collision, not the argv. So this cell is Go **serves** vs frp-rs **refuses**,
    and the refusal (with or without `--`) is the same pre-existing positional rule filed in the
    `frpc`-subcommand-after-leading-root-flags item below, not something this branch changed.
    The `--config-dir`/`--config_dir` control stays a divergence and is now a **different** one: rc 2
    `Failed to read config directory: No such file or directory (os error 2)`, because the extension
    flag is one of the four the pass covers and the dash-shaped token is now its value, where it was
    rc 1 ``--config-dir` requires an argument `DIR``; Go's rc 1 `unknown flag: --config-dir` is not
    comparable (it has no flag). Both spellings behave the same here. Recorded in
    `docs/developing.md` § CLI exit codes.
    Two more user-visible rows of the same rule, both measured Go/head: `frps -c --help` is now
    rc 1 naming `--help` as the config path (Go: `open --help: no such file or directory`; base
    printed help, rc 0) — a match, deliberately losing the old convenience; and a repeated `-c`
    still refuses on frps (`frps -c a.toml -c b.toml` → `` argument `-c` cannot be used multiple
    times `` , base == head) where **Go is last-wins and opens `b.toml`** — so "the same rule on
    both binaries" covers the dash-value attachment only, **not** last-wins: the frpc `.last()`
    work did not touch `parse_frps_args` and this branch does not either. With the rewrite the
    dash-valued repeat (`frps -c --strict-config=false -c p.toml`) moves from the `-c` refusal to
    that same "multiple times" message (rc 1 either way). Pinned by
    `dash_help_after_config_is_a_value_not_a_help_request` and
    `repeated_config_flags_refuse_with_the_multiple_times_message`.
  * **Sequencing:** the third row's *current* Go error is `open --strict-config=false: no such file
    or directory`, and that is what the fix pins. `frps verify` is still unimplemented (its own item
    below), and with the rewrite in place `frps verify -c --strict-config=false` now reports
    `` `verify` is not expected in this context `` (rc 1) rather than the `-c` refusal — the missing
    subcommand is the first error. Implementing `frps verify` flips this row back to a config-load
    error; this item and `docs/developing.md` § CLI inputs both state the current error, so the flip
    is visible rather than silent.
  * Pins: `frps/tests/cli_exit_codes.rs` grew seven argv-level tests
    (`dash_shaped_config_value_is_the_value_not_a_flag`,
    `dash_dash_as_config_value_is_consumed_not_a_separator`,
    `real_separator_and_dangling_config_stay_refused`,
    `config_dir_dash_value_now_reaches_the_directory_read`,
    `verify_subcommand_is_now_the_first_error_for_a_dash_config_value`,
    `dash_help_after_config_is_a_value_not_a_help_request`,
    `repeated_config_flags_refuse_with_the_multiple_times_message`), so
    `env.FRPS_CLI_TESTS` moved 9 → 16 in `.github/workflows/ci.yml` in the same commit; the
    parser-level pins `frps_takes_a_dash_shaped_config_value` and
    `frps_rewrite_scope_matches_frpc` live in `frp-core/src/cli.rs`, and both the real entry points
    and the test call the same `prepared_cli_argv` (`frp-core/src/cli.rs`), so the test follows the
    wiring rather than a sibling copy.
    Red evidence, measured by reverting only the `parse_frps_args` call site in a scratch copy and
    re-running the file: `test result: FAILED. 10 passed; 6 failed` — the six failing new pins are
    the dash-shaped-value, `-c --`, `--help` value-position, repeated-`-c`, `--config-dir` and
    `verify` tests. The seventh new pin, `real_separator_and_dangling_config_stay_refused`, passes
    on both trees **by design**: it pins what must *not* change (Go serves a positional after `--`,
    so frp-rs refusing it is pre-existing, not this branch's). The parser-level test still passes
    with the call site reverted (it pins the repair, not the wiring).
  * The `verify` pin is the sequencing made loud: it asserts the **current** first error
    (`` `verify` is not expected in this context ``) and the `-c` value being consumed, so
    implementing `frps verify` turns it red instead of silently changing which error the row
    reports. Verified by simulation in a scratch copy (accept a bare `verify` positional): **that
    one test fails, the other 15 pass**. The item's third measurement above therefore has one foot
    in this item and one in the `frps verify` item below, which now carries the same warning.
  * **A flaky pre-existing SIGTERM control, found and fixed while adding these tests.** With the
    extra tests in the file, `cargo test -p frps --test cli_exit_codes` failed
    `good_config_starts_and_exits_0_on_sigterm` / `disable_log_color_value_spelling_is_applied` with
    `unix_wait_status(15)`. Two mechanisms, both measured with the helper as the **only** difference
    (40 iterations of the whole file per arm): (a) the SIGTERM task is spawned from the same async
    fn as the accept loop and can be unpolled when the connection is accepted
    (`frp-server/src/service.rs:1579-1619`); (b) **the load-bearing one** — `ephemeral_port()`
    releases its port before the child binds it and tests run in parallel, so the connect witness
    can be satisfied by a *foreign* listener (every failure in both A/B arms had an **empty child
    log** although a connect had succeeded, and one reviewer failure ended in `Address already in
    use (os error 48)`). Connect-only helper: **7/40** on the author's host, **5/40** on the
    reviewer's; marker helper: **0/40** on both. Respawning fresh children did not help (3/3 lost
    the race again). The helper now waits for the
    child's own `SIGUSR1 reload ready` line (`frps/src/main.rs:207-215`), which only this child can
    write to its own log: **0/40, 0/40 and 1/40** across three A/B loops here and **0/40** on the
    reviewer's host — the one residual failure is the non-zero window below, not the
    foreign-listener arm (a follow-up 30-run loop did not reproduce it, ~1/100).
    The marker is **not** proof that SIGTERM's handler is registered — tokio registers signals per
    kind and lazily (`tokio-1.53.1/src/signal/unix.rs:283-300`), leaving a measured ~0.16 ms
    median / 1.10 ms max window — so the helper's doc comment says "small but nonzero" instead of
    claiming the handler is up. This is a test-harness fix, not a product change — the
    product path is unchanged — and it is the only edit to a pre-existing test.
  * **frpc regression check** (the shared pass's other caller): the #383 rows were re-measured with
    the new `frpc` binary, including against a one-shot mock on `p7498.toml`'s admin port —
    `status -c --strict-config=false -c p7498.toml` still dials `7498` and exits 0 on both binaries,
    `status -c --strict-config=false` and `status -c -x` still read the token as a file (rc 1,
    naming it). `rewrite_config_dash_values`'s body is unchanged on this branch; the only call-site
    change is on the frps side, and the frpc suites pass unchanged.
- [x] **`frpc` does not accept a subcommand after leading root flags, where Go's cobra does.**
  Measured on Go v0.71.0 and this head (identical at the base head `ec82a20`, so the
  persistent-flag work did not change it): `frpc -c pA.toml status` → Go resolves the `status`
  subcommand and dials `127.0.0.1:17498` (pA.toml's `[webServer] port`); frp-rs falls back to run
  mode and answers rc 1 ``Error: no such command or positional: `status`, did you mean `https`?``.
  Same for `frpc --strict-config=false status -c pA.toml` (Go dials 17498) and
  `frpc -c missing.toml tcp --local-port 5 --remote-port 6 --proxy-name x --server-port <free>`
  (Go starts the single tcp proxy; frp-rs says ``no such command or positional: `tcp` ``). bpaf
  chooses the branch before dispatch, so the subcommand token is a leftover in the run-mode parser.
  **Done-when:** either accept cobra's flag/subcommand interleaving (hoist a leading token that
  names a known subcommand before bpaf runs, or restructure the parser) and pin the three rows
  against Go, or record the refusal as a deliberate divergence in `docs/developing.md` § CLI inputs.
  frp-rs's own `frpc <subcommand> [flags]` order keeps working either way.
  **Done (2026-09-27, `9bff35e` plus the carrier pass on the same branch).** Re-measured everything at this branch's base
  (`5b9a084`; the item's `ec82a20` is four PRs stale) with the official
  `/private/tmp/frp_0.71.0_darwin_arm64` binaries and the frp-rs `frpc` built from the base and the
  head, over a 45-row table (one-shot mock admin on the config's `[webServer]` port, canary TCP
  listener on `--server-port`, every child bounded and killed on timeout). The table is in
  `docs/developing.md` § "A subcommand after leading root flags"; the harness is
  `/tmp/ledprobe/probe.py` and the raw rows `/tmp/ledprobe/{go,base,head}45.jsonl`.
  * **The three rows and every flag order now match Go**, not just resolve: `-c pA.toml status`,
    `--strict-config=false status -c pA.toml`, `-c pA.toml --strict-config=false status`,
    `-c pA.toml -c pA.toml status`, `-c=pA.toml`/`-cpA.toml` spellings,
    `--config-dir <dir> -c pA.toml status`, `-v=false`/`--version=false`/`--version=true`/
    `--allow-unsafe X` before the token — each rc 0 and dialling the mock at the config's
    `[webServer] port`, where the base gave rc 1 ``no such command or positional``. The tcp row
    (`-c missing.toml tcp … --server-port <free>`) connects to the canary on both Go and the head
    (the missing config is never opened) and was the same refusal at the base.
  * **The value-position traps were measured on both binaries and none is hoisted**:
    `-c status`/`--config status` — a config file literally named `status` — is run mode on Go
    (`start frpc service for config file […/status]`, and on both frp-rs trees the same run-mode
    load), as are `--config=status`, `-c=status` and `-cstatus`; `-c -status` is the value
    `-status` on Go (`open -status: no such file or directory`) and on the head;
    `tcp --proxy-name status …` and `-c missing.toml tcp --proxy-name status …` connect on Go and on
    the head; `-c pA.toml -- status` stays Go's run mode (positional ignored) and frp-rs's recorded
    positional refusal — the hoist does not cross a real `--`; `-c pA.toml notacommand status` is
    Go's `unknown command "notacommand"` and frp-rs's leftover-token refusal, so only the **first**
    bare word is ever hoisted.
  * **One Go row is surprising and is recorded rather than claimed as a match**: `-c -- status` is
    `open --: no such file or directory` on Go — pflag gives `-c` the value `--`, so `status` *is*
    resolved (the config read happens on the admin path). Because the shared
    `rewrite_config_dash_values` pass runs first and attaches that value (`-c=--`), the hoist sees
    `status` as the first bare word; the head answers `--: failed to read config file: …`, Go's path
    and rc with a different message shape. This is why the two passes compose in that order
    (`prepared_cli_argv`, `frp-core/src/cli.rs`).
  * **Design**: `hoist_leading_subcommand` runs before bpaf over the argv after `cli_args` dropped
    `argv[0]` — the first version saw `argv[0]` as a bare word and never fired, which the 45-row
    table caught immediately. It skips the value of a flag that cobra's `stripFlags` would let
    swallow one, stops at a real `--`, and only ever hoists the first bare word. `frps` passed
    `has_subcommands: false` and was byte-identical at that head. **Superseded, and the
    parenthetical was false:** Go's `frps` declares `verify`, so the "no subcommands" premise is
    wrong and `frps` now runs the same hoist from its own flag/command set — see the `frps verify`
    item's Done block (`RootCommand`, `FRPS_SUBCOMMANDS`, `FRPS_BOOL_ROOT_FLAGS`).
  * **The classifier's `NoOptDefVal` set is where the first version was wrong, and the reviews
    found it in both directions.** The rule is cobra's: a `--long`/`-x` without `=` consumes the
    next token *unless the flag is a pflag bool* (`pflag-1.0.5/bool.go:56` sets
    `NoOptDefVal = "true"`). On `frpc` exactly two root flags are bools —
    `--version`/`-v` (`cmd/frpc/sub/root.go:52`) and `--strict-config`/`--strict_config` (`:53`) —
    while `-c/--config`, `--config_dir` and `--allow-unsafe` (`:50-51,55`) consume, and a flag
    cobra does not know also consumes. The first version wrongly listed `--strict-config` as a
    consumer. **Over-consuming is not the safe direction** (the earlier claim that it was is
    falsified): skipping a token shifts *which* token is the first bare word, so the regression
    direction was `frpc --strict-config true status -c pA.toml` — Go rc 1
    ``unknown command "true" for "frpc"``, base rc 1, that head **rc 0 with a real
    `GET /api/status`** (`stop`/`reload` likewise, and `--strict-config true tcp …` connected to
    the canary); the mirror was `frpc --strict-config status -c pA.toml` — Go rc 0 and dials, that
    head rc 1 ``no such command or positional``. Both are fixed by exempting the two bool
    spellings, and the four other root flags were swept with no divergence:
    `-v/--version`, `--allow-unsafe` and `--config_dir` behave as Go does, `--help`/`-h` stays a
    consumer (cobra adds it in `execute`, after `Find`), and an unknown flag consumes like Go's
    `stripFlags`. The full matrix, both directions, is in `docs/developing.md` § "A subcommand
    after leading root flags" (raw rows `/tmp/ledprobe/{go,base,oldhead,fixed}_sc_.jsonl` and
    `…_ofl_.jsonl`).
  * **Tests**: 11 unit tests in `frp-core/src/cli.rs` (`mod hoist_tests`) pin the classifier (both
    the consumer and the `NoOptDefVal` rows), the hoist, the traps, the composition order, both
    directions of the `--strict-config` grammar and both directions of the `FRPC_SUBCOMMANDS` ↔
    `frpc_parser` correspondence; 13 end-to-end tests appended to `frpc/tests/cli_inputs.rs`
    (one-shot mock admin and canary listeners) pin the fixed orders, the traps, the `--` case, both
    `--strict-config` directions, the existing order and the request-head equality between the
    hoisted and unhoisted orders. Nothing was added to `frpc/tests/cli_exit_codes.rs` or
    `frps/tests/cli_exit_codes.rs`, so the two guarded counts in `.github/workflows/ci.yml`
    (`FRPS_CLI_TESTS: "16"` **at that head** — the literal has since moved to `19` with the typed
    exit-code pins and to `27` with `frps verify` plus its review round, and `FRPC_TINY_CLI_TESTS:
    "11"`) were unchanged by that round and matched `-- --list` then. `frpc/tests/cli_inputs.rs` went 21 tests at the base to 34 (13 new); with `BIN`
    re-pinned to the base binary the suite is **28 passed, 6 failed**, the six being exactly the
    command-resolution tests, and with it pinned to the pre-fix head `86745d5` the suite is
    **32 passed, 2 failed** — and the two failures are *both* direction tests,
    `a_word_after_bare_strict_config_is_not_resolved_as_a_subcommand` (the regression the
    over-consuming classifier introduced) and
    `bare_strict_config_before_the_subcommand_still_resolves_it` (the mirror it left unfixed),
    while the five command-resolution tests pass. Each direction is red on the revision that got
    it wrong, independently.
  * **Gates at this head**: `cargo fmt --all -- --check` clean; `cargo clippy -p frp-core -p frps
    -p frpc --all-targets --all-features -- -D warnings` clean; `cargo test -p frp-core --lib`,
    `cargo test -p frps`, `cargo test -p frpc` pass; `bash scripts/repo-health.sh` rc 0;
    `scripts/compat-test.sh` not run and not relevant — this is an argv-layer change with no wire
    effect (no protocol, transport, encryption or proxy code touched).
- [x] **A CLI failure's output shape is still not Go's: frp-rs prints a `tracing` line where Go
  prints one bare error, and `verify` writes to stderr where Go writes to stdout.** Measured on Go
  v0.71.0 and on the head binaries while closing the exit-code item above (only the *exit code*
  was fixed there):
  * Go `frpc -c bad.toml` → stdout is exactly `json: unknown field "notAKnownFrpKey"`, nothing
    else. frp-rs (pre-fix, at the time this item was filed) → an ANSI-coloured `ERROR frpc: Failed
    to load config: unknown field … in config file …  error=…` on stdout (same stream, different
    shape).
  * Go `frpc verify -c bad.toml` → the parse error on **stdout**, exit 1. frp-rs (pre-fix, then) →
    `Config file … is invalid: …` on **stderr**, exit 1 (now correct).
  * frp-rs's `--strict-config=foo` message (`Error: \`foo\` is not expected in this context`) also
    differs from Go's pflag message, though both exit 1 (already recorded in the space-separated
    `--strict-config` item above).
  **Done-when:** either match Go's message shape and stream on these paths, or state the shape
  divergence in `docs/developing.md` § CLI exit codes as deliberate with the reason. No sha.
  **Done (2026-09-27, branch `fix/cli-output-shape`, based on `main` @ `5ae1bcf`).** Split per path:
  the **stream and the shape of each line are matched** on all three load-failure paths named here,
  and **two shape divergences are recorded as deliberate**: the wording, and the line count at
  N ≥ 2. `frps -c <bad>` — the same Go code shape, and the same pre-fix output shape — was changed
  with `frpc`; leaving it would have been an indefensible asymmetry. *(The branch's four
  behaviour/carrier commits were written against the pre-rebase base `04959b1` and rebased onto
  `5ae1bcf` by the orchestrator; the rebase was clean and `frps/src/main.rs` — the only file the two
  bases differ in among the four this branch touches — kept both changes. `c70da36` is the head the
  reviewers saw; the further carrier-only commit reviewed and re-measured here is the branch tip
  (its sha is in the PR body, not here — this block cannot cite the commit that contains it). Every
  measurement below was
  **re-derived on the rebased parent `5ae1bcf`** after the rebase, including the red evidence and
  the `--help=<bool>` rows.)*
  * **The change.** `frpc/src/main.rs` (`run`'s single-config `Err` arm) and `frps/src/main.rs` (the
    same arm) replace `init_logging(…, None)` + `tracing::error!(error = %e, "Failed to load
    config: {}", e)` with `println!("{e}")`; `frpc/src/main.rs`'s `run_verify` moves both refusals
    (the parse error and the oidc-without-feature refusal) from `eprintln!` to `println!`. Net diff
    before carriers: `frpc/src/main.rs` +23/−7, `frps/src/main.rs` +11/−5
    (`git diff --numstat 5ae1bcf c70da36` — still the same at the branch tip, because the later
    review fix round added no source lines), plus the two
    `cli_exit_codes.rs` test files (assertions tightened, no test added or deleted there). Exit codes
    are
    unchanged (`EXIT_RUNTIME`/1 on every one of these paths). Anchors: Go's `fmt.Println(err);
    os.Exit(1)` in `cmd/frpc/sub/root.go` (`RunE`), `cmd/frpc/sub/verify.go` (`verifyCmd`) and
    `cmd/frps/root.go` (the `cfgFile != ""` arm); Go installs its logger only after a successful
    load (`startServiceWithAggregator`), so dropping the `init_logging` call from the arm that exits
    before any log record is also Go's ordering.
  * **Measured 2026-09-27, Go v0.71.0 darwin/arm64 (`/private/tmp/frp_0.71.0_darwin_arm64`) vs the
    frp-rs debug binaries, stdout and stderr redirected to separate files and the exit status read
    directly from `wait` (never through a pipe), every child bounded and reaped:**

    | command | Go stdout / stderr | frp-rs before | frp-rs at head |
    |---|---|---|---|
    | `frpc -c bad.toml` | 38 B `json: unknown field "notAKnownFrpKey"` / 0 B, rc 1 | stdout ANSI `ERROR frpc: Failed to load config: … error=…`, stderr 0 B, rc 1 | stdout one bare line, `unknown field "notAKnownFrpKey" in config file <path>`, stderr 0 B, rc 1 |
    | `frpc verify -c bad.toml` | 38 B same text / 0 B, rc 1 | stderr `Config file <path> is invalid: …`, stdout 0 B, rc 1 | stdout one bare line, `Config file <path> is invalid: unknown field … in config file <path>`, stderr 0 B, rc 1 |
    | `frpc verify -c <missing>` | stdout `open <path>: no such file or directory` / 0 B, rc 1 | stderr, rc 1 | stdout one bare line, `Config file <path> is invalid: <path>: failed to read config file: …`, stderr 0 B, rc 1 |
    | `frps -c bad.toml` | 38 B same text / 0 B, rc 1 | stdout ANSI tracing line, stderr 0 B, rc 1 | stdout one bare line, `unknown field "notAKnownFrpKey" in config file <path>`, stderr 0 B, rc 1 |
    | `frpc verify -c good.toml` (control) | stdout `frpc: the configuration file <path> syntax is ok`, rc 0 | stdout `Config file <path> is valid` + 3 summary lines, rc 0 | **unchanged** — the success line was not in scope |
    | `frpc --strict-config=foo -c good.toml` | **stderr** pflag `invalid argument "foo" for "--strict-config" flag: …` + full cobra usage, stdout 0 B, rc 1 | stderr `` Error: `foo` is not expected in this context ``, rc 1 | **unchanged** — same stream, text and usage block differ (recorded; see below) |
    | `frps -c --strict-config=false` / `-c -x` / `-c -c` / `-c --bind-port` | rc 1 `open <value>: no such file or directory` on stdout | stdout ANSI `Failed to load config: <value>: failed to read config file: …` | stdout one bare line, `<value>: failed to read config file: …`, stderr 0 B, rc 1 |
    | `frpc --config-dir <dir with a bad config>` | Go exits **0** (prints only `frpc service error for config file […]`) | stdout ANSI tracing lines, rc 2 | **unchanged** (extension surface, no Go line to match) |

    Only Go's `38 B` is quoted, and it is the one path-independent total here: Go's
    decoder error carries no config path, while **every frp-rs total moves with the
    path embedded in the line**. This table originally quoted head stdout as
    75/79/127/170 B, all from probes under `/tmp/cli-probe/cfg/`
    (`.../bad.toml` etc.); re-measuring the same one-key content under
    `/tmp/f1-probe/cb1.toml` gave 70 B for the `frpc -c` line — the 5-byte
    difference is exactly the 5-character path difference (74 B vs 69 B of text
    plus `\n`), and the reviewers, on their own paths, got other totals again. The
    "before" `tracing` totals move the same way, since the message appears twice
    there plus the path. The claims are the stream, the line shape and the line
    **count**, not the byte totals.

  * **Recorded, not matched: the wording.** frp-rs names the config file (`unknown field "x" in
    config file <path>`, plus a `did you mean 'y'?` suggestion — `frp-core/src/config/strict.rs`'s
    `check_strict_in`, levenshtein ≤ 3); Go prints the codec's `json: unknown field "x"` with **no**
    path. Matching byte-for-byte would mean a literal `json: ` prefix on a message frp-rs also
    emits for TOML/YAML/INI, and dropping the only file identity in `--config-dir` mode and in the
    admin `reload`/`status`/`stop` refusals, which already print this same bare stdout line. The
    `--strict-config=foo` row is the third recorded case: both binaries already write it to
    **stderr** and exit 1, and only the text differs (Go's pflag sentence plus the whole cobra usage
    block vs frp-rs's one shorter line) — that text is already carried by the space-separated
    `--strict-config` item above and by `docs/developing.md` § `--strict-config`, so nothing was
    changed for it here. `frpc verify`'s **success** line is a third adjacent divergence left alone
    and stated: Go prints exactly `frpc: the configuration file <path> syntax is ok`, frp-rs prints
    `Config file <path> is valid` + three indented summary lines; that is a success row, outside
    this item's failure paths, so it is recorded in `docs/developing.md` rather than folded in.
  * **Recorded, not matched: the line count at N ≥ 2** (found by both reviewers of this branch, after
    the first revision of the Done block claimed "one bare line" without qualification — that
    generalisation was false for two or more unknown keys, and this half of the item's done-when had
    not been met). `run_strict_check` (`frp-core/src/config/strict.rs`) collects **every** unknown key
    and returns `errors.join("\n")`, so one `println!("{e}")` emits one line per rejected key; Go sets
    `DisallowUnknownFields` on a single `decoder.Decode(out)` (`pkg/util/jsonx/json_v1.go:43-44`,
    reached from `pkg/config/v1/decode.go:29-33`) and returns at the **first**, so its whole output is
    one line whatever N is. Measured here with three unknown keys (streams separated, rc read
    directly, children reaped):

    | command | Go stdout | frp-rs stdout |
    |---|---|---|
    | `frpc -c <3 unknown keys>` | rc 1, 36 B, **1 line**, `json: unknown field "anotherBadKey"` | rc 1, **3 lines**, stderr 0 B |
    | `frpc verify -c <3 unknown keys>` | rc 1, 36 B, **1 line**, same text | rc 1, **3 lines** (first prefixed `Config file <path> is invalid: `), stderr 0 B |
    | `frps -c <3 unknown keys>` | rc 1, 36 B, **1 line**, same text | rc 1, **3 lines**, stderr 0 B |

    The key named **first** is the same on both sides and is chosen by key name, not document
    position: with the document order permuted to `zzzBadKey, anotherBadKey, thirdBadKey` Go still
    names `anotherBadKey` (and with `zzzBadKey, aaaBadKey` it names `aaaBadKey`), while frp-rs names
    `anotherBadKey` first and then `thirdBadKey`, `zzzBadKey`. So the divergence is purely the
    *count* — all keys versus the first — and reporting all of them is kept deliberately (listing
    every rejected key is what strict mode is for; matching Go would discard N−1 of them, and a
    caller that wants Go's single line reads the first line). Recorded in `docs/developing.md`
    § CLI exit codes → *Output stream and shape on a config-load failure* and in `CHANGELOG.md`.
  * **Tests.** Assertions in the two existing `cli_exit_codes.rs` files were tightened; **no test was
    added to or deleted from either**, so the guarded counts do not move.
    `frpc/tests/cli_exit_codes.rs`: `daemon_bad_config_exits_1_and_names_the_unknown_field` and
    `verify_bad_config_exits_1_and_names_the_unknown_field` now assert the **exact** stdout bytes and
    an **empty stderr** (they previously concatenated the two streams); `verify_missing_config_exits_1`
    asserts the stdout line starts with `Config file <path> is invalid: <path>:` and stderr is
    empty; the tiny module's two tests get the same treatment for `frpc-tiny`.
    `frps/tests/cli_exit_codes.rs`: the same exact-stdout/empty-stderr pin for
    `bad_config_exits_1_and_names_the_unknown_field` and `missing_config_exits_1`;
    `dash_shaped_config_value_is_the_value_not_a_flag` now asserts the load line on **stdout**
    (a refusal leaves stdout empty) instead of the removed `Failed to load config` wording, and
    `real_separator_and_dangling_config_stay_refused` swaps its negative
    `!all.contains("Failed to load config")` for `!stdout.contains("failed to read config file")`,
    which keeps "the token after a real `--` was not taken as `-c`'s value" discrimination.
    The N ≥ 2 count is pinned **at the collector**, not the CLI, because every CLI fixture in both
    files carries one unknown key: `strict_check_reports_every_unknown_key_not_just_the_first`
    (`frp-core/src/config/tests.rs`) asserts three unknown keys produce exactly three joined lines,
    each naming its own key, in key-name order — that is the `errors.join("\n")` behaviour the CLI
    line count rests on. Neither guarded literal counts it.
    **Red evidence** (re-derived on the rebased parent `5ae1bcf`): with `frpc/src/main.rs` and
    `frps/src/main.rs` checked out at `5ae1bcf` and rebuilt, the strengthened suite is **6 passed /
    3 failed** in `cargo test -p frpc --test cli_exit_codes` (daemon, verify-bad, verify-missing),
    **14 / 2 failed** in `-p frps` (bad, missing) and **6 / 5 failed** in the tiny lane — then 9/0,
    16/0 and 11/0 at head. The three counts were unchanged by that round (`env.FRPS_CLI_TESTS`
    `16` **at that head** — the literal reads `27` now, after the typed exit-code pins took it to
    `19` and `frps verify` plus its review round took it to `27`; `env.FRPC_TINY_CLI_TESTS` `11`,
    still `11`; both were re-checked against `-- --list` then).
  * **Carriers**: `docs/developing.md` § CLI exit codes gained a
    **Output stream and shape on a config-load failure** subsection with the table above, the
    recorded wording divergence, the recorded N ≥ 2 line-count divergence and the adjacent `verify`
    success-line row; § CLI inputs' item (3) ("a config load failure is written to stderr by
    `verify` only") was corrected to point at it, and § CLI inputs § 2b's `./frps.toml` quote was
    re-quoted to the bare line; `CHANGELOG.md` § Unreleased § Changed has one entry (a user-visible
    stream/shape change, with the N ≥ 2 half stated); `TODO.md` gained the `--help=<bool>`
    subcommand item below (filed, not folded in here) plus the two re-quotes noted in § "review fix
    round" below.
  * **Review fix round (2026-09-27, carrier-only commit at the branch tip).** Both reviewers
    returned "merge after these fixes" on the carrier layer with nothing behavioural blocking; this
    round is **text plus one new unit test in `frp-core` — no `frpc/src/main.rs` or
    `frps/src/main.rs` change**, so the measured behaviour cannot move
    (`git diff --numstat 5ae1bcf c70da36` over the two source files still reports +23/−7 and +11/−5
    at the branch tip). (1) This block's own headline claim, "one bare line", was **false for N ≥ 2**
    (found by both reviewers, each with their own fixtures) and is
    reworded in `docs/developing.md`, `CHANGELOG.md` and both `cli_exit_codes.rs` module docs, with
    the divergence **recorded as deliberate** (the half of the done-when that was missing) and the
    collector pin added. (2) Four quotes of the deleted `Failed to load config: ` prefix that
    presented it as the current output were re-quoted (`docs/developing.md` § CLI inputs § 2b and
    the `frps -c --strict-config=false` table cell; `TODO.md`'s `./frps.toml` note and the
    `-c --strict-config=false` row); the older "before" columns that legitimately show the pre-fix
    shape were left alone. (3) This table's path-dependent frp-rs byte counts were replaced with
    `<path>` renderings — only Go's path-independent 38 B is quoted. (4) The base-sha citations were
    corrected from the pre-rebase `04959b1` to the frozen `5ae1bcf`, and the red evidence was
    **re-derived on `5ae1bcf`**. (5) `frpc --strict-config true status -c CFG` was filed as a
    cross-reference row inside the `--help=<bool>` item, marked pre-existing and explicitly not
    absorbed by this change. (6) One lint nit about a `38 B` figure in a source comment is resolved
    in the carriers instead of the code, because this round must not touch `main.rs`: the docs now
    spell out that Go's 38 B is 37 B of text plus `\n`.
  * **Gates at this head**: `cargo fmt --all -- --check` clean; `cargo clippy --workspace
    --all-targets --all-features -- -D warnings` clean; `cargo test -p frpc` (6 targets,
    8+25+9+34+7+1 passed), `cargo test -p frps` (3 targets, 0+6+16 — the `cli_completion` target is
    #391's, added by the rebase), `cargo test -p frp-core --lib` (940, the new N ≥ 2 pin included)
    pass; the tiny lane `cargo test -p frpc --no-default-features --features tiny --test
    cli_exit_codes` 11/0; `RUSTFLAGS="-D warnings" cargo check --workspace --no-default-features
    --features tiny` and `… --features micro` clean; `bash scripts/repo-health.sh` rc 0 (466 repo
    path references resolve). `scripts/compat-test.sh` not run and **not relevant** —
    no protocol, transport, encryption or proxy code was touched (the behaviour diff is two
    `println!` sites and one removed `init_logging` call per daemon).
- [x] **`frpc --help=<bool> <subcommand>` does not follow Go: pflag's bool `--help` is
  short-circuited by frp-rs's bpaf parser, so a subcommand's *help* and a real request are
  confused.** Found by #387's Reviewer 1, whose report has the same rows on Go v0.71.0, that branch's
  base head and its head. Re-measured here (2026-09-27) on Go v0.71.0 and on **this branch's frozen
  base head `5ae1bcf` and its head** — identical on both, i.e. pre-existing and not this item's
  done-when — with stdout and stderr captured separately, the exit status read from `wait` (never
  through a pipe), and **one fresh listening socket per run** on the config's `[webServer] port` to
  observe whether the admin port is dialled at all (connections counted by `accept`, never
  inferred):
  * `frpc --help=false status -c CFG` with `[webServer] port` **set** → Go **rc 1**, **1
    connection**, stdout `Get "http://127.0.0.1:<port>/api/status": read tcp …: read: connection
    reset by peer` (the listener closes immediately) — the flag is a pflag bool whose `false`
    **runs status**. frp-rs **rc 0**, **0 connections**, prints `status`'s bpaf usage (1604 B) on
    stdout.
  * the same argv with **no** `[webServer] port` → Go **rc 1**, **0 connections**, stdout
    `web server port should be set if you want to use this feature`; frp-rs **rc 0**, **0
    connections**, the same bpaf usage. (Both Go rows exit 1; which one you get is the config, so
    neither row alone pins "runs status".)
  * `frpc --help=true status -c CFG` → Go **rc 0**, **0 connections**, stdout is `status`'s *help*
    (`Overview of all proxies status` + `Usage: frpc status [flags]`, 627 B); frp-rs **rc 0**, **0
    connections**, stdout is the bpaf *usage* text (1604 B) — a different document, not Go's help.
  * `frpc -hc status` (pflag shorthand cluster: `-h` then `-c`, which needs a value) → Go **rc 1**,
    **0 connections**, **stderr** `Error: flag needs an argument: 'c' in -c` plus `status`'s usage
    (637 B), stdout 0 B; frp-rs **rc 0**, **0 connections**, prints `status`'s usage on stdout.
  The root-command half of this class is already recorded — `--help`/`-h` is a Go pflag bool
  (`frpc --help=false -c cfg` starts, rc 124) and bpaf's built-in here (prints help, rc 0) — in the
  `--flag=<bool>` item's "deliberately left divergent" list; these four rows are the *subcommand*
  case, where Go's bool resolves the command and frp-rs's built-in pre-empts it, and they are not
  in that item's table.
  **Cross-reference — one more row of the same cobra-hoist class, filed here rather than as a
  separate item, and explicitly *not* absorbed by this branch's output-shape fix.** Measured here
  on Go v0.71.0 and the head binary with one fresh listening socket on the config's
  `[webServer] port` (connections counted by `accept`), streams separated and rc read directly:
  `frpc --strict-config true status -c CFG` (the space form; Go's pflag bool does not consume
  `true`, so it is a positional command word) → **Go rc 1**, 0 connections, stdout 0 B, stderr
  70 B `Error: unknown command "true" for "frpc"` + `Run 'frpc --help' for usage.`; **frp-rs rc 1**,
  0 connections, stdout 0 B, stderr 70 B `` Error: no such command or positional: `status`, did you
  mean `https`? ``. Same stream, same rc, no dial — a different **diagnosis**, which is what the
  done-when below would have to cover for this row too. It is **pre-existing and not this branch's**:
  the branch's diff (`git diff 5ae1bcf c70da36`) touches no parser code at all — no
  `frp-core/src/cli.rs` — and `frpc/tests/cli_inputs.rs` pins only "rc ≠ 0 and the proxy never
  started", which both sides satisfy. The space-separated `--strict-config` item above records the
  same argv's *exit-code/leniency* half ("Go: `unknown command "true" for "frpc"`; frp-rs consumes
  it and goes lenient, warns") for `run`; this row is the `status` diagnosis on top of that.
  **Done-when:** either make `--help=<bool>` a parsed bool that a subcommand can follow (so
  `=false status` runs `status` and dials, and `=true status` prints Go's `status` help) and make
  `-hc` a parser error like pflag's — the help-rendering shape difference is a separate, larger row
  — or record the rows in `docs/developing.md` § `--flag=<bool>` as deliberate with the reason.
  **Done at `8ecbb09`, first branch, with the second named and measured rather than claimed.**
  `frp-core/src/cli.rs` gained two pre-parse passes on the argv
  `rewrite_config_dash_values`/`hoist_leading_subcommand` already produced
  (`prepared_cli_argv`): `expand_help_bool_value_form` drops a `--help=<bool>` token whose argv's
  first bare word is an implemented command — so `=false status` runs and dials — and appends a
  bare `--help` at the end when the value is true, so the *subcommand's* help is what prints; and
  `reject_pflag_shorthand_cluster_that_needs_a_value` prints `Error: flag needs an argument: 'c'
  in -c` on stderr with rc 1 for the argv bpaf answered with help. Sweep: the first round measured
  **85 argvs** on
  Go v0.71.0 (darwin/arm64) / base `5b18489` / this head, one fresh listening socket per run on the
  config's `[webServer] port` with connections counted by `accept`, streams separate and rc read
  from the child — **the whole sweep is 262 rows (210 `frpc` + 52 `frps`) with 70 moved and none
  regressed**; the first matrix alone was 154 with 34 moved. The per-matrix table (rows / moved /
  help-document rows) is in `docs/developing.md` § `--help=<bool>` so the figure can be re-derived
  rather than trusted (the review-fix round added the 69-row matrix R2 named, which is where the first
  revision's 19 regressions were found and fixed). **Scored per surface, because one aggregate hid
  the frps half twice:** the 20-row `frps` matrix is **19 agree / 1 differ** (the root
  `--help=false -c CFG` divergence), the valid-config `verify` rows are **9 agree / 1 differ** (that
  one is a run-path row whose `rc 3` is the recorded `EXIT_AUTH` empty-token hardening, not the
  verify flag set), and the 6 hardening-safe `run` rows are **3 agree / 3 differ** — all three
  `frpc tcp`, the pre-existing single-proxy flag requirement that the base shows with **no help
  flag in argv**. `frpc --help`, `-h`, `--help=true`, every
  `frpc <sub> --help`/`-h`, `frpc --help status`, `frpc -c --help` and the root
  `frpc --help=false -c cfg` divergence are unchanged — the 29 historical help rows are
  **byte-identical** to the base (95 rows whose stdout is a help document, base == head on rc,
  connection count and both byte counts — the recipe is in the same section). **One correction to this item's own rows:** `frpc -hc status` is rc 1 with the
  missing-argument line, and the mechanism is cobra's, not pflag's: `stripFlags` sees `-hc` (three
  characters, so its two-character short rule does not apply) and then collects `status` as the
  first **bare word**; `Find` selects the `status` command and `argsMinusFirstX` removes the word,
  so the *command's* parser is handed `["-hc"]` and pflag reports the missing argument on that
  parser. Measured on Go v0.71.0: `frpc -hc status` stderr 637 B (status's usage), `frpc -hc verify`
  548 B (verify's usage), and `frpc -hc notacommand` 77 B `unknown command "notacommand" for
  "frpc"` — no command matches there, so `legacyArgs` refuses the word before any parse. With a
  token after the cluster (`frpc -hc status -c CFG`, `… -t`, `… -v`) Go is **rc 0 and prints help**,
  and the walk leaves those alone because the cluster claims the token. **Not done, deliberately:** the
  help **document**.
  `--help=true status` and `status --help` still print bpaf's usage (1604 B for `status`, 2405 B
  root) where Go prints cobra's (`Overview of all proxies status`, 627 B; 1370 B root) —
  reproducing cobra's renderer over bpaf's metadata is a flag-surface-wide row, so the byte counts
  are the honest statement and are tabulated in `docs/developing.md` § `--help=<bool>` with the
  residual argvs (`--help=false -c cfg`, `--help=0`, `--help=true notacommand`, `-h -v -c`,
  `-hLinfo`, `-h -c status`, `-c cfg -- --help=false`) and the unchanged admin-status stream
  divergence. The help-rendering row is **filed as its own item below** ("cobra's help document is
  not reproduced"), so "the renderer is separate" is a tracked row rather than a claim in this
  entry. Two argv families the review round measured are covered by the same item and are
  **not** residuals: a `--help=<bool>` token in a flag's **value** position stays untouched for
  **every** flag the parser feeds the next token to — short, long, cluster and the `verify`/admin
  surfaces, including `frps verify --token --help=false -c CFG` (Go rc 0, 116 B, byte-identical
  here) and `frpc verify --allow-unsafe --help=false -c CFG` — and a flag-shaped value is attached
  to its flag (`frps -c CFG -t -h` now exits 1 with the config load exactly as Go does, where the
  base printed root help with rc 0). The one `frpc tcp --proxy-name --help=false -c CFG` row is
  **byte-identical to the base's** `frpc tcp --proxy-name=x -c CFG` (the help flag is inert); Go
  starts on both and that gap is the pre-existing single-proxy flag-requirement divergence, not
  this item's.
  No test was added to a guarded lane, so `env.FRPC_TINY_CLI_TESTS` stays `11` and
  `env.FRPS_CLI_TESTS` stays `27`.
- [x] **Exit codes `3`/`4` on daemon service-construction failures are frp-rs extensions where Go
  exits 1.** Measured at the head of the CLI-exit branch on Go v0.71.0 darwin/arm64 and the frp-rs
  debug binaries:
  * **The `EXIT_AUTH`/3 example is `auth.tokenSource`, not the empty token.** With
    `tokenSource = { type = "file", file = { path = "<missing>" } }`: Go frps rc **1** in 0.26 s
    (`failed to resolve auth.tokenSource: failed to read file …`), Go frpc rc **1** in 0.25 s,
    frp-rs **3** on both in ~0.25 s. This is the `is_token_error` heuristic in the daemons'
    init-error arms (`frpc/src/main.rs` `run_normal` + `run_single_proxy`, `frps/src/main.rs`).
    Pinned by `frpc/tests/cli_exit_codes.rs::unresolvable_token_source_exits_3_where_go_exits_1`.
  * **The empty-token case is not a comparable pair at all**: with `[auth] method = "token"` and
    `token = ""`, frp-rs refuses at construction with exit **3** in ~0.01 s, while Go frps
    **starts and keeps running** (`frps started successfully`, alive after 6 s) — Go has no such
    check and never exits, so there is no Go 1 to contrast. A hardening divergence, documented in
    `docs/developing.md`.
  * **`EXIT_BIND`/4 is the construction fallback, not a bind error.** `frpc` with `[store] path`
    pointing at a file that is not JSON → frp-rs **4** in 0.25 s, Go **1** in 0.26 s
    (`failed to create store source: … failed to parse JSON: …`). Pinned by
    `frpc/tests/cli_exit_codes.rs::malformed_store_file_exits_4_where_go_exits_1` — the name this
    item landed with; the test is `…_regardless_of_the_file_name` at the head (same pin, both
    names).
  * A bind conflict is **not** one of these paths: `frps` on an occupied `bindPort` (with
    `auth.token` set) exits **1** on both sides — frp-rs binds inside `service.run()`, so the
    `EXIT_BIND` arm is not reached by a port conflict.
  * A rejected login is also not one: with `loginFailExit = true` it leaves through
    `service.run()` and exits **1** on both sides.
  * **The 3-vs-4 choice is a substring match over the whole error text, so the same failure can
    land on either code** — tracked separately in the item below; the two pins named above use
    auth-free filenames and therefore cannot catch that flip.
  **Done-when:** either collapse the daemons' init-error arms to exit 1 like Go (and delete/keep
  `EXIT_AUTH`/`EXIT_BIND` accordingly, noting the empty-token hardening refusal that Go does not
  have), or state them as deliberate extensions in `docs/developing.md` § CLI exit codes with a
  test pinning each reachable arm. **The second half is now partly done** — the doc states them
  and two measured inputs are pinned; what remains is the decision, plus pinning the
  `frps`-side 3 and the oidc-no-issuer construction path if they are kept. No sha.
  **Done (head `889317e`, 2026-09-27): the codes are kept, as deliberate extensions, and every
  reachable arm is now pinned — the closing half of this item is the decision, and the other half
  is the typed classification in the item below.** The argument, written out in
  `docs/developing.md` § CLI exit codes and in `CHANGELOG.md`: collapsing to Go's 1 removes no
  *compatibility* risk, because Go's CLI is zero-or-nonzero and every frp-rs construction failure
  is already nonzero — a Go-compatible caller checks for 0, not for 1 specifically — while it
  would delete a documented per-class signal this repo already keeps for `EXIT_CONFIG`/2 (a
  surface Go answers with 0). What was not defensible was how the code was *chosen*, and that is
  what the second item changed. What would reverse the choice is stated in the doc: a Go per-class
  scheme, or a caller found that must see exactly 1 — then the whole change is to return
  `EXIT_RUNTIME` from the three daemon arms.
  **Re-measured 2026-09-27** against Go v0.71.0 (darwin/arm64) and `main`'s `d0f9ec5` binaries,
  one fresh config and one fresh port per (case, binary), rc captured directly from the child,
  stdout/stderr in separate files, every child bounded at 8 s and reaped:
  * `auth.tokenSource` → missing file, on **both** `frps` and `frpc`: Go rc **1** (the frps row
    printed `failed to resolve auth.tokenSource: failed to read file …` on stdout), frp-rs rc
    **3**. Both binaries, so the frps-side 3 the Done-when asked for is pinned.
  * `frps` with `[auth] method = "token"`, `token = ""`: frp-rs rc **3**; Go **still running
    after 8 s** (`frps started successfully`, then SIGTERM'd by the probe). Confirmed as recorded
    — a *hardening divergence*, not a code divergence, and it now has its own pin rather than
    being argued from the 3/4 decision (it survives a collapse, as exit 1).
  * `frps` on a genuinely occupied `bindPort`: frp-rs rc **1** — the `EXIT_BIND` arm is *not*
    reached by a port conflict, because the listener binds inside `service.run()`. Confirmed
    for **both** binaries. The first attempt at this row was a **harness fault, recorded so it
    is not repeated**: holding the port with an IPv4 `0.0.0.0` socket while frps used its
    default `bindAddr = "0.0.0.0"` (`pkg/config/v1/server.go:110`) left Go listening on the
    **IPv6** wildcard and the holder on the IPv4 one — `lsof` showed both in `LISTEN` in the
    same run, which is not a conflict. Setting `bindAddr = "127.0.0.1"` on both sides gives the
    real thing: Go rc **1** (`create server listener error, listen tcp 127.0.0.1:<port>:
    bind: address already in use`), frp-rs rc **1** (`Address already in use (os error 48)`).
  * `frps` with `[auth] method = "oidc"` and no issuer: frp-rs rc **3**; Go **panics** and exits
    **2**. Confirmed as recorded, and now pinned.
  * A rejected login with `loginFailExit = true` — recorded in the item, not re-measured here.
  **Pins added** (all in `frps/tests/cli_exit_codes.rs`): the tokenSource → 3 arm,
  `empty_token_refusal_is_a_hardening_divergence_go_does_not_have` (asserting the *absence* of a
  Go comparison, i.e. the refusal's message, not a Go rc), and
  `oidc_without_an_issuer_is_refused_with_3_where_go_panics`. The `frps` guard literal moved
  **16 → 19** in `.github/workflows/ci.yml` in the same commit as the change, and both lanes'
  guard logic was driven locally: the right value passes, a wrong value exits 1 with the
  direction-aware message
  (`lists 19 tests, env.FRPS_CLI_TESTS is 16: move the single env.FRPS_CLI_TESTS value …`). The
  `tiny` lane's literal stayed **11**.
  **Least sure:** the rejected-login row is the one evidence row taken from the item rather than
  re-measured at this head.
- [x] **Go has `frps verify`, frp-rs has no `frps verify` at all.** Measured on Go v0.71.0 and the
  frp-rs debug binary: `frps verify -c goodfrps.toml` → Go rc **0**, stdout `frps: the
  configuration file goodfrps.toml syntax is ok`; `frps verify -c badportfrps.toml` → Go rc **1**
  with the parse error. frp-rs on both: `Error: \`verify\` is not expected in this context`, rc
  **1** — so a *valid* server config "fails" and a script that validates a config with
  `frps verify` cannot use frp-rs at all. The client side has the subcommand
  (`frpc/src/main.rs::run_verify`); the server CLI (`frp-core/src/cli.rs`, `parse_frps_args`)
  registers only the run path. Found by the adversarial reviewer of the CLI-exit branch;
  pre-existing, not introduced there, and not fixed there.
  **Done-when:** add `frps verify` mirroring `frpc verify` (Go's output shape, rc 0 good / 1 bad,
  honoring `--strict-config`) with CLI tests in the style of `frps/tests/cli_exit_codes.rs`, or
  record it as a deliberate surface reduction in the feature-surface policy. No sha.
  **Sequencing warning (2026-09-27):** the `-c <dash-value>` item above pins this item's current
  behaviour with `verify_subcommand_is_now_the_first_error_for_a_dash_config_value`
  (`frps/tests/cli_exit_codes.rs`): with the shared config dash-value rewrite in place,
  `frps verify -c --strict-config=false` now reports `` `verify` is not expected in this context ``
  as the first error. **Implementing `frps verify` is expected to make that test fail** — that is the
  tripwire working as designed, not a regression: update the test (and the row in
  `docs/developing.md` § CLI inputs) to the new error at the same time, and do not delete the test to
  make it pass.
  **Done (head `ed3c1f8`, 2026-09-27): `frps verify` exists, and the tripwire fired exactly as this
  item predicted — the test was re-pointed, not deleted.** `frps_verify_cmd`
  (`frp-core/src/cli.rs`) is Go's `verifyCmd` shape: `frps_build` parses the root surface and only
  the two fields `verifyCmd` reads are kept (`cmd/frps/verify.go:36,40`), with `-c` as
  `config_arg` (pflag last-wins) and `--config-dir` refused — it is an frp-rs-only extension, and
  accepting it would make an argv Go rejects (`unknown flag: --config-dir`, rc 1) exit 0. The
  loader is `load_server_config`, the same parse-and-validate path the run path uses.
  **Measured on Go v0.71.0 darwin/arm64 and the frp-rs debug binary, one fresh config and one fresh
  free port per row, stdout/stderr in separate files, rc read **directly** from the child, every
  child bounded (6 s) and reaped, `pgrep -x frps` = 0 at the end:**
  * `frps verify -c <valid>` → Go rc **0** stdout `frps: the configuration file <p> syntax is ok`,
    stderr 0 B; base rc **1** `` `verify` is not expected in this context ``; head rc **0**, the
    same line, stderr 0 B.
  * `frps verify -c <missing>` → Go rc **1** stdout `open <p>: no such file or directory`;
    head rc **1** stdout `<p>: failed to read config file: No such file or directory (os error 2)`.
  * `frps verify -c <unknown key>` → Go rc **1** `json: unknown field "notAKnownFrpKey"`; head
    rc **1** `unknown field "notAKnownFrpKey" in config file <p>`.
  * `frps verify -c <bindPort = "not-a-port">` → Go rc **1** `field "bindPort": cannot unmarshal
    string into int`; head rc **1** `<p>: config validation error: invalid type: string
    "not-a-port", expected u16`.
  * `frps verify` (no `-c`) → Go rc **0** `frps: the configuration file is not specified` (frps's
    `-c` default is the empty string, `cmd/frps/root.go:44`; `verifyCmd` returns nil at `:36-39`);
    head rc **0**, same line.
  * `--strict-config=false` in **every** flag order Go accepts — `frps verify -c <bad>
    --strict-config=false`, `frps verify --strict-config=false -c <bad>`,
    `frps --strict-config=false verify -c <bad>`, `frps --strict_config=false verify -c <bad>` →
    Go rc **0** (`syntax is ok`) and head rc **0** with the same line; the bare, `=true` and space
    spellings keep strict on (the space form is the documented extension and warns on stderr, Go
    rc 1 / head rc **1** with the same verdict).
  * Accepted-and-ignored root flags: `frps verify --bind-port <free> -c <valid>`,
    `frps verify --allow-unsafe X --version -c <valid>` → Go rc **0** and head rc **0** with the
    verify output and **no** version line (`showVersion` is read only by the root command's `RunE`,
    `cmd/frps/root.go:57`).
  * `frps verify -c <valid> -c <valid2>` → Go rc **0** naming `<valid2>` (pflag last-wins on the
    persistent `-c`); head rc **0** naming `<valid2>`.
  **The false premise, corrected and acted on.** The comment at the `parse_frps_args` call site said
  "Go's `frps` declares no subcommands, so no hoist runs on this binary and its behaviour is
  byte-identical to before" — false (`frps --help` lists `verify`, `completion` and `help`, and the
  measured `unknown command "true" for "frps"` is cobra's `Find` running). The hoist now runs on
  **both** roots through a `RootCommand` that carries the two facts `stripFlags`/`Find` read:
  subcommands (`frps` = ["verify"]) and pflag **bools** (`frps` = `version`,
  `strict_config`, `enable_prometheus`, `disable_log_color`, `tls_only` —
  `cmd/frps/root.go:44-48`, `pkg/config/flags.go:242,246,251`; `frpc` = `version`,
  `strict_config`). The deciding row is `--dashboard-tls-mode`: `VarP(BoolFuncFlag{…})`
  (`pkg/config/flags.go:256-258`), **not** `BoolVarP`, so pflag sets no `NoOptDefVal` and it
  consumes `verify` — Go then **starts the server** (rc **143**, the probe's 6 s SIGTERM
  watchdog; the `timeout`-based rows elsewhere in this repo report 124 for the same shape) instead
  of verifying; `frps --tls-only verify -c <valid>` resolves the command on Go (rc **0**, head
  rc **0**). Both directions are pinned by
  `the_bool_root_flag_sets_are_per_root_command` and
  `frps_hoists_verify_past_its_own_root_flags`.
  **The tripwire, re-pointed.** `verify_subcommand_is_now_the_first_error_for_a_dash_config_value`
  became `verify_subcommand_resolves_so_the_dash_config_value_is_the_first_error`
  (`frps/tests/cli_exit_codes.rs`): for `frps verify -c --strict-config=false` it now pins rc **1**,
  **stdout** `--strict-config=false: failed to read config file: …` — Go rc **1** stdout
  `open --strict-config=false: no such file or directory`, i.e. the config read is the first error
  and the argv is no longer refused for the bare word `verify`. The matching
  `docs/developing.md` § CLI inputs row moved in the same commit, as did the "n/a — frp-rs `frps`
  has no `verify` subcommand" row in § `--strict-config`.
  **Guard interaction:** `frps/tests/cli_exit_codes.rs` is the guarded file, so
  `env.FRPS_CLI_TESTS` (`.github/workflows/ci.yml`) moved **19 → 26** in that commit — seven
  new pins plus the re-point (a re-point is not an added test) — and then **26 → 27** in the
  review-fix round below (+1: `verify_refuses_the_two_frp_rs_only_root_flags_like_go`).
  `-- --list` reads **27 tests, 0 benchmarks**; the lane's own guard logic was driven locally with
  27 (`ok: 27 tests listed (expected 27), 0 failed`), with the stale 26 (`lists 27 tests … move the
  single env.FRPS_CLI_TESTS value … from 26 to 27`) and with 28 (DECREASED direction), and the same
  three ways at the earlier 26/19/27 values. `FRPC_TINY_CLI_TESTS` stays **11** (re-measured).
  **Review-fix round (same branch, after both reviewers returned "MERGE after these fixes"):** one
  behavioural fix plus carriers. `frps verify` used to let the frp-rs-only `--log-format` ride in
  through `frps_build`, so `frps verify --log-format json -c <valid>` printed `syntax is ok` and
  exited **0** where Go exits **1** (`unknown flag: --log-format`) — the same false success the
  `--config-dir` refusal had been designed against. Both extension slots are now
  `bpaf::pure(None)` on the verify path (`FrpsRootSlots`), the run path keeps both, and the two
  flags are the *complete* extension set — measured by diffing the two binaries' rendered `--help`
  lists: frp-rs-only = {`config-dir`, `log-format`}, Go-only = {`vhost-http-timeout`}. Two further
  verify rows were measured and classified as pre-existing: `--vhost-http-timeout` (frp-rs does not
  model it — filed below) and `--dashboard-tls-mode` in its string-flag spellings, including the
  bare trailing form where frp-rs reads `true` and answers rc **0** `syntax is ok` while Go answers
  rc **1** `flag needs an argument: --dashboard-tls-mode` — a **false ok**, which is why the
  carrier sentences now say "every root flag frp-rs **models**" instead of "every other root flag".
  Carriers corrected in the same round: the `WordSepNormalizeFunc` direction in two comments
  (Go rewrites `_` to `-`, `pkg/config/flags.go:31-36`), two doc comments that cited a
  non-existent test name, `frp-core/src/config/tests.rs` and
  `frp-core/src/config/fixtures/README.md` (both said `frps` has no verify subcommand), this file's
  earlier hoist item (the false "Go `frps` declares no subcommands" premise, marked superseded) and
  two stale `FRPS_CLI_TESTS: "16"` quotes in this file. The `frpc verify` success-line divergence
  and the `frps help`/`completion` rc divergence are recorded — the first filed as an item below,
  the second in `docs/developing.md` § Maintenance policy: feature surface.
  **Three things this does not claim.** (1) The `--allow-unsafe`/`TokenSourceExec` gate was not run
  at this head: Go's verify does run its post-load `ValidateServerConfig`
  (`pkg/config/v1/validation/validator.go:22-27` via `auth.go:34-35`, reached from
  `cmd/frps/verify.go:46-48`), so `frps verify -c <exec tokenSource>` is Go rc **1**
  (`unsafe feature "TokenSourceExec" is not enabled …`) and the head was rc **0** — the same
  pre-existing divergence `frpc verify` had, filed as its own item below and closed in `3798a727`
  (see that item's Done block). (2) Trailing
  positionals: Go's `verifyCmd` sets no `Args` validator, so `frps verify -c <valid> junk` is Go
  rc **0** and head rc **1** — the same divergence `frpc verify -c <valid> junk` has (measured,
  Go 0 / frp-rs 1). (3) The run path's `frps -c a.toml -c b.toml` has no last-wins either before or
  after this (`svr_config`, not `config_arg`); only the verify subcommand takes pflag's last-wins.
  Head sha `ed3c1f8` — the commit that implemented the item; the review-fix commit(s) follow it
  on the same branch, and every claim above was re-derived at the frozen head before that round.
  Carriers: `CHANGELOG.md`, `docs/developing.md` § CLI inputs
  (three corrected rows, the new `frps` hoist table, the new `#### frps verify (Go's verifyCmd)`
  section and the four review-round rows), `docs/developing.md` § Maintenance policy: feature
  surface (`help`/`completion`). **Ledger:** this item was the 84th closed; the three items filed
  by the review round (this one's `--allow-unsafe` gate, `frpc verify`'s success line, and `frps`'s
  missing `--vhost-http-timeout`) take the open count from 17 to **20** — 84 closed / 20 open.
- [x] **The `3`-vs-`4` exit code is chosen by a substring match on the formatted error, so the
  *same* failure exits differently depending on a path or URL inside it.** `is_token_error`
  (in `frp-core/src/logging.rs` until #418 deleted it; the tombstone comment is now at
  `frp-core/src/logging.rs:647`) is `msg.contains("token") || msg.contains("auth")`, and the
  daemons call it on `e.to_string()` of a service-construction error
  (`frpc/src/main.rs:583`, `frps/src/main.rs`'s init-error arm). The error text embeds the config
  path and any URL from the config, so an unrelated substring decides the code. Measured with the
  identical malformed-`[store]` config, changing only the file *name*:
  * `[store] path = "/tmp/exitprobe3/authstore.json"` (file contains `this is not json`) →
    frp-rs exits **3**, Go exits **1** (0.03 s).
  * the same file content at `…/plainstore.json` → frp-rs exits **4**, Go exits **1** (0.02 s).
  The mismatch is not the code: it is that frp-rs's own two runs disagree about the *same* failure
  class. The same coupling applies to an OIDC discovery URL ending in `/authz` (3) versus `/zzz`
  (4), per the adversarial review.
  **Pinning gap, stated deliberately (test since renamed to
  `…_regardless_of_the_file_name`):** `frpc/tests/cli_exit_codes.rs::malformed_store_file_exits_4_where_go_exits_1`
  uses `badstore.json` — an auth-free name — so it pins the 4 path and *cannot* catch this flip.
  A test for the flip would have to assert both codes for one failure class, which would pin the
  wrong behaviour rather than fix it.
  **Done-when:** classify construction failures by error *kind* (e.g. a typed `AuthError` /
  `ConfigError` at the construction boundary) instead of by substring, so the code cannot depend
  on the text; then give 3 and 4 one measured input each, and either delete the substring helper
  or document it as a heuristic with its false positives named. No sha.
  **Done (head `889317e`, 2026-09-27): classification is by kind, and the substring helper is
  deleted.** `frp_core::init_error::InitErrorKind` (`Auth` → 3, `Other` → 4) is attached where the
  `Service` constructor raises the error and is carried by a typed `ConstructError` the
  constructors return; the three daemon arms read only `e.kind().exit_code()`
  (`frpc/src/main.rs` `run_normal` + `run_single_proxy`, `frps/src/main.rs`'s init-error arm), and
  **`logging::is_token_error` no longer exists**. `frp-core/src/init_error.rs` asserts the
  kind → code mapping literally and that the kind is independent of the displayed text.
  **The flip control, before and after** — the item's own two names, one run each, one fresh
  config and one fresh port per run, rc captured directly from the child, stdout/stderr separate:
  * **Before (`main` = `d0f9ec5` binaries)**: `authstore.json` → frp-rs **3**, Go **1**;
    `plainstore.json` → frp-rs **4**, Go **1**. Go's message is
    `failed to create store source: failed to load existing data: failed to parse JSON: invalid
    character 'h' in literal true (expecting 'r')` (stdout, 137 B, stderr 0); frp-rs's is a
    `tracing` ANSI record on stdout, stderr 0.
  * **After (head)**: `authstore.json` → frp-rs **4**, `plainstore.json` → frp-rs **4** — one
    code for one failure class. Go is unchanged at **1** on both names.
  The two codes now have one measured input each: **3** = `auth.tokenSource` on a missing file
  (both `frps` and `frpc`; Go 1), **4** = the malformed `[store]` file (Go 1). The regression is
  pinned by
  `frpc/tests/cli_exit_codes.rs::malformed_store_file_exits_4_regardless_of_the_file_name`, which
  replaces the old single-name `…_where_go_exits_1` test (same test count, so the `tiny` guard
  literal stays 11) and runs both names — one failure class, both 4.
  **A reversion to a text match fails that test — measured, not asserted:** re-introducing
  `e.to_string().contains("token") || …contains("auth")` in `frpc`'s arm made the test fail on the
  `authstore.json` iteration with `left: Some(3)`, `right: Some(4)`; restoring the typed arm made
  it pass. The `is_token_error` site itself carries a comment at
  `frp-core/src/logging.rs` saying why it must not come back.
  **Corrected from the item's own text**: the daemon site was `frpc/src/main.rs:583` in the
  frame the item was written in; at `d0f9ec5` it is `:592` (`run_normal`) and `:731`
  (`run_single_proxy`), and the frps arm is `:228`.
  **The OIDC half, re-measured and corrected (it is observable, on the client, with no mock, and
  my earlier "not shown" note here was wrong).** The failing reasoning was that Go and frp-rs were
  treated as one observation — they are separate processes, and the probe had been on **`frps`**,
  where the flip was never possible in the first place. Measured with one fresh config and one
  fresh closed port per row, rc read directly from the child:
  * **`frpc`** `[auth] method = "oidc"`, `clientID`/`clientSecret` set, **no**
    `oidc.tokenEndpointURL` → `OidcClient::new` fetches `<issuer>/.well-known/openid-configuration`
    and the error embeds that URL (`frp-core/src/auth.rs:1232-1247`). Base `d0f9ec5`: an issuer
    path containing `auth` → **3**; the auth-free paths `zzz`, `plain`, `nope`, `x` → **4** (five
    paths, four runs each, same rc every time). Head: **3** for every path. A missing
    `oidc.trustedCaFile` is the same family (base **4** at an auth-free path, head **3**).
  * **`frps` changes no code and never did**: every reachable server construction failure already
    carried `auth`/`token` in its message (the OIDC dial failure through the
    `Cannot start frps with OIDC auth: …` wrapper, the startup refusals through `check_startup`'s
    `[auth]` text), so base **and** head are **3** for `/authz`, `/zzz`, a missing `tokenSource`,
    an empty token, a missing OIDC CA file, an empty issuer and an empty audience — `EXIT_BIND`/4
    is **unreachable on `frps`**.
  * **Probe confound, recorded so it is not repeated:** the claim is about the *message*, and the
    message does not contain the config path, so the config's own **directory name** must be held
    fixed across the arms being compared. An earlier probe used `mktemp -d` per run, whose random
    suffix can spell `auth`; two nominally identical arms then disagreed and produced two wrong
    readings. Isolated directly: with the issuer path held at `/zzz`, an auth-bearing and an
    auth-free config directory both give base **4** / head **3** — the directory name is not what
    the classifier read; the URL is.
  Pinned by `frpc/tests/cli_exit_codes.rs::oidc_construction_failure_exits_3_whatever_the_issuer_path`
  (two auth-free issuer paths, both 3), `#[cfg(feature = "full")]` because `oidc` is not in `tiny`.
  It is mutation-checked: reinstating `to_string().contains("auth")` in `frpc`'s arm fails it with
  `left: Some(4)`, `right: Some(3)` on the `zzz` arm.
  **Pinning gap closed, not argued away:** the old test used `badstore.json` and could not catch
  the flip; the new store test uses `authstore.json` *and* `plainstore.json`, and neither path
  contains `token`, so moving the auth-bearing arm to 3 can only come from a text match on `auth`.
  **Where the guard is weak, stated:** on `frps` no test can distinguish the typed arm from a text
  match, because every reachable frps construction message contains `auth`/`token` — a substring
  mutant in `frps/src/main.rs` passes all 19 of that file's tests (verified by attempting it).

- [x] **`frps verify` / `frpc verify` do not run the post-load `--allow-unsafe` gate, so `verify`
  accepts a config the daemon refuses.** Found by the reviewers of the `frps verify` round; the
  sentence that pointed at "its own item" in `docs/developing.md` § CLI inputs named an item that
  did not exist, which is what filed this one.
  Evidence, all measured on Go v0.71.0 darwin/arm64 and the frp-rs debug binaries with one fresh
  config and one fresh free port per row, stdout/stderr in separate files, the exit status read
  directly from the child, every child bounded (5 s) and reaped. Config in every row:
  `[auth] method = "token"` + `[auth.tokenSource] type = "exec"` with a `command` set.
  * `frps verify -c <that config>` → Go rc **1**, stdout `unsafe feature "TokenSourceExec" is not
    enabled. To enable it, ensure it is allowed in the configuration or command line flags`,
    stderr 0 B; frp-rs head rc **0**, `frps: the configuration file <p> syntax is ok`.
  * `frpc verify -c <that config>` → Go rc **1**, the same line; frp-rs rc **0**,
    `Config file <p> is valid`.
  * `frps -c <that config>` / `frpc -c <that config>` (**run** path) → Go rc **1**, the same line;
    frp-rs rc **3** (the `EXIT_AUTH` construction refusal, a documented extension).
  * `--allow-unsafe TokenSourceExec` makes **all** of the above Go rc 0, and frp-rs's `verify` rc 0
    as well.
  So the gate exists on both sides but at a different **stage**: Go applies it in
  `ValidateServerConfig` (`ValidateUnsafeFeature`, `pkg/config/v1/validation/validator.go:22-27`,
  called for `tokenSource.Type == "exec"` at `pkg/config/v1/validation/auth.go:34-35`), which both
  Go's run path (`cmd/frps/root.go:85-94`) and its verify (`cmd/frps/verify.go:46-48`) run;
  frp-rs applies it only in service construction (`frp-server/src/service.rs`, via
  `frp_core::auth::validate_token_source_unsafe`), which `verify` never reaches. The client has
  carried the same divergence since its verify existed (`frp-core/src/config/tests.rs`:
  "Go refuses both spellings … frp-rs strict `verify` exits 0").
  **Done-when:** run the gate on the load path (one place, both binaries, both commands) so
  `verify` refuses what the daemon refuses, and give each row above a measured pin; or record it
  as a deliberate divergence in `docs/developing.md` § CLI inputs **and** in the feature-surface
  policy, with the reason the two stages are allowed to differ. No sha.

  **Done (`3798a727`).** Took the first branch. `run_verify` in both binaries now loads through
  `load_server_config_checked` / `load_client_config_with_presence_checked`
  (`frp-core/src/config/file.rs`), which call the new `check_server_unsafe_features` /
  `check_client_unsafe_features` and reuse the daemons' own predicate
  (`frp_core::auth::validate_token_source_unsafe`), so one place gates both binaries and both
  commands. `--allow-unsafe` is read on the two `verify` subcommands
  (`VerifyArgs { config, strict_config, allow_unsafe }`, `frp-core/src/cli.rs`) instead of
  ignored, and the gate is fail-closed: `--allow-unsafe WrongFeature` is rc 1 (was rc 0). The
  daemon path is untouched and still exits 3 `EXIT_AUTH` on the same config, the documented
  frp-rs extension over Go's rc 1; that divergence is stated in the pins' doc tables
  (`frps/tests/cli_exit_codes.rs:273-282`, `frpc/tests/cli_exit_codes.rs:630-639`) rather than
  moved. Every row above now has a measured pin:
  `verify_runs_the_post_load_allow_unsafe_gate_like_go` in `frps/tests/cli_exit_codes.rs:295`
  and `frpc/tests/cli_exit_codes.rs:651`, plus the loader-level
  `check_client_unsafe_features_gates_both_token_source_spellings` in
  `frp-core/src/config/tests.rs:10825` for the `auth.oidc.tokenSource` spelling, which this round's
  probe table does not cover separately but Go gates through `validateOIDCConfig`
  (`pkg/config/v1/validation/client.go`), so it is an exact-parity arm.
  Teeth: `Ok(())` for either checked wrapper reds the spawn pin's refuse row
  (`frps/tests/cli_exit_codes.rs:310:5`, `frpc/tests/cli_exit_codes.rs:665:5`),
  widening the predicate to `unsafe_features.is_empty()` reds the fail-closed row
  (`frps/tests/cli_exit_codes.rs:353:5`, `frpc/tests/cli_exit_codes.rs:712:5`), and deleting
  the `auth.oidc_token_source` arm reds `frp-core/src/config/tests.rs:10890:14` (the
  `.expect_err` line; the round-1 review measured this head).

  **Round-1 review fixes (`b9ab5473` F1, `436a8130` F5).** Round 1 blocked on a regression
  this fix introduced: `allow_unsafe_parser()` was declared without `.many()`, so a repeated
  `--allow-unsafe` was refused (`Error: argument `--allow-unsafe` cannot be used multiple
  times in this context`, rc 1) on both verify commands and the run paths, where Go's pflag
  appends. That regressed `frpc verify` (the base `971e0fa0` routed it through the
  `.many()`-bearing `ignored_allow_unsafe()`, so it had accepted repeats) and kept
  `frps verify`'s pre-existing refusal (its base inline parser already rejected them). It is now `.many()` plus a flatten of
  each trimmed comma-split occurrence, matching Go v0.71.0 on all three surfaces
  (`--allow-unsafe WrongFeature --allow-unsafe TokenSourceExec` rc 0 in both value orders,
  `--allow-unsafe Ignored,TokenSourceExec` rc 0, `WrongFeature` alone rc 1, no flag rc 1).
  Pins: `allow_unsafe_appends_and_comma_splits_on_every_reading_surface`
  (`frp-core/src/cli.rs:5188`) and three extra rows per binary inside
  `verify_runs_the_post_load_allow_unsafe_gate_like_go`; teeth: a last-wins mutant reds
  `frp-core/src/cli.rs:5207:9`, `frps/tests/cli_exit_codes.rs:408:9` and
  `frpc/tests/cli_exit_codes.rs:767:9`, while removing `.many()` does not compile
  (the deleted `.many()` at `frp-core/src/cli.rs:2636`; the diagnostic labels
  `.fallback(vec![])` at `:2647` and the unsatisfied closure at `:2637`, `E0599`/`E0631` — the
  closure's `Vec<String>` type is the enforcement, so that mutation is killed by the checker
  rather than by a failing assertion).
  F5: the comment in `frp-core/src/config/file.rs:167-193` now names both spellings and Go's
  `validateOIDCConfig` (`pkg/config/v1/validation/client.go`), which gates
  `auth.oidc.tokenSource` exec identically — an exact-parity arm, not an unmeasured one.
- [x] **`frpc verify`'s success line is not Go's, and now differs from `frps verify`'s too.**
  Recorded as "a second, adjacent divergence left alone" by the output-shape round
  (`docs/developing.md` § Output stream and shape on a config-load failure) and mentioned in
  `CHANGELOG.md`; the `frps verify` round gave the **server** verify Go's exact line and
  deliberately left the client's, because moving it touches `frpc/tests/cli_exit_codes.rs` and is
  outside that item's done-when.
  Evidence, measured on Go v0.71.0 and the frp-rs debug binaries (streams separated, rc direct):
  * `frps verify -c <valid>` → both Go and frp-rs print `frps: the configuration file <p> syntax is
    ok`, stderr 0 B — a match.
  * `frpc verify -c <valid>` → Go prints `frpc: the configuration file <p> syntax is ok`, stderr
    0 B; frp-rs prints `Config file <p> is valid` plus three indented summary lines
    (`Server: …`, `Proxies: …`, `Visitors: …`), stderr 0 B.
  The rc, the stream and the verdict are Go's on both; only the sentence differs, and the two
  frp-rs verifies now disagree with each other while each agrees with its Go counterpart on rc.
  **Done-when:** print Go's line (keeping or dropping the summary lines is a separate call worth
  stating) and move `frpc/tests/cli_exit_codes.rs`'s exact-bytes pins in the same commit, or record
  the divergence as deliberate **with the asymmetry to `frps verify` named** in
  `docs/developing.md`. No sha.
  Done: fixed in #418 (`4e53bbe9`). `frpc verify -c <valid>` now prints Go's exact
  sentence `frpc: the configuration file <path> syntax is ok` (`frpc/src/main.rs:800`;
  Go `cmd/frpc/sub/verify.go:52`, measured on Go v0.71.0: stdout exactly that line,
  stderr 0 B), followed by the three indented summary lines (`  Server:`, `  Proxies:`,
  `  Visitors:`). Those three stay deliberately: they are an frp-rs addition Go does not
  print, and `frpc/tests/legacy_ini_fixture.rs` observes the vendored Go legacy fixture's
  43 proxies / 2 visitors through the `Proxies:`/`Visitors:` counts, so dropping them
  would remove that test's only observation channel. The `frps verify` / `frpc verify`
  asymmetry is therefore narrowed to the three lines, not the sentence. Measured at this
  head on a minimal config (`g.toml`): Go stdout 52 B, frp-rs 104 B — the 52 B delta is
  exactly the three summary lines. Pins: `frpc/tests/cli_exit_codes.rs::verify_good_config_exits_0`
  moved from a `.contains("is valid")` substring to exact whole-stdout bytes, and the
  `is valid` substring pins and prose rows in `frpc/tests/legacy_ini_fixture.rs`,
  `frpc/tests/cli_inputs.rs`, `frp-client/src/service.rs` and
  `frp-core/src/config/tests.rs` moved with it. No assertion was weakened and no test was
  deleted. `docs/developing.md`'s "left alone" paragraph, its `--strict-config` table rows
  and the byte-count rationale are corrected on the same branch.
- [x] **`frps` does not register Go's `--vhost-http-timeout`, so an argv Go's `frps` accepts is
  refused here — on both paths.** Surfaced by the `frps verify` round's flag-surface work.
  Evidence, measured on Go v0.71.0 and the frp-rs debug binaries (own config and free port per row,
  streams separated, rc direct, children bounded and reaped):
  * Flag-set diff from the two binaries' rendered `--help`: **Go-only = {`vhost-http-timeout`}**,
    frp-rs-only = {`config-dir`, `log-format`}. So this is the one Go `frps` root flag frp-rs does
    not model at all (the config-file key `vhost_http_timeout` **is** supported — `docs/config.md`).
  * `frps --vhost-http-timeout 30 -c <valid>` → Go rc **143** (bounded: `frps started
    successfully`); frp-rs rc **1**, `` `--vhost-http-timeout` is not expected in this context ``,
    identical on the base (`37f91cd`) and the head — a **pre-existing** gap, not introduced by the
    `frps verify` work.
  * `frps verify --vhost-http-timeout 30 -c <valid>` → Go rc **0** (`syntax is ok`; `verifyCmd`
    ignores the flag); frp-rs rc **1**, the same refusal. Newly *visible* on `verify` because
    `verify` is new.
  **Done-when:** register the flag on the run path with Go's default (`60`,
  `pkg/config/flags.go:237`) and let `verify` inherit it through the shared builder, with one
  end-to-end row per path; or record it as a deliberate surface reduction in the feature-surface
  policy. No sha.

---

## P0 — hygiene

  Done: fixed in #418 (`5e72947d`). The flag is registered on the shared
  `SvrTransport` builder, so both the run path and `verify` (which inherits root flags
  through `frps_build`) accept it, under both spellings — `--vhost-http-timeout` and
  `--vhost_http_timeout` — matching Go's `WordSepNormalizeFunc`
  (`pkg/config/flags.go:31-36`, measured on Go v0.71.0: both are rc 0 on `verify`).
  Value: `Option<u64>` applied by `override_server_config` on the flags-only lane;
  `ServerConfig::default()` already carries Go's 60 (`frp-core/src/config/server.rs:247`),
  so an absent flag keeps 60, and with `-c` the file stays authoritative — the same rule
  as the other transport flags. `VALUE_TAKING_LONG_FLAGS` gained both spellings so the
  short-flag, help and rewrite passes agree that the flag consumes its value. Measured:
  `frps verify --vhost-http-timeout 30 -c <valid>` was rc 1 (the bpaf refusal) and is now
  rc 0 with Go's success line byte-identical; the run path starts and listens under both
  spellings (bounded, Go rc 124). The rendered `--help` flag diff against Go v0.71.0 is
  now **Go-only = {}** with frp-rs-only = {`config-dir`, `log-format`}, and the two
  comments that counted this as the one Go-only flag are updated. Tests:
  `vhost_http_timeout_flag_applied_to_server_config` (`frp-core/src/cli.rs`: both
  spellings → `Some(30)` and applied, absent → 60) plus
  `vhost_http_timeout_flag_starts_and_listens` and
  `verify_accepts_vhost_http_timeout_both_spellings_and_prints_go_line`
  (`frps/tests/cli_exit_codes.rs`); `ci.yml`'s `FRPS_CLI_TESTS` 29 → 31. Residual filed
  below: the value is `u64` where Go's is `int64`, so `-1` is refused here and accepted
  there.
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

- [x] **`repo-health.sh`'s doc-figures gate tracebacks under a sparse checkout.** The curated
  `doc_claims` block's `vendor_version` (`scripts/repo-health.sh:1087`, heredoc from `:937`) opens
  `vendor/<crate>/Cargo.toml` unconditionally, so a tree whose worktree does not materialise it
  raises instead of reporting. Reproduce:
  `git sparse-checkout init --cone && git sparse-checkout set docs scripts && bash scripts/repo-health.sh`
  → `Traceback (most recent call last):` / `File "<stdin>", line 155, in <module>` /
  `File "<stdin>", line 152, in vendor_version` /
  `FileNotFoundError: [Errno 2] No such file or directory: 'vendor/rustls/Cargo.toml'`, after which
  the run reports `FAIL  a live doc quotes a figure the tree no longer matches`. Pre-existing: the
  `f8f127f` script prints the identical traceback (same `<stdin>` lines 152/155) on the same tree —
  re-measured 2026-09-23 during the path-scan work, not caused by it. The path-scan gate itself
  fails closed there (242 `read error:` lines → exit 3), so nothing is certified green.
  **Done-when:** `vendor_version` treats a missing manifest as a loud, non-traceback failure (an
  explicit `FAIL … vendor manifest missing` line, or a documented "partial tree" exit 3 reported
  once before the entries that need it). No sha.

  Done (branch `fix/p0-repo-health-script`, based on `main` @ `0a8aed4`): the `doc_claims` block now
  preflights its complete measurement-input set in one run — `scripts/compat-test.sh`,
  `scripts/protocol-matrix.sh`, `scripts/rust_comments.py`, `frp-core/Cargo.toml`, the two bench
  sources, each `vendor/<crate>/Cargo.toml`, and both crate `src` directories — and an input the tree
  does not carry or cannot read is reported *before* the entries that need it:
  `FAIL partial tree: <path> is missing — cannot measure the doc figures (sparse checkout?)`,
  `FAIL vendor manifest missing: <path>`, or `FAIL … is unreadable (<reason>)` with the real reason
  (`Permission denied`, `not a regular file`, `not valid UTF-8`), after which the block exits 3 and
  `repo-health.sh` prints `FAIL doc figures not evaluated — the tree is partial (exit 3)` and keeps
  the run red. A source walk that cannot complete exits 2 with its own line; a genuine figure
  mismatch keeps `a live doc quotes a figure the tree no longer matches`. Reproduced on the item's own
  command (`git sparse-checkout init --cone && git sparse-checkout set docs scripts`): pre-fix
  `FileNotFoundError: [Errno 2] No such file or directory: 'vendor/rustls/Cargo.toml'` plus the
  docs-blame line; post-fix 0 tracebacks, the full 11-input set checked and the 8 missing inputs
  reported in one run, exit 1. The first two
  review rounds found the same class still reachable *inside* the block — `unsafe_counts`' unguarded
  `.rs` reads, a missing or emptied `frp-core/src` measuring a false 0, a non-UTF-8 input tracebacking,
  and a FIFO blocking the read — all closed in the same PR, each with a before/after probe in the
  review record. Residue (pre-existing, unchanged, now recorded as the two new items below): read
  sites outside this block (the `Code size` walk, the bash `grep` on `README.md`, the curated-claims
  `open()` on a doc path, the SAFETY/report walks) can still block on a FIFO, and the version/SAFETY
  gates can print `ok` rows computed from a tree they could not read.
- [x] **`repo-health.sh` derives its root from `$0`, so a symlinked script scans the wrong tree.**
  `cd "$(dirname "$0")/.."` (`scripts/repo-health.sh:23`) resolves the *symlink's* directory: a
  symlink to the script placed in a subdirectory makes the whole run treat that subdirectory's
  parent as the repository root. Guarded form: the fail-open half — a wrong root certified from an
  enclosing repository's index — is closed by the `git rev-parse --show-toplevel` check below; what
  remains is that the run scans the wrong subtree loudly, red or floor-failed. Measured
  2026-09-23 by symlinking the script into each subtree, `docs/` reports 204 stale refs,
  `frp-core/` 9, `frp-core/src/` 6, `frp-client/` 13 and `frp-server/` 4, while `frpc/`
  (4 scannable files), `frpc/src/` (3) and `frp-server/src/` (32) hit the size floors and exit 3.
  The fail-open half is now closed: a wrong root that *does* hold an invalid `.git` entry (an
  empty `.git` directory, say) inside a real repository runs `git ls-files` against the enclosing
  repo's index, and the `git rev-parse --show-toplevel` guard rejects it (`the index belongs to
  another tree: git --show-toplevel reports R, cwd is R/sub`) with exit 3. (An earlier
  transcription of this list said `frpc/src` 6; that figure is `frp-core/src`, which reproduces at
  6 — `frpc/src` really is 3 files and floor-failed.) Every wrong-root run also logs
  `walk error: docs/archive: No such file or directory` from the archive report.
  **Done-when:** resolve the real script path (`readlink -f` or `cd -P`) before deriving the root,
  or refuse to run when the resolved root is not the tree containing the script. No sha.

  Done (branch `fix/p0-repo-health-script`, based on `main` @ `0a8aed4`): the root is now derived
  from the physical script path — `${BASH_SOURCE[0]:-$0}`, a bare name resolved against the caller's
  cwd and then `command -v`, symlinks followed with a bounded `readlink` loop (`readlink -f` is not
  POSIX and older macOS/BSD releases lack it) and `cd -P` on the result. Measured on the item's own
  shape: a link at `frp-core/src/rh-link.sh` invoked as `cd frp-core/src && bash rh-link.sh` scanned
  `frp-core/` pre-fix (`canonical (frp-core/Cargo.toml) :` empty, nine
  `grep: … No such file or directory` lines — eight distinct paths, `frp-core/Cargo.toml` twice —
  exit 1) and the repository root post-fix (exit 0,
  `RESULT: invariants hold`); a `docs/`-level link from the repository root and from inside `docs/`,
  a two-hop relative chain, an absolute path, `bash ./scripts/repo-health.sh`,
  `bash scripts/./repo-health.sh`, a PATH invocation with a decoy same-named file in the cwd, a path
  containing a space, `env -i`, `sh` and the `.git`-less tarball all land on the repository root. The
  complete-tree report stays byte-identical to the pre-fix script on stdout and stderr (exit 0 both).
  Residue (pre-existing, unchanged, measured): a hard link in a subtree still resolves to the link's
  directory (no syscall returns a hard link's real path) and `bash <(cat scripts/repo-health.sh)`
  resolves to `/dev`; `source` now resolves the real file but still `cd`s and `exit`s in the caller's
  shell.

- [x] **Read sites outside the doc-figures block still block on a non-regular file.** The
  doc-figures path now refuses a non-regular measurement input before opening it, but other read
  sites do not. Measured 2026-09-24 (macOS 26.6.2, no `timeout(1)`; a kill watchdog bounded each probe
  at 20 s, each killed with zero `FAIL` lines and no `RESULT` line): a FIFO named
  `frp-core/src/zz.rs` hangs the `Code size` section's `find … -name '*.rs' | xargs cat`; a FIFO at
  `README.md` hangs the version gate's bash `grep`; a FIFO at `docs/developing.md` hangs the
  **path-reference scan** (that scan, not the curated-claims `open()`, is a live doc's first reader);
  and a symlink at `vendor/rustls/Cargo.toml` whose target flips between a regular file and a FIFO
  hangs the Vendored-crates loop, whose `[ -f ]` test and `grep` are two separate processes (6 of 20
  flipper runs killed at 8 s). The pre-fix script hangs identically, so this is pre-existing, not a
  regression. **Done-when:** each read site refuses (or bounds) a non-regular file, with one probe per
  site showing a loud non-zero exit instead of a hang.

  Done (branch `fix/repo-health-read-sites`, based on `main` @ `fe37358`): every read site refuses a
  non-regular file instead of blocking on it. Named paths — the version gate's seven sources, the
  vendored manifests, `rust-toolchain.toml`, the workflow files — go through `read_regular`, one
  `python3` doing `os.open(O_RDONLY|O_NONBLOCK)` + `os.fstat` on the *same* fd, so a path flipping
  regular↔FIFO between a test and the open cannot slip through and a FIFO's blocking `open()` is
  never reached (this host has no `timeout(1)`, so a shell-level bound is not portable). The
  recursive source counts are one python walk (`os.walk(followlinks=False)` + the same fd guard)
  instead of `find -L … | xargs cat` / `-exec grep`, the gated python blocks use an equivalent
  `safe_read`, and the two workflow scans consume the bytes the guard read rather than re-opening the
  files. `.git` is resolved *without* git (directory or gitfile + `commondir`) and
  `HEAD`/`config`/`index`/`commondir` must be regular before any git call; every git call is bounded
  (`git_bounded`, 15 s; the path scan 30 s) and sees the same `GIT_*` environment sanitisation as the
  path scan. Measured with watchdog-bounded probes: a FIFO at `frp-core/src/zz.rs`,
  `frp-server/tests/zz.rs`, `README.md`, `docs/developing.md`, `.github/workflows/zz.yml`,
  `.git/config`, `.git/HEAD`, `.git/index` or `.git/commondir` hung the pre-change script (killed,
  zero `FAIL` lines, no `RESULT`) and now exits 1 naming the path; a flipping symlink at
  `vendor/rustls/Cargo.toml` hung 6/20 → 0/20, `frp-core/Cargo.toml` 15/20 → 0/20,
  `rust-toolchain.toml` 11/20 → 0/20, a crate `*.rs` 13/20 → 0/12, the workflow set 2/12 → 0/15, a
  flipping `.git/index` 4/4 (one still running past 75 s) → 0/4, the worst case bounded at 33 s by
  the path scan's timeout. Residue (all measured, none a false green): with `grep`/`sed`/`awk`
  absent, gates outside the read guard word a *content* failure where the tool is missing (red
  either way); a symlinked `.rs` *file* is double-counted by the python walks (recorded below); a
  directory named `*.yml` and a symlinked directory under `.github/workflows/` are now documented in
  the gate's own known-not-covered list; `--sizes` and non-host platforms are unmeasured.
- [x] **Two gates print `ok` rows computed from a tree they could not read.** With
  `frp-core/Cargo.toml` unreadable the version gate compares `""` to `""` and prints
  `ok    frp-core/Cargo.toml`; with `frp-server/src` absent the SAFETY gate prints
  `ok    every unsafe block has a // SAFETY: justification` while that crate's file list is empty
  (the other three crates are still scanned). Measured 2026-09-24 by the second (adversarial) review
  round. Both runs still exit 1 for other reasons, so these are false `ok` rows in the report rather
  than a false green — the same class the doc-figures gate no longer has. **Done-when:** a gate whose
  input is missing or unreadable reports that instead of an `ok` row, pinned by a probe.

  Done (branch `fix/repo-health-read-sites`, based on `main` @ `fe37358`): a source a gate cannot
  read is reported instead of compared. `read_into` refuses a missing / unreadable / non-regular
  path with the reason in the message and never prints `ok`; `check_ver` distinguishes "no version
  found in `<path>`" (the file *was* read, and the wording is what needs checking) from "not
  evaluated" (it was not read), and prints `canonical version unknown — not compared` instead of an
  empty `(expected )`; a refused `frp-vnet/Cargo.toml` no longer prints an empty `info` row; an
  absent `<crate>/src` is noted, so both the Unsafe-usage table (whose exit status is now checked in
  bash) and the SAFETY gate report "not evaluated" instead of `ok`; and the two workflow scans read
  the file set through the guard first, so any refusal prints `not evaluated`. Measured:
  `chmod 000 frp-core/Cargo.toml` → zero `ok` rows, `canonical version unknown — not compared`;
  `rm -rf frp-server/src` → `scan error: frp-server/src is not a directory — crate not scanned` +
  `FAIL unsafe/SAFETY scan failed (exit 4)`, no `ok`; an unreadable **regular**
  `.github/workflows/evil.yml` holding a real `rustup default stable` was the worst case — the
  pre-change script printed `ok    no floating toolchain selection under .github/workflows/` and
  `RESULT: invariants hold` at rc 0, and now exits 1 with the file named and both workflow scans
  "not evaluated" (`chmod 000 .github/workflows/` likewise); with `python3` absent every source
  reads `not evaluated — python3 not found (a green run needs it)` instead of blaming the file; with
  `awk`/`sed` absent the workflow verdict is unchanged, because that scan is python and its output
  is parsed in bash. Residue: the workflow scan walks with `os.walk(followlinks=False)`, so a
  symlinked directory under `.github/workflows/` and a directory named `*.yml` are not covered
  (documented in the gate's own known-not-covered list); the tracked-`__pycache__` and
  symlinked-`.rs` items below are unchanged by this work.

- [x] **A committed `__pycache__` byte-code file is tracked in the repository.**
  `scripts/__pycache__/rust_comments.cpython-314.pyc` has been tracked since `84a621f` (#354): a
  CPython-version- and platform-specific artifact that churns on any diff of the module, is
  meaningless on another interpreter, and is exactly what `.gitignore` is for. Measured 2026-09-25
  during the read-site work (present at `fe37358` and still present at the branch head). Not a
  correctness issue — Python validates the source's mtime/size and falls back to it, and the
  `.git`-less walk fallback is unaffected. **Done-when:** the file is untracked, `__pycache__/` is
  in `.gitignore`, and `bash scripts/repo-health.sh` still exits 0.

  Done (measured 2026-09-26, untracked in this branch, based on `main` @ `774ed26`): both halves of
  the done-when. Pre-fix blob, observed before the untracking —
  `git rev-parse --verify 774ed26:scripts/__pycache__/rust_comments.cpython-314.pyc` →
  `8bc4eaa077a244bcdc2f56903103e690910b8d18`; no sha is invented for the fix, this branch's own
  commit is the untracking. `git ls-files scripts/__pycache__` listed that one path before and
  prints nothing after `git rm --cached scripts/__pycache__/rust_comments.cpython-314.pyc`. At the
  head of this branch, with the ignored copy still on disk as in this worktree,
  `git status --porcelain --ignored scripts/__pycache__` prints exactly `!! scripts/__pycache__/`
  (24 bytes; ignored by the new `__pycache__/` line in `.gitignore`, which has no leading slash and
  so matches at any depth) and nothing else. That output is precondition-dependent: in a fresh
  checkout of the same commit the copy is absent with its directory, and the same command prints
  **nothing at all** (0 bytes, exit 0) — measured both ways at this head. The transient index
  state between that `git rm --cached` and its commit (`0a66def`) printed the staged deletion as
  well — `D  scripts/__pycache__/rust_comments.cpython-314.pyc` — which an earlier draft of this
  block quoted as the head state; that line is gone once the deletion is committed. The `.pyc` may
  stay on disk: `rm -f` of the 5035-byte worktree copy did not change any verdict —
  `bash scripts/repo-health.sh` exited **0** before and after, with byte-identical output (the
  artifact is not an input to any gate), and the run did **not** recreate it, because all ten of
  the script's `python3` invocations pass `-B` (so the tracked copy must have come from an ad-hoc
  import, not from the gate). The worktree copy was byte-identical to the blob it was untracked
  from — md5 `0893cb97642c7c462a62e1d1ab15baab` before deletion, and
  `git hash-object scripts/__pycache__/rust_comments.cpython-314.pyc` =
  `8bc4eaa077a244bcdc2f56903103e690910b8d18`.
- [x] **A symlinked `.rs` *file* is double-counted by the python source walks.** `ln -s
  kcp/session.rs frp-core/src/zz.rs` makes `unsafe_counts` (and the printed `Code size` walk) read
  the same file twice: the printed block count becomes 22 while the curated `CLAUDE.md` claim says
  21, so `DOC-FIGURES` fails and blames the docs for a tree that is merely symlinked. Measured
  2026-09-25 (both the pre-change `find`/`grep` and the new `os.walk` behave the same way, so this
  is pre-existing, not introduced). A symlinked *directory* is no longer followed (it is documented
  as not covered). **Done-when:** a symlinked `.rs` whose target is inside the same crate root is
  counted once (by real path), or the `Code size` and unsafe counts both name the duplicate instead
  of silently disagreeing with the curated claim.
  Done (measured 2026-09-29, `fix/symlink-double-count` cut from `main` @ `f177e493`): every counted
  `.rs` walk keys each file on `os.path.realpath`, deduping **per scope** — `rs_texts`
  (`scripts/repo-health.sh:290` the `seen` set, `:300`/`:309` the per-branch realpath) is called
  twice per crate, once over `<crate>/src` for Code size / lines / SAFETY cmts (`:329`) and once over
  the whole crate dir for the test-function / proptest counters (`:339`), so an alias outside `src/`
  can neither mask the real file nor be attributed to no scope at all; the printed unsafe table
  (`:530-536`), the SAFETY-justification gate (`:653-660`) and `unsafe_counts` (`:2147-2153`) carry
  their own `seen`, and the comments at `:268-286`/`:320-326` describe that two-scope model.
  Measured on one tree with
  `ln -s kcp/session.rs frp-core/src/zz.rs` present: `bash scripts/repo-health.sh` rc **1**,
  `frp-core` Code size **70 files / 78342 lines**, unsafe row **22/3/1/24**, test functions 2501,
  `DOC-FIGURES: FAIL` (`FAIL #33 CLAUDE.md:172 says 21, the tree measures 22`) → rc **0**, **69 files
  / 76510 lines**, **21/3/1/23**, 2481, `DOC-FIGURES: ok — 53 curated doc figure(s)`; with no symlink
  the whole output is byte-identical before and after (`diff` of the two runs empty, so no figure
  moved on a clean tree).

  Round 1 shipped one shared walk for both scopes, and review caught a silent regression: with
  `ln -s src/kcp/session.rs frp-core/zz_alias.rs` the alias won that shared `seen` and, being outside
  `src/`, was attributed to no scope, so the real 1832-line `frp-core/src/kcp/session.rs` was counted
  zero times — rc **0**, `frp-core` **68 files / 74678 lines**, unsafe **21/3/1/22**, `DOC-FIGURES:
  ok`, against the pre-fix script's 69/76510 on the same tree. Per-scope walks fix it: rc **0**,
  **69/76510**, **21/3/1/23**, 2481 for every alias — inside `src/`, in the crate root, in `tests/`
  (`../src/kcp/session.rs`), and two aliases to one target — each byte-identical to the symlink-free
  run.

  Pinned by `scripts/probe-symlink-file-count.sh` (new, manual — deliberately not wired into CI,
  which has no script-test harness): five alias legs (in `src/`, in the crate root, in `tests/`, two
  aliases to one target) plus a symlinked *directory* leg, all asserting the Code size row, the
  unsafe row and the `test functions` counter equal the symlink-free baseline, with every parsed
  value asserted non-empty first so a parser matching nothing cannot pass vacuously (checked against
  a fake `HEALTH` printing only `frp-core 1 1`). Against the pre-fix script
  (`f177e493:scripts/repo-health.sh`) it fails at the `src/`, crate-root, `tests/` and two-alias legs
  while the symlink-free leg stays green; it passes rc **0** against this fix.
  Sweep of the same class: the `frp-server/tests` `.rs` walk was affected identically (test
  functions 2481→2485, files with tests 208→209, `frp-server/tests` 250→254 with a symlinked `.rs`)
  and shares this fix; a symlinked *directory* **inside a walked root** is still not followed
  (`frp-core` 69/76510 either way); the non-`.rs` walks still double-count and are filed below;
  `docs/README.md` indexing is name-based, not a count, so a symlinked `docs/*.md` is correctly
  reported as an unindexed entry.
  Two model boundaries remain and are filed below rather than fixed here: a symlink whose target is
  in *another* crate is counted in both crates, and a hard link is not deduped.

  Round 3 (review caught the change shipping a claim it falsified): the blanket "a symlinked
  *directory* is still not followed" was too broad. `os.walk(root, ..., followlinks=False)` scandirs
  its own root, so `followlinks=False` never applied to `<crate>/src` once round 2 made that a walk
  root: with `mv frp-core/src /tmp/x && ln -s ../frp-server/src frp-core/src` the Code size row read
  `frp-core` **32 files / 59146 lines** — frp-server's tree — and the SAFETY column **1**, where the
  base script read **0 / 0** and **0**. `rs_texts` now refuses a scope root that is itself a symlink
  (`scripts/repo-health.sh:287-289`, note + return), and the three other `<crate>/src` walks that
  round 2 made root-level refuse it the same way: the printed unsafe table (`:523-528`), the
  SAFETY-justification gate (`:648-652`), and `unsafe_counts` (`:2140-2145`, a `PartialTree` whose
  detail says "is a symlink" rather than the misleading "is missing"). Measured after: rc **1**,
  `frp-core` **0 / 0**, no `frp-core` row in the unsafe table, and the doc-figure gate names the
  cause (`FAIL partial tree: frp-core/src is a symlink (scope root refused) — cannot measure the doc
  figures`); the `top_only` `frp-server/tests` counter is refused too, so it reads **0** instead of
  the **137** it printed while following `frp-client/tests` — a count the whole-crate walk never
  included, so the report had been internally inconsistent. Legs 7-8 of
  `scripts/probe-symlink-file-count.sh` pin both (rc != 0 and `0 / 0` / counter 0); against the
  round-2 script the probe fails exactly there (32/59146, 137). A symlinked directory *inside* a
  walked root remains not followed. The no-python3 `find -L` fallback still follows a symlinked scope
  root — not covered, already red on that path.

  Ledger: base **25 open / 108 closed** → round 1 **26 open / 109 closed** (this flip plus the two
  filings below) → round 2 **27 open / 109 closed** (the boundary filing below; total 136); round 3
  files nothing new (the finding is fixed here), so it stays **27 open / 109 closed**. No
  CHANGELOG bullet: `## Unreleased` is user-facing
  (Features/Changed/Fixed/Docs) and the recent tooling/test/doc-only commits `f177e493`,
  `c4357fc5`, `66be9ce1` added none.
- [x] **A newline in a workflow filename is mis-parsed by the workflow-scan protocol.** The scan
  hands its hits to bash as `C <path>:<line>:<text>` / `D …` / `E …` lines on stdout and the wrapper
  parses them with `case`. A tracked file whose *name* contains a newline (git can track such names;
  the path scan already handles them with `surrogateescape`) splits a hit line, and the fragment is
  re-parsed as a hit of its own: measured 2026-09-25 by the adversarial review with a file named
  `a<LF>C forged.yml`, which produced a bogus `FAIL 1 \`toolchain:\` input(s)` naming
  `forged.yml:5` while the real witness was truncated to `.github/workflows/a`. False-FAIL direction
  only — no false green, and the real violation is still reported. **Done-when:** the wrapper refuses
  or skips a workflow path containing a newline (or the protocol escapes it), pinned by a probe.

  Done: fixed in #415 (`38517d2d`). `wf_scan` now joins the path first and refuses any workflow
  **path** — filename or directory component — containing a newline (or CR) before it reaches the
  `C`/`D`/`E` protocol: `FAIL  workflow path with a newline in its name was not scanned: <path>`
  (newline escaped in the message) plus both `…scan not evaluated — a workflow file could not be
  read` rows, rc 1, fail-closed. Measured: the review's `a<LF>C forged.yml` filename shape forged
  `forged.yml:8:          toolchain: 1.98.0` and a fabricated `FAIL` row for the `toolchain:` input
  check before the fix, and is refused after it (the item's `FAIL 1` was the first cut's count; the
  measured values are 2 for this shape and 1 for the directory shape, and the script comment states
  both shapes without a count); the **directory** shape
  `sub<LF>C forged.yml/probe.yml`, which defeated the first
  cut because its guard tested the basename only, is refused too. Both shapes are pinned in
  `scripts/tests/repo-health-fixtures.sh` (scenarios 2 and 3).
- [x] **The exit-code mapping between the gate's python blocks and `repo-health.sh` is unpinned.**
  Measured 2026-09-26 at this branch's head: the script itself can only exit **0 or 1** — every
  assignment is `fail=0`/`fail=1` (`grep -n "fail=" scripts/repo-health.sh`; `grep -c "fail=[234]"`
  is 0), the explicit early exits are `exit 1` (`:55`, `:73`) plus the `|| exit 1` fallbacks on the
  root-resolution `cd -P`/`readlink` steps (`:64`, `:65`, `:78`), and the tail is `exit "$fail"`
  (`:2328`). The statuses 2/3/4 belong to the python blocks. Census with `ast` over all ten inline
  blocks (eight heredocs, two `-c` bodies), comments excluded: `sys.exit(2)` ×**2** (`:105`,
  `:2134`; a third textual hit is a comment at `:2095`), `sys.exit(3)` ×9, `sys.exit(4)` ×4,
  `sys.exit(5)` ×1, `sys.exit(1)` ×1 (`:2253`), plus the computed
  `sys.exit(4 if state['bad'] else 0)` (`:1116`) and the second inline block's
  `sys.exit(127)`/`sys.exit(124)`/`sys.exit(r.returncode)` (`:765`, `:768`, `:770`);
  `IndexUnavailable` is caught at `:1721` (a `raise` — the toplevel guard's — is at `:1677`) and
  exits at `:1725`. The bash side turns each block status into a `FAIL` row and sets `fail=1` —
  several rows carry the number (the path scan interpolates it: `(exit %s)`, `:1775`; the
  doc-figures mapping branches on it: `(exit 3)` at `:2271`, `(exit 2)` at `:2274`), while others name
  the reason in words (`read_into`'s `missing`/`not a regular file`/`Permission denied`, set at
  `:142`-`:144` and printed at `:147`; the source-counts block's "source counts incomplete (see scan
  errors above)", `:333`; the workflow scan's "a workflow file could not be read", `:1124`).
  The prose drifted because the shorthand "the gate exits 3" gives the block's
  status the whole script as its subject; it appeared in `docs/developing.md:915`/`:924` and
  `TODO.md:1324`/`:1330` and had to be corrected in this PR (the #368 block above), while
  `docs/developing.md:977` already stated the mapping correctly. Nothing prevents it drifting back:
  there is no test harness for `scripts/repo-health.sh` anywhere under `scripts/`, and CI only runs
  the gate itself (`.github/workflows/ci.yml:102`, whose comment at `:91` says
  "scripts/repo-health.sh exits 1 on drift"). **Done-when:** a fixture-based check — a throwaway
  tree, e.g. a gitfile whose gitdir is gone or a repo missing a tracked path, so the run needs
  seconds, not a whole-tree scan (a full `bash scripts/repo-health.sh` measures ~2.6 s here) —
  asserts both the process rc the wrapper returns (**1**, never 3) and the `(exit 3)` annotation on
  the corresponding `FAIL` row, so a future bare `exit 3`/`fail=3` regression, or a re-drifted
  "the gate exits 3" claim, fails a test.

  Done: fixed in #415 (`12b49bb7`, hardened in `8efa9aa5`). New
  `scripts/tests/repo-health-fixtures.sh` builds a throwaway tree, runs the gate against it, and
  asserts both halves on the *named* row: the process rc is **1** (not the python block's 3) and
  the `FAIL  archive path scan failed (exit 3)` row is printed — matched by `grep -qF` on the row
  text, because a partial tree already prints two unrelated `(exit 3)` rows
  (`path-reference scan produced no result`, `doc figures not evaluated — the tree is partial`), so
  an any-row assertion was vacuous. Teeth measured by four mutations, each reverted byte-identical:
  `scripts/repo-health.sh:1452` `sys.exit(3)` -> `sys.exit(0)` reds it; that row's annotation
  reworded reds it; the basename-only newline guard reds it (scenario 3); containment-before-
  readability reds it (scenario 4). The harness runs as its own step in the `health` job of
  `.github/workflows/ci.yml` (no `continue-on-error`): `RESULT: 12 fixture check(s) hold`, ~0.9 s at
  the time (the follow-up batch grew the harness to 19 checks, ~4.6 s),
  cwd/HOME/locale/`TMPDIR`-robust and leak-free.

- [x] **`ci.yml` spells the guarded test counts out by hand in two lanes, so every added test moves a literal.**
  Evidence (read at this head, `79478ca`): the `frps` CLI exit-code guard asserts its expected
  count twice — `.github/workflows/ci.yml:270`
  `grep -q "test result: ok. 5 passed; 0 failed"` and `.github/workflows/ci.yml:271`
  `[ "$n" = "5" ]` — and the `tiny` sibling (`.github/workflows/ci.yml:278`) repeats the pattern
  with its own pair at `:313`/`:314` (`9`). Both are steps of one job (`tests-unit`,
  `.github/workflows/ci.yml:104`), so the two pairs sit 43 lines apart (`:271` → `:314`) with
  nothing tying them together. Counted at this head as `#[test]`/`#[tokio::test]` attributes:
  `frps/tests/cli_exit_codes.rs` **5**, `frpc/tests/cli_exit_codes.rs` **9** (7 `full`-tier plus
  the 2 `tiny`-gated ones at `frpc/tests/cli_exit_codes.rs:352` and `:375`). Not hypothetical:
  PR #379's first CI run
  ([36231618841](https://github.com/viogus/frp-rs/actions/runs/36231618841), head `4b02c51`,
  branch `fix/strict-config-space`) failed the `frps` step with
  `##[error]frps CLI exit-code guard failed (status=1, listed=5)` at 09:11:26, while the tests
  were green. The captured log the step prints on failure pins which checks failed: at that head
  they still expected `4` (`test result: ok. 4 passed`, `[ "$n" = "4" ]`), and the log shows both
  `Running tests/cli_exit_codes.rs` and `test result: ok. 5 passed; 0 failed` — so those two `4`
  literals were the only red, and the guard failed closed (`:272`). The test that moved the count
  is `space_form_strict_config_warns_on_stderr` (`frps/tests/cli_exit_codes.rs:844`), which the
  step's own comment names at `:232`.
  Two comments in that file are stale at this head:
  * `ci.yml:300` — the `tiny` lane's comment opens "Same three checks as the step above" and
    gives the count of that step (`frps`) as 4 ("4"/"9" tests listed). It was literally right
    when written: at `c4836b7` the only `4` literal in the file was the `frps` step's, and the
    `tiny` lane's own count has been `9` since it was added (`frpc/tests/cli_exit_codes.rs` held
    9 tests at `c4836b7` too, so the `4` is not this lane's earlier count). The `frps` step lists
    **5** now (`:271`), so that `4` is stale.
  * `ci.yml:185` — says `frpc/tests/admin_cli.rs` has "(14 tests)"; it has **25** attributes at
    this head. The figure was written by `f8f127f` (#367) and was true then
    (`git show f8f127f:frpc/tests/admin_cli.rs` counts 14), and `0a8aed4` (#369) and `79478ca`
    (#379) have added tests to the file since. The 14-era measurements at `:201`/`:202` and
    `:215` are point-in-time and were not re-measured here; only the two present-tense claims
    above are stale.
  Keep the hard-coded *expectation*: both reviewers of #379 judged that a guard deriving its
  expected count from the same file it checks can be fooled by wholesale deletion (delete the
  tests together with the expectation and the lane stays green). The follow-up is to give the
  number one home, not to remove it.
  **Done-when:** each expected count lives in one place — a job-level `env:` value consumed by
  both lanes (the primary shape), or a meta-test that only checks the `ci.yml` *literals* agree
  with the counts in the guarded files — so a test-count change cannot leave a stale literal
  behind, and the two stale comments (`ci.yml:300`'s `4`, `ci.yml:185`'s `14`) are corrected. In
  both shapes the expectation itself stays hard-coded in the guard: it is the guard that must not
  take its expected count from the file it is checking.
  Done: each lane's expected count now has one home — a job-level `env:` block on `tests-unit` in
  `.github/workflows/ci.yml` (`FRPS_CLI_TESTS: "9"`, `FRPC_TINY_CLI_TESTS: "11"`) — and both of the
  lane's count assertions (the log grep and the `[ "$n" = ... ]` comparison) read that same value,
  so the duplicate literals the item measured (`[ "$n" = "9" ]`, `:277`, and `[ "$n" = "11" ]`,
  `:322`, 45 lines apart at the base head `0658427`) are now one value per lane. A malformed or
  missing value is rejected before cargo runs (`…must be a non-negative integer (got '')`), and the
  failure text is direction-aware: it prints the three counts distinctly (`env=…, file=…, log=…`)
  and names the single value to move only when the log's summary count and the `-- --list` count
  agree and the file lists **more** tests than the value (`…lists 10 tests, env.FRPS_CLI_TESTS is 9:
  move the single env.FRPS_CLI_TESTS value … from 9 to 10`); a **decrease** says so and sends the
  reader back to the tests instead of down to the value (`…lists 8 tests, env.FRPS_CLI_TESTS is 9 —
  the listed count DECREASED: if you deleted tests, restore them; do not lower this value`). The
  expectation stays hard-coded and is never derived from the file the lane checks — the mutants
  below are what show a deleted test cannot ride along with its expectation. Shape chosen over the
  meta-test: it removes the second site instead of adding a third artefact that must itself be kept
  in sync, and the value the guard reads is the value the message names.
  The item's counts were stale by the time this landed: `cargo test -p frps --test cli_exit_codes --
  --list` lists **9** (not 5) and `cargo test -p frpc --no-default-features --features tiny --test
  cli_exit_codes -- --list` lists **11** (not 9; the file's 11 `#[test]` attributes are 9 admitted
  by the `full` gate plus the 2 `tiny`-gated ones). Both lanes' literals were already correct at
  `0658427`, and had moved twice since the evidence was read: 4 → 5 (#379) and 5 → 9 / 9 → 11
  (#381, `57d9f4b` — the only post-`79478ca` commit that touched `ci.yml`; #382/#383/#384 touched
  neither `ci.yml` nor either guarded file).
  Mutants, each run by extracting the step's `run:` block and executing it against the real cargo
  commands (both lanes pass with the committed values: `frps CLI exit-code guard ok: 9 tests listed
  (expected 9)` and `frpc tiny CLI exit-code guard ok: 11 tests listed (expected 11)`; the two
  source mutants in a scratch copy of the tree, restored afterwards): `FRPS_CLI_TESTS=10` → rc 1
  (`env=10, file=9, log=9`, DECREASED); `FRPS_CLI_TESTS=8` → rc 1 (`from 8 to 9`); `FRPS_CLI_TESTS`
  unset → rc 1; empty → rc 1; `"9 "` / `" 9"` → rc 1; `"*"` → rc 1; a typo'd key → rc 1; only the
  other lane's variable set → rc 1 (every malformed/unset shape exits at the integer check, before
  cargo); one test deleted from `frps/tests/cli_exit_codes.rs` → rc 1 with `env=9, file=8, log=8`
  and the DECREASED text; one test appended → rc 1 with `from 9 to 10`; `FRPC_TINY_CLI_TESTS=12` /
  `=10` → rc 1 with the same two directions.
  Stale comments: `ci.yml`'s `frpc/tests/admin_cli.rs` "(14 tests)" is now **25**
  (`cargo test -p frpc --test admin_cli -- --list`; the file carries 25 `#[test]` attributes and no
  lane counts it, so the corrected figure is marked a snapshot — both reviewers judged that marking
  sufficient and declined a follow-up item). The same paragraph cited
  `frpc/tests/admin_cli.rs:228` for the `unknown field` stdout assertion; `:228` is `fn exit_code`,
  and the first of the four such assertions is at `:253` (also `:285`, `:496`, `:638`), which is
  what the citation now says. The item's other stale comment — `ci.yml:300`'s `4`, the frps count
  quoted inside the `tiny` lane's "Same three checks as the step above" — had already been
  rewritten to `9`/`11` by `57d9f4b`; this change drops the restated per-lane counts from both
  steps' prose (each now points at its own `env.*` value), so the count is written once per lane
  rather than in the gate twice plus the surrounding prose. Left alone deliberately: the 14-era
  point-in-time measurements (`ci.yml`'s "9 of the 14 fail", "8 unit tests ... + 14 spawn-based
  tests") describe the runs they measured; re-measuring their wall time was not this item's scope.

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

- [x] **The `Lint` gate depends on the unpinned runner toolchain, so it can go red on unchanged code.**
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
  Done: pinned by a new `rust-toolchain.toml` at the repo root —
  `channel = "1.98.1"`, `profile = "minimal"`,
  `components = ["clippy", "rustfmt"]`. The channel is an **exact version** on
  purpose (`stable`, `nightly` or a floating `1.98` would track new releases and
  re-open the hazard); `profile = "minimal"` plus those two components is exactly
  what the documented gates need (`cargo fmt --all -- --check`,
  `cargo clippy --workspace --all-targets --all-features -- -D warnings`).
  1.98.1 is the compiler the gate already used: the last green `Lint` job
  (`85f6a15`, run `35786004665`, job `106942858348`) ran on ubuntu-24.04 image
  `20260920.314.1`, whose published readme lists Rust 1.98.1 / Cargo 1.98.1 /
  Rustup 1.29.1 / Rustfmt 1.9.0 — coordinator-measured from that image's readme,
  not re-fetched here. This PR's own base run confirms the same fact from the
  other side, in its log line `stable-x86_64-unknown-linux-gnu unchanged - rustc
  1.98.1 (48a229cea 2026-09-01)`: the pin names the compiler the unpinned lane
  was already resolving, so it closes the race without moving the result.
  Scope: the pin covers every rustup-based job that builds the checked-out tree.
  rustup resolves the file from parent directories (measured), so
  `scripts/frp-stress/` and the `./base` checkout `ab-matrix.yml` builds inherit
  it — that lane's before/after delta stays a single-compiler comparison. It does
  **not** cover the Docker source build, filed as its own item below.
  Mechanism: all 7 `- name: Install Rust stable` + `run: rustup default stable`
  pairs in `.github/workflows/ci.yml` are now
  ``- name: Install pinned Rust toolchain (`rust-toolchain.toml`)`` +
  `run: rustup toolchain install --no-self-update`, and the `lint` job adds
  `- name: Assert the lint compiler is the pinned one`, which reads `channel`
  from the file (never hardcoded) and fails the job with `::error::` unless
  `rustc --version` starts with `rustc <channel> `. The explicit install replaces
  `rustup show`, which also auto-installs the file's toolchain but makes rustup
  1.29.1 print five `warn:` lines that auto-installation is deprecated for most
  commands (`rust-lang/rustup#4836` — reproduced here in a scratch `RUSTUP_HOME`
  with no toolchains: exit 0, 284 s, `the missing active toolchain ... has been
  auto-installed` + `auto-installation is deprecated ...` + 3 more `warn:` lines);
  the replacement is measured on rustup
  1.29.1 in an empty `RUSTUP_HOME` — it resolves the file, downloads 5
  components, installs no rust-docs, and reports the toolchain active "because:
  overridden by `<repo>/rust-toolchain.toml`". Typo behaviour, measured on rustup
  1.29.1: a **misspelled component is loud on a fresh `RUSTUP_HOME`** —
  `components = ["rustfm"]` gives `error: component 'rustfm' for target '<host>'
  is unavailable for download for channel '1.98.1-<host>'` and exit 1 with nothing
  installed, which is the state a CI runner starts in — and only degrades to
  `warn: skipping unavailable component rustfm` with exit 0 once that toolchain is
  **already installed** (the local case), so a local typo of that kind can pass
  unnoticed. An **unknown key in the `[toolchain]` table** (e.g.
  `profilee = "minimal"`, or `component = [...]`) is ignored with no warning and
  exits 0 in both cases, so that one rests on review. A typo in a *value* is
  always loud (malformed TOML, an unknown `profile` and a non-existent `channel`
  all exit 1), and no silent case can leave the compiler unpinned. Also, the gate
  parses only the standard `[toolchain]`
  section form, so the inline-table and dotted-key spellings rustup also honours
  fail closed rather than being accepted unchecked. The
  `actions-rust-lang/setup-rust-toolchain@v1` steps in `compat.yml`,
  `release.yml` (×3), `stress-test.yml`, `xtcp-compat.yml` and `ab-matrix.yml`
  pass no `toolchain:` input, so per that action's `v1` README they install what
  the file specifies — cited, not executed from this host. A `toolchain:` input
  would make that action ignore the file (its `override: true` then beats it),
  which is why the gate below rejects one.
  Gate: `scripts/repo-health.sh` gained a `Toolchain pin` section, printed between
  the `Vendored crates` and `Docs` sections. It fails on: a missing
  `rust-toolchain.toml`; anything other than exactly one toolchain file, at the
  repo root, in `.toml` form — tracked, present, and **not shadowed by an
  untracked one** (a legacy `rust-toolchain` wins over the `.toml` in rustup and a
  nested one wins inside its own directory, measured, and an untracked copy does
  so identically); a `channel` that is absent, outside the `[toolchain]` table,
  or not an exact `X.Y.Z` (single- or double-quoted, trailing TOML comment
  allowed); a `toolchain:` input **on a `setup-rust-toolchain` step** — with the
  step detected in this closed list of forms and no others: inline
  `- uses:`, a quoted `uses:` value, `uses :` with a space, a named step with
  `uses:` on its own line under `- name:` or a bare `-`, and the flow form
  `- {uses: ..., with: {toolchain: stable}}`; and the key detected as a block
  mapping, a flow mapping `with: {toolchain: stable}`, a comma-separated
  `{rustflags: '', toolchain: ...}`, a single- or double-quoted key, or an
  uppercase `TOOLCHAIN:` — in both `*.yml` and
  `*.yaml`; and
  `rustup default` used as a leading `run:` command under `.github/workflows/`. It
  is pure text/file parsing — no rustup and no installed version — so the
  toolchain-less `health` CI job can run it. Falsified in both directions:
  `stable`, `nightly`, `1.98`, `1.98.1.0`, a deleted `channel` key, `channel`
  outside `[toolchain]`, a deleted file, a tracked second `rust-toolchain`, a
  tracked nested `scripts/frp-stress/rust-toolchain.toml`, an **untracked**
  `rust-toolchain`, a workflow `toolchain:` input on the setup step in each of
  those twelve step/key spellings, an injected
  `run: rustup default stable`, its double-spaced variant and a block-scalar
  `rustup default stable` line each exit 1 with the file and value named;
  `channel = '1.98.1'`, `[toolchain] # comment`, `channel = "1.98.1" # comment`,
  a comment naming the removed command and
  `- run: cargo build # rustup default stable was removed` do **not** fail it. Its
  comments list the evasions it does **not** catch (`cargo +stable`, an inline
  `RUSTUP_TOOLCHAIN=stable ...`, `rustup override set`, a `rustc = ...` written
  into `.cargo/config.toml`, a non-leading `rustup default` in a `run:` line, a
  quoted-scalar `run: "rustup default stable"`, a script/Makefile the job invokes,
  a container base image) — the `toolchain:` check's own comment records both what
  it catches and the known shapes it does not see, each measured there and
  explicitly **not a completeness claim**: it is
  scoped to the setup-action step, so a `toolchain:` that overrides nothing is
  ignored (`workflow_dispatch.inputs.toolchain`, `matrix.toolchain`, an `env:`
  entry, a `run: |` body line in another step), and the shapes listed in its
  `KNOWN NOT COVERED` block escape it — among them an anchor or tag token between
  `-` and `uses:` (a narrowing introduced by `476305a`'s rewrite, which `5bf5270`
  caught), a flow sequence with no `-` line, a comment at or below the step's
  indentation before the key, a `#` inside an earlier quoted value on the same
  line, an anchor/alias on the `with:` block, a key consumed by a different
  action, and a case-different action URL (not verified against GitHub) — plus
  fail-closed over-catches, where the gate fails a workflow that never passes the
  input: a `{`/`,` inside a quoted scalar or inline comment, a nested sequence in
  the step, and a key-like line inside a block scalar.
  Docs: `CLAUDE.md` (Build / Test / Lint, plus the clippy row of Current Health),
  `docs/developing.md` § 3 (`### Toolchain pinning`) and one sentence in
  `README.md`.
  Verified in the worktree with **no** `+toolchain` argument — i.e. selected by
  the file: `rustc --version` → `rustc 1.98.1 (48a229cea 2026-09-01)`,
  `cargo clippy --version` → `clippy 0.1.98`,
  `rustfmt --version` → `rustfmt 1.9.0-stable`. Gates:
  `cargo fmt --all -- --check` → exit 0;
  `cargo clippy --workspace --all-targets --all-features -- -D warnings` →
  exit 0 (58.33 s, after `cargo clean -p` on the 6 workspace crates forced a real
  re-check of all of them, 0 warning/error lines);
  `RUSTFLAGS="-D warnings" cargo check --workspace --no-default-features
  --features tiny` → exit 0 and the same with `micro` → exit 0;
  `cargo test --workspace --all-features --lib` → exit 0, 300 (frp-client) +
  870 (frp-core) + 497 (frp-server) + 40 (frp-vnet) passed / 0 failed;
  `bash scripts/repo-health.sh` → exit 0. The assertion step was falsified too: a
  wrong expectation (`1.99.99` with a live `rustc 1.98.1`), an unparsable
  `[toolchain]` channel, and a `rustc` shim reporting `1.96.0` each exit 1 with
  their `::error::` message; and it now passes the two shapes that used to false-fail
  it — `[toolchain] # pinned` with `channel = "1.98.1" # pinned`, and a stray
  `channel` outside the table, which both parsers ignore because they read the
  table (`channel = '1.98.1' # c` passes too).
  CI. The shipped command is measured on the runner by **this PR's own run
  `35828829198`** (`Lint` job `107076491956`, conclusion `success`, head
  `4c729f8`); timestamps below are anchored from that job's log by this author:
  the step's `##[group]Run rustup toolchain install --no-self-update` line at
  `06:54:19.3038416` to `info: it's active because: overridden by
  '/home/runner/work/frp-rs/frp-rs/rust-toolchain.toml'` at `06:54:28.1387715` —
  **≈8.83 s**; the same step in that run's `Security` job (`107076491729`) runs
  `06:53:19.5561254` → `06:53:27.5356438` (**≈7.98 s**). That log contains no
  `rustup show` group and no rustup deprecation warning, and its assertion step
  prints `lint compiler: rustc 1.98.1 (48a229cea 2026-09-01) — matches the pinned
  channel 1.98.1`. The earlier run `35825672987` (`Lint` job `107066732208`) is
  the **pre-fix `rustup show` measurement** — it is where the five deprecation
  `warn:` lines and the ~10 s figure (06:15:28.906 → 06:15:38.473) come from, and
  it must not be read as evidence for the shipped command. The install is neither
  cached nor free: nothing caches `~/.rustup` and hosted runners are fresh VMs, so
  every `ci.yml` run pays it in its cargo jobs — **6 of the 8 jobs on a
  `pull_request`** (`build` is `if: push && (main || tags)`, so it is skipped on
  PRs, verified in run `35828829198`) and **7 of the 8 on a push to `main`**
  (`ci.yml` is `on.push.branches: [main]`, so no tag push reaches this workflow at
  all and the `refs/tags/` clause in `build`'s `if:` is unreachable inside it); the
  8th, `health`, has no Rust toolchain and runs only the gate — plus the
  `setup-rust-toolchain@v1` steps in the other workflows, whose cost was not
  measured. Keying a `~/.rustup`
  cache on `hashFiles('rust-toolchain.toml')` was considered and rejected: a
  second cache key plus save/restore logic across 6-7 jobs to save ~8-10 s per job
  is not worth it. The 5m00.420s measured on this macOS host for the same 5
  components is this host's route to `static.rust-lang.org`, not a runner
  estimate.
  Not verified: the other lanes' results at the time of writing, the
  Windows/macOS release lanes, the Docker image's compiler, and the other
  workflows' install cost.

- [x] **The compat lanes install a floating Go toolchain that nothing uses.**
  Evidence: `.github/workflows/compat.yml:37-39` and
  `.github/workflows/xtcp-compat.yml:54-57` run `actions/setup-go@v5` with
  `go-version: '>=1.22.0'`, so which Go actually gets used is a property of the
  runner image, not of the commit — the same class as the `Lint` item above. In
  the last green `compat` run (`85f6a15`, run `35786004606`, job `106942857867`)
  that range resolved to a runner-image-cached toolchain, not to current Go:
  `Setup go version spec >=1.22.0` → `Found in cache @
  /opt/hostedtoolcache/go/1.26.8/x64` → `go version go1.26.8 linux/amd64`; that
  job ran on ubuntu-24.04 image `20260907.300.1`, whose readme lists cached Go
  1.24.13 / 1.25.14 / 1.26.8, so 1.26.8 was simply what the image carried.
  Nothing in the pipeline invokes it: `git ls-files '*.go'` is empty,
  `git grep -nE '(^|[^a-zA-Z_/.-])go (build|run)' -- scripts/ .github/` finds
  nothing, and `scripts/download-go-frp.sh:29` fetches the **prebuilt** release
  tarball (`https://github.com/fatedier/frp/releases/download/v${VERSION}/…`).
  It is a leftover of a removed path that `CHANGELOG.md:2359-2360` (0.3.1)
  records — `build_go_frp_v2()` (clone + `go build`, cached to
  `/tmp/frp-source-build/`) exists nowhere in the tree, yet
  `.github/workflows/compat.yml:48` still caches that orphaned
  `/tmp/frp-source-build/` under a step named "Cache cargo + go-frp builds".
  **Done-when:** either drop the `setup-go` step, the stale
  `/tmp/frp-source-build/` cache path and the "go-frp builds" wording with the
  lane still green, or pin the Go version and state what consumes it. Today
  nothing consumes it, and the `>=` range makes the resolved version a
  runner-image property.

  **Done (`6c2a9a1a`).** Took the first branch: the `actions/setup-go` step is gone from
  both lanes and the orphaned `/tmp/frp-source-build/` cache path with it
  (`.github/workflows/compat.yml:42-51`, the step now simply named `Cache cargo`). The
  citations in the evidence above (`compat.yml:37-39`, `xtcp-compat.yml:54-57`,
  `compat.yml:48`) are the pre-change state and no longer resolve. Re-measured at the new
  head: `git ls-files '*.go'` is still empty, `scripts/download-go-frp.sh:29` still
  fetches the prebuilt release tarball, `build_go_frp_v2()` exists nowhere, and all seven
  workflow YAMLs parse. `actions/setup-go` survives only in records (`CHANGELOG.md:2360`,
  this file, `docs/archive/plans/2026-06-28-xtcp-testing.md`). No gate update was owed —
  `scripts/repo-health.sh`'s toolchain checks match `rustup default` and
  `setup-rust-toolchain` only, never `setup-go` — and the `compat` lane is green at the
  head.

- [x] **The Docker source build is outside the toolchain pin and floats its own compiler.**
  Evidence, read from `docker/Dockerfile.source` — the Docker build was **not**
  run, so this is a code-read, not a measurement of the image: `:12`
  `FROM --platform=$BUILDPLATFORM rust:1-slim-bookworm AS builder`, a floating
  `rust:1` tag. The build's `COPY` set (`:56-64`, plus `docker/entrypoint.c` at
  `:81`) is `Cargo.toml`, `Cargo.lock*`, `vendor/` and the six crate dirs
  (`frp-core`, `frp-server`, `frp-client`, `frp-vnet`, `frps`, `frpc`) —
  `rust-toolchain.toml` is not copied and there is no `COPY . .`, so the pin never
  reaches the image build, and `cargo zigbuild` (`:71`) runs on the base image's
  default toolchain. `.github/workflows/docker.yml` builds that Dockerfile on
  `pull_request` (`:8-9`) for a 6-component matrix (`:34-41`) and the result is
  pushed to `ghcr.io` (`env.REGISTRY`), so a shipped artifact is built by a
  compiler nothing pins. `scripts/repo-health.sh`'s toolchain gate scans
  `.github/workflows/` only and does not cover this file.
  Unverified reasoning — a naive fix is not sufficient and the image was not
  built: `COPY rust-toolchain.toml ./` at `:56` would not be enough, because
  `:52` `RUN rustup target add $(cat /tmp/rust_target)` installs the musl target
  into the **base image's** toolchain *before* that COPY, so a pinned toolchain
  created afterwards would lack that `rust-std`.
  **Done-when:** either pin the base image tag *and* keep it in sync with
  `rust-toolchain.toml` **by construction** rather than by hand, or put the
  toolchain file in the build context and reorder/extend the target setup so the
  musl target is installed for the pinned toolchain — in both cases with a
  measured `docker buildx build` for at least one component.

  **Done (`6c2a9a1a`).** Took the second branch. `docker/Dockerfile.source:56-58` is now
  `WORKDIR /build` → `COPY rust-toolchain.toml ./` →
  `RUN rustup toolchain install --no-self-update`; the fail-closed assertion follows
  (`:64-70`) and only then `RUN rustup target add $(cat /tmp/rust_target)` (`:77`), ahead
  of `COPY Cargo.toml Cargo.lock* ./` (`:80`). The citations in the evidence above (`:52`,
  `:56-64`) are the pre-change numbering. The base tag still floats (`rust:1-slim-bookworm`,
  `:12`), but the compiler no longer does: the assertion refuses the build when the active
  toolchain is not the file's channel, or when `RUSTUP_TOOLCHAIN` overrode it. Measured on
  the real context with `docker buildx build --platform linux/amd64`: pinned/COPY present →
  `1.98.1-aarch64-unknown-linux-gnu (overridden by '/build/rust-toolchain.toml')`, assertion
  rc 0; COPY dropped → rc 1; stray `RUSTUP_TOOLCHAIN=stable` → rc 1 (the reordering tooth
  with a divergent pin showed the old order leaving the musl target in the base default
  toolchain — `OLD_TARGET=MISSING`, the E0463 `can't find crate for std` root cause — and
  the new order has it present). A full uncached
  `docker buildx build --no-cache … -f docker/Dockerfile.source` then succeeded, logging the
  pinned toolchain (`Finished release profile [optimized] in 5m 19s`, image 3.94 MB). The
  before-image never completed — the default 2 CPU/2 GiB colima VM was OOM-killed — so its
  compiler line comes from the old Dockerfile plus a diagnostic `RUN`, as the PR records.

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
  original #341 report; the run carrying this shape for that PR is Cross-Compat run
  `35260126822` (2026-09-17: the same job's `Run compat tests` printed `86 passed, 0 failed` while
  its protocol matrix printed `8 passed, 3 failed` with `tcp-plain` and `tcp-tls` at zero
  throughput and `tcp-tls-mux` "proxy port not reachable"; the PR merged with that run still red
  and it was never re-run). Its failure set is **not** the one the report's own wording describes
  (`go-to-rust-quic`, then `tcp-tls`/`tcp-tls-mux` plus `ws-plain`), so the report's "2 of 3
  consecutive runs on the same commit" still has no run id behind it; this run is cited as an
  instance of the shape, not as that episode. It is not part of this reproduction.
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

  **Recurrence (2026-09-23 — two more instances, both re-verified from the CI logs, on trees
  that passed the same lanes on other runs):**
  * `5bf5270`'s Cross-Compat run
    [35833904525](https://github.com/viogus/frp-rs/actions/runs/35833904525) (attempt 1,
    `pull_request`) failed in the **Protocol connectivity matrix** step while the compat-tests
    step in the *same job* printed `RESULTS: 86 passed, 0 failed`. The matrix log reads
    `[matrix] retry 1/3 tcp-plain: zero throughput (mbps=0.0)`, `retry 2/3 … (mbps=0)`,
    `retry 3/3 … (mbps=0)`, `[matrix] FAIL tcp-plain: zero throughput (mbps=0)`, then
    `[matrix] FAIL tcp-tls: proxy port not reachable`, ending
    `=== protocol matrix: 9 passed, 2 failed ===`, exit 1. The same job therefore both
    certified the data plane (86 scenarios) and failed to move bytes in the matrix — the two
    halves are different suites and must not be pooled either way.
  * The post-merge push run on `9c1b291`,
    [35840916594](https://github.com/viogus/frp-rs/actions/runs/35840916594), failed in the
    compat-tests step on **attempt 1** with `go-to-rust-wss-plain: proxy port 23802 not
    reachable`, `RESULTS: 85 passed, 1 failed`, exit 1. The scenario logged its
    `=== go-to-rust-wss-plain ===` banner at 09:13:21.735 and the failure at 09:13:38.088 —
    **16.35 s**, consistent with the scenario burning its whole wait window — while
    `go-to-rust-wss-encrypted` and `go-to-rust-wss-mux` passed immediately after it. The
    run-level conclusion is `success` only because the job was re-run (attempt 2); the failed
    attempt is the evidence, and `gh run view --attempt 1 --log-failed` is how it was read.
  Attempt 2 of that same run is a separate, later re-run — `RESULTS: 86 passed, 0 failed` at
  09:53:30 and `=== protocol matrix: 11 passed, 0 failed ===` at 09:55:07, both re-read from the
  attempt-2 log — landing ~39 min after the 09:14:31 attempt-1 failure, not in the same minute.
  Both instances are the item's shape — a scenario failing on a tree that passed the same lane
  elsewhere — and neither can be explained by a data-plane diff.

  **Recurrence (2026-09-26, PR #376's run
  [36207103495](https://github.com/viogus/frp-rs/actions/runs/36207103495) — head `f3e7b96`,
  squash-merged as `1becff8`):** **attempt 1** failed in the **Protocol connectivity matrix**
  step only, repeating the **2026-09-17 matrix signature** with the same scenario set: the
  `retry 1/3`…`retry 3/3` pair on `tcp-tls` and again on `tcp-tls-mux`, each ending
  `[matrix] FAIL …: zero throughput (mbps=0)`, then `[matrix] FAIL ws-plain: proxy port not
  reachable`, ending `=== protocol matrix: 8 passed, 3 failed ===`, exit 1. The *same job's*
  `Run compat tests` step printed `RESULTS: 86 passed, 0 failed` at 01:12:00; the matrix
  failures ran 01:12:33–01:14:23. The diff is the strongest form of this item's evidence: its
  changed files were `.gitignore`, `TODO.md`, `docs/developing.md`, a deleted
  `scripts/__pycache__/rust_comments.cpython-314.pyc` and `scripts/repo-health.sh` — **no Rust
  source at all**, so `frps`/`frpc` were built from inputs identical to `main`'s and nothing on
  the data plane could have changed (the evidence is that file list; no artifact hash was
  compared). Attempt 2 of the same run: `success`. Evidence class: the
  attempt-1 failures and the attempt-2 results were both re-read from this run's logs
  (`gh run view --attempt 1 --log-failed`, then `--attempt 2 --log`) while writing this item.

  **Counted over the occurrences labeled in this item, not a census of the flake** (and not from a
  stored total). Units matter,
  so all three, and "five" is the last one: **four recurrence blocks** record the shape — the
  original report, the PR #351 recurrence, the 2026-09-23 block (two instances) and the
  2026-09-26 block; the PR #338 ETXTBSY block above is a different phenomenon and is not counted;
  **seven failing runs** (2 + 2 + 2 + 1); and **five distinct failing commits** — 2026-09-17 ×2
  (the original report and the PR #351 recurrence: neither carries a run id or commit id in this
  item), `5bf5270`, `9c1b291`, and `f3e7b96` (squash `1becff8`). An earlier reading counted four
  by taking 2026-09-17 for a single failing commit; the item records two separate 2026-09-17
  episodes, which is where the fifth comes from.
  **These five are not the whole flake.** A sweep of `compat.yml` runs for 2026-09-16..18 alone
  finds at least two further runs with the identical signature — compat suite green while the
  protocol-matrix step is red on attempt 1, left red and never re-run — which the labeled five do
  not include: PR #344 run `35261357001` (head `0d1425d`, matrix `8 passed, 3 failed`: `kcp-tls`,
  `kcp-tls-mux`, `quic`) and a `main` push run `35286319673` (head `e1ccec5`, matrix `5 passed,
  6 failed`: `kcp-plain`, `kcp-tls`, `kcp-tls-mux`, `quic`, `ws-tls-mux`, `wss`). So "seven failing
  runs" and "only one was never re-run" are properties of the labeled set, not of the flake.
  The failing scenario is not stable across the five labeled occurrences: **eight** distinct names
  appear there (the sweep's additional runs above add more — `kcp-plain`, `kcp-tls`, `kcp-tls-mux`,
  `ws-tls-mux`, `wss`, `quic`) —
  `go-to-rust-quic`, `kcp-rust-to-rust`, `rust-to-go-tcp-tls` and `go-to-rust-wss-plain` from
  `compat-test.sh`, and `tcp-plain`, `tcp-tls`, `tcp-tls-mux` and `ws-plain` from
  `protocol-matrix.sh` — although the 2026-09-26 run did repeat the 2026-09-17 matrix set, so
  "a different scenario each time" holds only in the loose sense that no two consecutive
  occurrences failed the same *set*. That qualified reading rests on one premise the reader should
  know: the count is over scenario failures only (the PR #338 ETXTBSY unit-test block is excluded,
  as it says itself). The 2026-09-17 ambiguity does not affect it — those two episodes are treated
  as two different commits on the strength of two different labels with no run id behind either,
  and merging them into one would still leave the 2026-09-26 matrix set separated from the
  remaining 2026-09-17 set by two intervening occurrences (the PR #351 recurrence and the
  2026-09-23 pair), so no two consecutive sets would become equal.
  This is still exactly why the item exists, and the one instance that was never re-run *among
  those five* is the
  worse version of the habit, not a better one: **four** of the five were re-run to green (the
  original report on the third run, PR #351 on the third attempt, `9c1b291` on attempt 2,
  `f3e7b96` on attempt 2) while
  **`5bf5270` was never re-run at all** — run `35833904525` is still `attempt 1, failure`, and the
  branch simply moved on to `476305a` (run 35836440857) and `d211d71` (run 35838710545), whose
  Cross-Compat runs were green on attempt 1. So the red run was left red and a new commit was
  pushed over it, leaving nothing on the record that distinguishes "flaked" from "fixed". That is
  why a habit of re-running, or of pushing past, cannot tell the sixth apart from a real
  regression. Nothing above is fixed, and this round claims no fix.

  A further occurrence on this branch: PR #421's `compat` run `36688056654` (job `109798401463`)
  failed the protocol-matrix step with `8 passed, 3 failed` — `kcp-tls` and `kcp-tls-mux` with zero
  throughput and `quic` with its proxy port not reachable — while the compat suite step itself was
  green, the same suite-green/matrix-red shape as the sweep's two extra runs above. The failed job
  was re-run (`109804152976`).

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

  **Progress (2026-10-01, code head `0f1b94c2` on `refactor/extract-ws-listener`, PR #436).** The
  first P1 seam landed: the dedicated-`websocket_port` accept loop moved byte-for-byte out of
  `frp-server/src/service.rs::run` into `frp-server/src/service/listeners.rs` as
  `pub(super) async fn start_websocket_listener(&self, rate_limiter_enabled: bool)` — 289 payload
  lines / 23 677 bytes `cmp`-identical, `frp-server/src/service.rs` 2671 → 2386 lines. The extracted
  block had **no** coverage at all (every lane that enables `websocket` also enables `kcp`, and
  `websocket_port` defaults to 0), so the round adds
  `frp-server/tests/transport_e2e_websocket_port.rs` (in-process frps + frpc over the dedicated port,
  256 KiB then 64 KiB echo, `tcp_mux` off and on) and the `websocket`-without-`kcp` curated CI lane.
  The remaining blocks (HTTP vhost, HTTPS vhost, TCPMux, SSH tunnel gateway, KCP, QUIC, dashboard,
  `tasks.rs`) are tracked in the plan doc, which now records what has landed.

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

- [x] **The "no GC ⇒ stable RSS over weeks" claim has no long-uptime evidence.**
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

  **Done (2026-09-30, code head `5b154c91` on `measure/rss-soak`, PR #424).** The 3-hour head-to-head
  series is published as `scripts/frp-stress/baselines/rss-soak-Mac.jsonl`: `bash scripts/rss-soak.sh
  10800 45` on macOS arm64, 2026-09-30T18:47:54Z → 21:47:54Z, **240 paired samples** at 45 s, one TCP
  proxy per stack over the same proxy set and the same offered traffic (8-connection churn at 40/s plus
  three 5 Mbps steady streams). RSS (KB): frp-rs `frps` 12336 → 10208 (min 9936, max 12592, mean
  10982.3, slope −532.13 KB/h, last-quarter mean −10.1 % against the first), frp-rs `frpc` 11632 → 9344
  (min 9344, max 11872, mean 10316.9, slope −525.92 KB/h, −10.5 %); Go `frps` 33856 → 30064 (min 29568,
  max 37600, mean 31026.7, slope −30.71 KB/h, 0.0 %), Go `frpc` 24288 → 24448 (min 23616, max 25648,
  mean 24627.1, slope +80.1 KB/h, +1.1 %). Neither frp-rs series is monotonically non-decreasing and
  both *decline* over the window, ending at roughly **one third** of Go's RSS (10208 against 30064 KB
  for `frps`, 9344 against 24448 KB for `frpc`), so the claim is **supported at this horizon** — 3 hours
  is not "weeks", and the series makes no claim beyond it. Traffic parity is exact inside the harness's
  10 % tolerance (achieved spread **0.0**): 427200 against 427206 churn round trips, 170183884800
  steady bytes per stack, **0 failed streams**. The host was loaded across the run (1-minute load
  2.27–93.93, mean 28.42; `TIME_WAIT` up to 5108), so the window includes busy periods. The harness
  contribution is separable from the number: `scripts/lib/rss-soak-run-dir.sh` binds every sample and
  the summary to one run directory (a run cannot publish a summary built from another run's samples)
  and `scripts/lib/rss-soak-summary.py` writes the record, both covered by
  `scripts/tests/rss-soak-run-dir.sh` (269 fixture checks) in the `health` CI job. The accepted bound —
  a `ps` stub printing a different plausible value on every sample passes every guard — is recorded in
  `scripts/frp-stress/baselines/README.md`.

**Findings filed by the `[web_server.tls]` fix round (all pre-existing, all measured 2026-09-29 at `ccff127`).
All six were closed in the `fix/webserver-tls-cluster` batch (A–F below, each with its own Done note and
measured evidence); ledger after that batch: 23 open / 104 closed. A seventh finding — a legacy `.ini`
proxy section without a `type` key, filed by the batch's review round — is open at the end of this
section; ledger now **24 open / 104 closed**.**
- [x] **A file that defines both `[webServer]` and `[web_server]` silently discards the whole
  `[webServer]` table — including a nested `[webServer.tls]`.** `normalize_server_config` renames the
  section with `table.entry("web_server").or_insert(v)` (`frp-core/src/config/normalize.rs`), an
  all-or-nothing move: when the snake_case section already exists the camelCase one is dropped, so a
  nested `tls` table written under `webServer` never reaches `normalize_web_server_section`. Measured
  with `[webServer.tls] cert_file = "/nested"` + `[web_server] tls_cert_file = "/flat"` (probe
  `/tmp/wstls-f1/src/main.rs` case `s14`): `tls_cert() == "/flat/cert.pem"` in **both** loader modes and
  in **both** trees — the flat key wins and the nested section is gone, with no diagnostic in
  non-strict mode. This is the one shape in which the "the nested values take precedence" claim on
  `WebServerTlsConfig` is **false** (the claim is qualified on `normalize_web_server_section` and in
  `docs/config.md` now, rather than fixed). It is the same class as the item above — a documented
  precedence claim the code does not honour — so it needs the same treatment: either deep-merge
  `[webServer]` into `[web_server]` (making the nested table reachable and the claim true) or report the
  discarded table. **Done-when:** the chosen behaviour is pinned by a test in both loader modes, and the
  precedence doc names the shape either way.

  Done: the two sections now **merge per key**, `[web_server]` winning each key both define (the
  order the old whole-table `or_insert` resolved in — not inverted), with nested tables merging
  recursively: `merge_section_into` / `or_insert_deep` in `frp-core/src/config/normalize.rs`, called
  from `normalize_server_config` and `normalize_client_config`. Measured with the probe harness
  a temporary in-tree probe harness (before/after transcripts `/tmp/ws-probe-before.txt`,
  `/tmp/ws-probe-after.txt`, reproduced in `/tmp/webserver-tls-cluster-report.md`), case A1 `[webServer.tls] cert_file = "/nested/cert.pem"` +
  `[web_server] tls_cert_file = "/flat/cert.pem"`: before `tls_cert() == "/flat/cert.pem"` in both
  loader modes, after `"/nested/cert.pem"`; A2 disjoint keys `user`/`port` written only under
  `[webServer]` were dropped before (`user="" port=0`) and survive after (`user="camel" port=7501`);
  A3 a key both sections define is still `[web_server]`'s (`user="snake"`); A5 two `tls` tables with
  disjoint keys both survive; YAML and the client `[web_server]` behave the same. Pinned by
  `both_web_server_sections_merge_per_key_in_both_modes` (`frp-core/src/config/tests.rs`). The
  presence detector that mirrors the merge is
  `ConfigPresence::web_server_tls_enable_set_in` (`frp-core/src/config/loader.rs`), pinned by
  `both_sections_present_the_flag_follows_the_merge`
  (`frp-core/tests/web_server_tls_enable_warning.rs`). The precedence prose was re-derived on
  `normalize_web_server_section` (`frp-core/src/config/normalize.rs`), on `WebServerTlsConfig` and
  `WebServerConfig::tls` (`frp-core/src/config/server.rs`) and in the `[web_server]` rows of
  `docs/config.md`.
- [x] **`.ini` files cannot use the nested `[webServer.tls]` section at all: the section name is stored
  verbatim as a top-level key.** `ini_to_toml` (`frp-core/src/config/format.rs`) inserts the bracket text
  as the key, so `[webServer.tls]` becomes the literal top-level key `"webServer.tls"` (and
  `[web_server.tls]` becomes `"web_server.tls"`) — never a `web_server` → `tls` table. Measured (probe
  `/tmp/wstls-f1/src/main.rs` cases `i01`, `i02`, identical in both trees): non-strict loads with
  `tls_cert() == ""` (the whole section dropped silently), strict reports
  `unknown field "webServer.tls"`. The neighbouring shapes **do** work, which is what makes this a trap:
  `[webServer] certFile = …` (a flat key in a normally-named section) loads in both modes, and the legacy
  INI `dashboard_tls_cert_file`/`dashboard_tls_key_file` map onto the flat fields. **Done-when:** either
  the dotted section name is expanded into nested tables before normalization (so `.ini` gets the same
  treatment as every other format) or the limitation is stated in `docs/config.md` with a test pinning
  the current message; a silent drop is not an option.

  Done: the first branch — a dotted header whose first segment is a v1 section name is expanded
  into nested tables **before** normalization, so `.ini` reaches `normalize_web_server_section` like
  every other format: `ini_to_toml` / `ini_section_path` / `insert_ini_section` /
  `INI_NESTED_SECTION_ROOTS` in `frp-core/src/config/format.rs` (the helper was
  `ini_section_mut` before the review round that split the parse from the insert). Measured before/after with the probe
  harness (cases B1/B2): `[webServer.tls] certFile = /nested/cert.pem` loaded `tls_cert() == ""` with
  strict reporting `unknown field "webServer.tls"` before, and `"/nested/cert.pem"` in **both** modes
  after; `[web_server.tls] cert_file` likewise. The first-segment restriction is load-bearing, not
  cosmetic: expanding every dotted header broke Go's shipped legacy fixture
  (`legacy_ini_go_shipped_frps_fixture_loads_end_to_end` failed with `unknown field "plugin"`),
  because Go's own `.ini` path is the *legacy* loader and keeps `[plugin.user-manager]` as one flat
  section name — `pkg/config/legacy/server.go`, the `strings.HasPrefix(name, "plugin.")` loop over
  `gopkg.in/ini.v1`'s `section.Name()` (v0.71.0 source). A literal top-level `webServer.tls = 1` key
  stays a distinct unknown key. A conflict between a scalar `tls` and the expanded table is
  **order-dependent**, and both orders are pinned: `[webServer] tls = 1` before `[webServer.tls]`
  errors (`section [webServer.tls] conflicts with the value already set at `webServer.tls``, rc 1
  both modes), while the reverse order loads rc 0 both modes with the later scalar overwriting
  the expanded table (`tls_cert() == ""`). Pinned by
  `dotted_ini_section_headers_become_nested_tables_in_both_modes` (`frp-core/src/config/tests.rs`);
  `docs/config.md` no longer says the section is unusable in `.ini`.
  Parity note: the expansion is an frp-rs **extension** — Go never reads `[webServer.tls]` from an
  `.ini` at all (its legacy loader ignores the section) — so `.ini` is documented as a first-class
  spelling of the v1 config, not as Go parity.
- [x] **`[web_server.tls] password = "…"` / `user = "…"` land on the real `web_server.password` /
  `web_server.user` fields.** `normalize_web_server_section` re-inserts every unmapped nested key at the
  parent level under its own name (`or_insert`), and `password` / `user` are real `WebServerConfig`
  fields, so a nested section's credentials silently *become* the dashboard Basic Auth credentials
  instead of being refused. Re-measured 2026-09-29 at `ccff127` (probe `/tmp/wstls-f1/src/main.rs` case
  `s15`): `[web_server.tls] user = "nested-user"` + `password = "nested-secret"` loads with
  `web_server.user == "nested-user"` / `web_server.password == "nested-secret"` — in the fixed tree and
  in the base tree alike (`5717fa2` also does it, non-strict), so it is pre-existing, not a mapping
  side effect. This is the mirror image of the `enable` decision above: a nested key that *is* a parent
  field name is re-inserted rather than dropped. **Done-when:** the unmapped-key re-insert is restricted
  to keys that are not parent fields (or the nested table is refused outright), pinned by a test
  asserting a nested `password`/`user` does **not** change `web_server.password`/`web_server.user`.

  Done: the re-insert is gone entirely — an unmapped nested key **stays inside `tls`**, so it can
  never bind a real `WebServerConfig` field: the residue is written back as `web_server.tls` when
  non-empty at the end of `normalize_web_server_section`
  (`frp-core/src/config/normalize.rs`), and `check_strict` descends `web_server` -> `tls` against
  `WEB_SERVER_TLS_KNOWN_KEYS` (`Ctx::WebServer` / `Ctx::WebServerTls`, `child_table_keys`,
  `child_ctx` in `frp-core/src/config/strict.rs`). Every parent field name was checked, not just the
  two in the item: `user`, `password`, `addr`, `port`, `enable_prometheus`/`enablePrometheus`,
  `assets_dir`/`assetsDir`, `pprof_enable`/`pprofEnable`, `custom_404_page`/`custom404Page`,
  `tls_cert_file`, `tls_key_file` — probe case C3 showed all of them landing on the parent field
  before the fix. Measured before/after (probe C2): `[web_server.tls] user = "nested-user"` +
  `password = "nested-secret"` loaded `web_server.user == "nested-user"` and
  `web_server.password == "nested-secret"` in both loader modes before, and the defaults after, with
  strict now naming `unknown field "web_server.tls.password"` / `...user` (before: silent in both
  modes when there was no parent value). Go refuses both keys outright — probed on the v0.71.0 `frps`:
  rc 1, stdout `json: unknown field "password"`. Pinned by
  `nested_web_server_tls_credentials_do_not_become_the_parent_fields` and
  `unknown_nested_web_server_tls_key_names_the_true_nested_path` (`frp-core/src/config/tests.rs`); the
  meta-guard `strict_array_element_keys_match_struct_fields` now compares
  `WEB_SERVER_TLS_KNOWN_KEYS` against `WebServerTlsConfig`. The old
  `unknown_nested_web_server_tls_key_still_names_a_parent_level_path` (which pinned the fabricated
  `web_server.bogus_key`) is replaced by the true-path test.
- [x] **The `web_server.tls.enable` warning never reaches a `-c` user: the `-c` path loads the
  config before logging exists.** `normalize_web_server_section` warns
  (`frp-core/src/config/normalize.rs`) because `enable` is inert, but the warning is emitted from
  inside the loader, and on the `-c` path the loader runs **before** `init_logging`
  (`frps/src/main.rs:263` vs `:290`; `frpc/src/main.rs:561` vs `:583`, both carrying a comment
  saying the ordering is deliberate Go parity). Measured on the v0.71.0 debug binaries with a config
  whose `[web_server.tls]` sets `enable = true` (probe `/tmp/wstls-warn-probe/`, output
  `/tmp/wstls-warn-probe/*.out`): `frps -c` → **0** occurrences of the message (also with
  `RUST_LOG=debug`), `frpc -c` → **0**, `frps --config-dir=<dir>` → **1** (that path calls
  `init_logging` first, `frps/src/main.rs:180`). So the honest scope, now written into
  `docs/config.md`, `CHANGELOG.md` and the test target's doc, is "warned when the sink is installed
  before the load (`--config-dir`)"; on the common path `enable = true` with no cert/key pair still
  serves the dashboard as plaintext HTTP **in silence**, which is the outcome the warning exists to
  prevent. **Done-when:** the warning survives the `-c` path — R1's sketch: add a presence flag to
  `ConfigPresence` (already returned by `load_config_from_file` and already used for
  `server_heartbeat_timeout_set`) and warn from `frps`/`frpc` **after** `init_logging` — with a test
  that fails without the flag on the `-c` path (a spawn test per binary, asserting the message on
  the captured output). Not done in the prose-only fix round: it is a behaviour change to two
  binaries, and `docs/config.md`/`CHANGELOG.md` now state the limitation instead of overstating the
  diagnostic.
  Done: `ConfigPresence` gained `web_server_tls_enable_set`, read from the **pre-normalization** value
  (the nested `tls` table's mapped keys — `enable` included — are removed before serde, so the flag
  could not be recovered afterwards) and
  surfaced by `load_server_config_uncompleted_with_presence` /
  `load_client_config_with_presence`. The loader no longer emits the record at all — one owner — and
  each binary warns once from `ConfigPresence::warn_inert_web_server_tls_enable` **after** its own
  `init_logging`, at each of its load sites (`frps` `-c` and `--config-dir`; `frpc` `-c`,
  `--config-dir` and `verify`, which had a sink before the load and keeps its record). Re-measured
  with the v0.71.0 debug binaries, stdout and stderr captured separately, occurrence counts (probe
  `/tmp/enable-warn-probe/run-probe.sh`, stream dirs `/tmp/enable-warn-probe/out/{before,after}/`):
  before `frps -c` 0 / `frpc -c` 0 / `frps --config-dir` 1 / `frpc --config-dir` 1; after **1** for
  all four, every one on **stdout** with 0 on stderr, and 0 for a config without the key. The
  `-c` load-before-`init_logging` ordering is untouched (Go parity; the fix moves the emission, not
  the load). The `frps/src/main.rs:`/`frpc/src/main.rs:` line numbers quoted in this item's opening
  paragraph are the frame the defect was measured in (base `fb8d6ac`); this change moved those lines,
  so current carriers cite the file and the symbol instead of a number. The record is
  presence-driven, not pair-driven, so `enable = false` beside a valid pair — where TLS stays on
  against the written value — is not silenced; the message text was made true in
  the no-pair case it exists for (`… ; without that pair the dashboard serves plaintext HTTP`). Tests:
  `frps/tests/warn_delivery.rs` and `frpc/tests/warn_delivery.rs` (real binary, real config, separate
  streams, per-case free port, bounded and reaped children; each falsified with
  `FRPS_BIN`/`FRPC_BIN` pointing at the pre-change binary — the `-c` test fails, `--config-dir` passes
  — and with the flag mutated to `false`, where all positive shapes fail), plus
  `frp-core/tests/web_server_tls_enable_warning.rs` for the flag, the message and the loader's
  silence. A new CI step runs the `frps` spawn target with a count guard and a second one guards
  `frpc`'s; the client's **reload** is pinned in-process by
  `frp-client/tests/reload_warning_delivery.rs`. Docs updated: `docs/config.md`, `CHANGELOG.md`, the
  test targets and `normalize_web_server_section`'s doc.
  **Second round — both reviewers returned `MERGE after these fixes`, each finding an invisible path
  the first round created (the same defect class this item closes).** (1) The flag detector read the raw
  value *before* `normalize_*_config` flattens `[common]` onto the top level, so
  `[common.web_server.tls] enable` reached the removal site but never set the flag: measured on the
  first-round binaries `frps --config-dir` **0** (base 1), `frpc --config-dir` **0** (base 1), and the
  same for `[common.webServer.tls]`, the inline `common = { … }` form and the shape in an `includes`
  file; the detector now checks the four places the table can come from, in the normalizers'
  `or_insert` order (top-level `web_server` → `common.web_server` → `webServer` → `common.webServer`),
  and stops at the first **present** key so it mirrors what the flatten keeps. (2) The now-silent
  wrappers are also called by the **reloads** (`frp-server/src/service.rs`, `frp-client/src/service.rs`),
  which run long after `init_logging` and so used to get the record — and the reload summary cannot
  report it (`enable` has no field), so the record was the only signal: measured `frps -c` reload
  window +1 on the base binary, **0** on the first-round binaries; both reload sites now emit it,
  pinned by `frps/tests/warn_delivery.rs` with a real `kill -USR1` and by
  `frp-client/tests/reload_warning_delivery.rs` in-process. The `docs/config.md`/`CHANGELOG.md` wording
  was re-derived to name the sites, the `[common]` spellings and the three shapes that deliberately get
  nothing (`frps verify`, `.ini`, the mixed `[web_server]` + `[webServer.tls]` pair). Falsified in both
  directions: against the pre-change binaries (plain `-c` fails) and against the first-round binaries
  (the `[common]` and reload tests fail) — `/tmp/enable-warn-probe/out2-falsify-*.txt`. Remaining scope
  reduction, filed below.
- [x] **The `frpc` admin API's config GET no longer sees the `[web_server.tls] enable` diagnostic.**
  `frp-client/src/admin.rs`'s `config_from_file` (the admin **GET** path: `/api/proxy/{name}/config`,
  `/api/visitor/{name}/config`, on **every request**) loads the file through
  `load_client_config` — the *file* API, not `load_*_config_from_str` — which is now silent, so the
  record it used to get from the loader is gone. That is the **only** silent admin load site: the
  admin **PUT** (`handle_put_config`) still delivers, because although its validate-before-write uses
  the silent `load_client_config_from_str`, the handler then calls `reload_and_wait`, and the
  write→reload path emits once per request. Measured end to end with an `admin`-feature `frpc` and a
  real `frps`, three requests each (`/tmp/enable-warn-probe/run-admin-probe.sh`, output
  `/tmp/enable-warn-probe/out3/admin-probe.txt`): startup 1 record; after 3 GETs **+0**; after 3 PUTs
  **+3** (one per request, via the reload). At the loader API the string loader was already measured
  1 → 0 (`frp-core/tests/web_server_tls_enable_warning.rs::the_string_loader_stays_silent`).
  (Corrected during #402's review: this list originally also named `/api/config`. That route does not
  reach `config_from_file` — `config_from_file` has exactly two callers, `frp-client/src/admin.rs:598`
  and `:618` → `handle_get_proxy_config`/`handle_get_visitor_config` — and `/api/config` is routed to
  `handle_get_config` (`admin.rs:894`), which reads the raw file and parses it itself. Measured against
  the **base** binary: 3 × `GET /api/config` added **+0** records while 3 × `GET /api/proxy/main/config`
  added **+3**, so that route was already silent and is not a regression of the `enable` change.)
  **Done-when:** either `config_from_file` emits the record itself (switch to
  `load_client_config_with_presence` and call
  `ConfigPresence::warn_inert_web_server_tls_enable`) — with a recorded decision on whether a
  **per-request GET** should warn once per poll or only on a state change — or the GET's silence is
  stated where a user of the admin API would look for it; the test target's "what it does not cover"
  and this item move together either way.

  Done: the first branch — `config_from_file` (`frp-client/src/admin.rs`) now loads through
  `load_client_config_with_presence` and calls
  `ConfigPresence::warn_inert_web_server_tls_enable` itself, **once per state change rather than once
  per request**. The decision is recorded on the function and on
  `AdminState::web_server_tls_enable_seen`: both routes are polled, so a per-request record would be a
  log flood carrying no new information, while the fact is a property of the file. The cell holds
  `0 = no baseline`, `1 = written`, `2 = absent`; `spawn_admin_server` **seeds it from the file** at
  startup (so a file that already wrote the key produces no second record on the first GET, and a
  hand-edit made **after the admin server has started** is still reported — an edit between the
  startup load and the spawn is baselined, since the seed reads the file at spawn), the record fires
  when the answer becomes "written", and `handle_put_config` resets the cell to `0` after a successful
  reload so a following GET cannot repeat the reload's record. Measured in-process by
  `admin_config_get_warns_once_per_state_change` (`frp-client/src/admin.rs`); the test asserts
  **cumulative record totals**, so they are quoted here in the test's own execution order — seed
  `ABSENT` with no key, one GET -> **0**; hand-add the key, one GET -> **1** (the window the seed
  exists to cover); seed `WRITTEN` with the key, three GETs -> **1** (the startup record is not
  repeated; no per-poll flood); rewrite without the key -> **1**; rewrite with it -> **2**; three more
  GETs -> **2**; cell reset (the PUT path) + GET -> **2**; rewrite without the key and back with it ->
  **3**. The pre-fix measurement the item filed (3 GETs -> **+0** records, 3 PUTs -> +3) stands as the
  "before". The seed **wiring** (not just the seed function) is pinned against the real binary by
  `frpc/tests/admin_config_get_warning.rs`, whose `hand_edit_after_startup_is_reported` is red when
  `spawn_admin_server` reverts to `AtomicU8::new(0)` and whose `seed_reads_the_file_non_strictly` is
  red when the seed's `strict = false` is flipped. The test target's "what
  it does not cover" (`frp-core/tests/web_server_tls_enable_warning.rs`), the
  `warn_inert_web_server_tls_enable` doc (`frp-core/src/config/loader.rs`), the emission comment in
  `normalize_web_server_section` (`frp-core/src/config/normalize.rs`) and the `docs/config.md` site
  list moved with it — `frps verify` is now the only site that gets no record.
- [x] **A parent-level `certFile` alias beside the parent-level canonical `tls_cert_file` is a
  `duplicate field` error — with no nested key involved at all.** serde binds `web_server.certFile`
  as an `alias` of `web_server.tls_cert_file`, so a file that writes both (in any spelling mix that
  puts two of those names at the parent level) fails to deserialize in **both** loader modes with
  ``config validation error: duplicate field `tls_cert_file` ``. Measured on all three trees
  (`5717fa2`, `ccff127`, the fix-round head — probe `/tmp/wstls-f1/`, cases `t17`/`t18`), so it is
  **pre-existing and not fixed by the nested-section mapping**: that fix removes the parent-level
  alias only when a nested value supplies the field. `t16` (`certFile` + `cert_file`, no canonical)
  is *not* this defect — `cert_file` is not a field, so it is correctly reported as
  `unknown field "web_server.cert_file"` in strict mode and dropped non-strict. Note the one
  message change the mapping does cause for `t18`-style files (alias + canonical + a nested table
  with some other key): base strict reported `unknown field "web_server.key_file"` first, the fixed
  tree reports the duplicate, because the nested spelling is now mapped instead of being unknown —
  both refuse, the wording differs. **Done-when:** the duplicate is either closed (drop the
  parent-level alias whenever the canonical is present, not only when a nested value is) or the
  error names the two parent-level keys, pinned by a test in both modes.

  Done: closed, by canonicalizing the whole four-spelling group in
  `normalize_web_server_section` (`frp-core/src/config/normalize.rs`) — whichever spellings are
  present, only the parent canonical `flat_key` survives, so serde can never see two names for one
  field. This covers the nested-supplied cases and the collision a naive per-key section merge (item
  A) would otherwise introduce (`[webServer] certFile` beside `[web_server] tls_cert_file`). Measured
  before/after (probe cases E1/E2, and `frps verify -c` on the real debug binary): before, rc 1 with
  `config validation error: duplicate field tls_cert_file` in **both** loader modes; after, the
  canonical value loads in both modes (`tls_cert() == "/canon/cert.pem"`). The pair's winner is the
  canonical (the struct's own field name); an empty canonical falls through to the alias, consistent
  with item F. Pinned by `parent_alias_beside_parent_canonical_loads_in_both_modes`
  (`frp-core/src/config/tests.rs`).
- [x] **A nested empty value clears the flat value: `[web_server.tls] cert_file = ""` beside
  `[web_server] certFile = "/p.pem"` loads with `tls_cert() == ""`.** The hoist's `insert` treats an
  explicitly empty nested string as "the nested value wins" — consistent with the documented
  precedence, but surprising for a field whose emptiness means *disabled*: a cert written for the
  flat/alias spelling is silently dropped and the dashboard serves plaintext. Measured (probe
  `/tmp/wstls-f1/`, cases `t19`/`t20`): base kept the flat value in both cases; `ccff127` and the
  fix-round head load with `tls_cert() == ""` (`t20` — parent canonical + empty nested — already
  behaved that way on `ccff127`). **Done-when:** the intended semantics are stated for the empty
  string (nested wins, or an empty nested value is "unset" and falls through to the flat key) and
  pinned by a test in both modes, with the one-clause note in `docs/config.md` either kept or
  replaced by the implemented rule.

  Done: decided that an explicitly **empty** nested value is *unset* — it falls through to the
  flat or alias spelling rather than clearing it — with the resolution order nested snake -> nested
  camel -> parent canonical -> parent alias, first **non-empty** spelling winning
  (`normalize_web_server_section` + `is_empty_string`, `frp-core/src/config/normalize.rs`). Rationale:
  emptiness is how these fields say *disabled*, so "empty wins" silently drops a configured
  certificate and leaves the dashboard serving plaintext HTTP — a fail-open outcome for a
  security-relevant field. Measured before/after (probe cases F1/F2):
  `[web_server.tls] cert_file = ""` beside `[web_server] certFile = "/p.pem"` (and beside
  `tls_cert_file = "/p.pem"`) loaded `tls_cert() == ""` in both loader modes before and `"/p.pem"`
  after. The same rule one level down: an empty nested `cert_file` beside a set nested `certFile` now
  yields the camelCase value (before: `""`, probe F4). Pinned by
  `empty_nested_value_is_unset_in_both_modes` (`frp-core/src/config/tests.rs`) and stated in the
  `tls_cert_file` / `tls_key_file` rows of `docs/config.md` in place of the removed "clears the flat
  value" clause.
  **Ledger after this batch: 24 open / 104 closed** (29 open / 98 closed before it and 23 / 104 when this
  note was first written — the `type`-less `.ini` item below was filed by the review afterwards), measured with
  `grep -cE '^- \[ \]' TODO.md` / `grep -cE '^- \[x\]' TODO.md`).

- [x] **A legacy `.ini` proxy section that omits `type` is dropped; Go v0.71.0 registers it as a `tcp`
  proxy.** Filed by the `fix/webserver-tls-cluster` review round while pinning the `.ini` dotted-header
  expansion — not caused by it (base `d958711` behaves the same), and not specific to the dotted
  spelling: a plain legacy name (`[myproxy]`) is dropped identically. **Go's legacy `.ini` dialect
  treats every non-`[common]` section as a proxy** (`pkg/config/legacy/client.go`), while frp-rs's
  `collect_legacy_ini_proxy_sections` (`frp-core/src/config/normalize.rs`) collects a section only when
  its table carries a `type` key. Measured with the real binaries (probe `/tmp/wsprobe3/run2.sh`;
  `--strict-config=false` and `--strict-config` both spelled out, because the flag defaults to **true**):
  `[auth.foo]` and `[myproxy]`, each with `local_port` / `remote_port` and no `type` —
  `frpc verify --strict-config=false` rc 0 with `Proxies: 0` (a **silent** drop) and
  `--strict-config` rc 1 `unknown field "auth.foo"` / `"myproxy"`; a real frp-rs `frps`+`frpc` run
  registers **0** proxies. Go v0.71.0: `frpc verify` rc 0 under both flag spellings for both shapes, and
  a real Go `frps`+`frpc` run logs `proxy added: [auth.foo]` /
  `[auth.foo] start proxy success` (likewise `[myproxy]`), with the server reporting
  `new proxy [myproxy] type [tcp] success` — i.e. **Go defaults the missing type to `tcp`**.
  **Done-when:** either accept a typeless legacy proxy section the way Go does (with the same `tcp`
  default, pinned in both loader modes) or state the `type` requirement in `docs/config.md` with a test
  pinning the current message and the `Proxies: 0` drop — a silent drop is not an option either way.

  Done: fixed in #418 (`9747f131`, with the regression guard `a757afc6`). Go's legacy
  `.ini` dialect treats every non-`[common]` section as a proxy and defaults a missing
  `type` to `tcp` (`pkg/config/legacy/client.go`); frp-rs collected a section only when it
  carried `type`. The file dialect is now threaded into the normalizers
  (`normalize_(client|server)_config(&mut toml::Value, ConfigFormat)`, fed by the
  `detect_format(path)` the loader already computed) and
  `collect_legacy_ini_proxy_sections(table, is_ini)` collects a typeless section in the INI
  dialect and fills `type = "tcp"` **before** the strict check and `normalize_proxies` see
  it. The rule is `.ini`-only: an unknown top-level table in TOML/JSON/YAML still reaches
  the strict check, as Go's v1 decoder does. Two boundaries: a `role = "visitor"` section
  is **not** defaulted (Go refuses a typeless visitor in both modes, `failed to parse
  visitor v, err: type shouldn't be empty`, so defaulting it would invent a divergence),
  and `ini_section_path` keeps a dotted header verbatim — which makes it a legacy proxy —
  exactly when its section carries `local_port` or `remote_port`, since a `.ini` proxy
  always has one and no v1 nested sub-table does. Measured with the real binaries on
  `[myproxy]`, `[auth.foo]` and `[my.proxy]` (each `[common]` plus
  `local_port`/`remote_port`): before, `--strict-config=false` rc 0 `Proxies: 0` (silent
  drop) and strict rc 1 `unknown field "myproxy"`; after, both modes rc 0 `Proxies: 1`,
  and a real frps+frpc run logs `Registering proxy 'myproxy' type=tcp remote_port=18081`
  where Go logs `new proxy [myproxy] type [tcp] success`. Tests:
  `typeless_ini_proxy_section_defaults_to_tcp_in_both_modes`
  (`frp-core/src/config/tests.rs`: `[myproxy]`/`[auth.foo]`/`[store.frontend]`/`[my.proxy]`
  in both modes, the `role = "visitor"` exclusion, and a portless `[webServer.tls]` still
  nesting) and `typeless_legacy_ini_proxy_verifies_in_both_modes`
  (`frpc/tests/cli_exit_codes.rs`, exact stdout `Proxies: 2`); no existing assertion was
  weakened, changed or moved. `ci.yml`'s guarded `FRPC_TINY_CLI_TESTS` 13 → 17 (two more
  pins arrived with the follow-up below). `a757afc6` then closed the phantom-proxy
  regression (`[webServer] port = 7500` collected as a proxy named `webServer`, the admin
  block silently lost, `Proxies: 1`) by listing the camelCase spellings beside their
  snake_case roots — but that in turn swallowed a **typed** camelCase root
  (`[webServer] type = "tcp"` plus ports), which base had registered. `e1fcd9e3` settles
  it: `KNOWN_SECTIONS` is snake_case-only again, and the typeless branch is narrowed to a
  section that names `local_port` or `remote_port` — the key set `format.rs`'s nest gate
  already used — so the phantom stays closed (`[webServer] port = 7500` → `Proxies: 0`;
  `[webServer] zzz_unknown_key = 1` → base's strict rc 1) while typed camelCase roots
  register exactly as at base971 (`Proxies: 1`, and `[webServer] type = "bogus"` is still
  `proxy 'webServer': invalid proxy_type 'bogus'`) and a port-carrying `type`-less section
  under any root is collected as the `tcp` proxy this item asked for. Residuals filed
  below: `type = ""`, the typeless visitor's own
  verdicts, and a dotted v1-root header without a port key.
- [x] **Three pin-precision nits in `frpc/tests/admin_config_get_warning.rs`, filed by #408's final review
  round.** All three are non-blocking, and all three were found after the fifth round had already returned
  MERGE: the batch merged on two MERGE verdicts and these are recorded rather than re-reviewed.
  (a) **A wrong mechanism claim in the new row's comment** (R2, R5-1). The
  `seed_resolves_spellings_only_the_loader_does` comment attributes the row's discrimination to "the per-key
  section merge". That path never consults it: `load_config_from_file` computes
  `ConfigPresence::web_server_tls_enable_set_in(&value)` from the raw, includes-resolved value **before**
  `normalize` (where `merge_section_into` lives), and the detector finds the `[common.webServer.tls]` shape
  through its own fallback. Proof: a mutant that drops `merge_section_into`'s `Occupied` arm leaves the target
  **4/4 green** while `both_web_server_sections_merge_per_key_in_both_modes` FAILS. The row does correctly pin
  "the seed goes through the loader" — the merge is pinned by its own frp-core test. The same loose wording
  sits in the frp-core detector test's "different keys to the flatten and merge afterwards" comment.
  (b) **An unreached assertion described as reached** (R2, R5-2). The target's "what it does not cover" says
  the two `NO_BASELINE` cases "are red" under the failure-mode mutant (`.unwrap_or(WS_TLS_ENABLE_NO_BASELINE)`
  → `ABSENT`). Measured: the target stays **4/4 green** and the in-process test reds at
  `frp-client/src/admin.rs:2044:9` (`left: 2 right: 0`) — the **`None`** assertion; the missing-path assertion
  at `:2047-2052` is never reached because the test panics first. Both assertions encode `NO_BASELINE`, so the
  substance (caught in-process, not by the target) is right.
  (c) **The row does not pin that the seed honours its argument** (R1). A seed that ignores `config_path` and
  reads `./frpc.toml` passes all four rows, because the harness always writes `frpc.toml` into the child's cwd;
  the in-process test does red it (`left: 0, right: 1`). A fixture with a non-default filename closes it.
  **Done-when:** (a) and (b) state what the row and the failure mode actually pin, and (c) is closed by a
  non-default-filename fixture in the target — or the row's "what it does not cover" says plainly that the
  argument is pinned in-process only.

  Done: fixed in #417 (`e95ce68c`). (a) The comments now attribute the row's discrimination
  to the pre-`normalize` read (`frp-core/src/config/normalize.rs:621`) plus the detector's
  `[common]` fallback (`frp-core/src/config/loader.rs:427-429`), not to the per-key section merge;
  measured: emptying `merge_section_into`'s `Occupied` arm (`frp-core/src/config/normalize.rs:554-558`)
  leaves `frpc/tests/admin_config_get_warning.rs` 4/4 green while
  `both_web_server_sections_merge_per_key_in_both_modes` reds at
  `frp-core/src/config/tests.rs:6241` (`A1: nested wins`). (b) The "what it does not cover"
  paragraph now states the measured reachability: the target stays 4/4 green under
  `.unwrap_or(WS_TLS_ENABLE_NO_BASELINE)` → `ABSENT`, and the in-process test reds on the **`None`**
  assertion at `frp-client/src/admin.rs:2044:9` (`left: 2 right: 0`), never reaching the
  missing-path assertion at `:2048-2053`. (c) The new fixture launches the child with
  `-c admin-node.toml` while a key-less `frpc.toml` sits in its cwd: 1 startup record, still 1 after
  three GETs, and a seed that ignores `config_path` and reads `./frpc.toml` reds at
  `frpc/tests/admin_config_get_warning.rs:264:9` (before: 4/4 green). The comment also records why a
  cwd holding *no* `frpc.toml` cannot catch that shape — a `NO_BASELINE` seed baselines silently
  (`previous != NO_BASELINE` gate at `frp-client/src/admin.rs:770`). The comment's own
  `loader.rs` citation was corrected in `3ade4968`.
- [x] **Three accuracy defects and two precision gaps in the `oidc_throttle_tests` mock note and pins
  (filed by #409's final round).** All five were marked **non-blocking** and "fileable as-is" by both
  reviewers after four rounds; PR #409 merged on two MERGE verdicts and these are recorded rather than fixed.
  (a) **A false count history.** The Done note says it "said 'ten' while the filter had 14 tests and
  'twelve' while it had 17". Measured: the `oidc` filter was **10** at `ac51f469`, **12** at `b6373f2c`
  (where "ten other" was still correct), **14** at `7f39d903` (where "ten" was stale and twelve was right)
  and **17** after the round-4 pins; `git show <sha>:TODO.md | grep -c 'ten other'` is 1 at `b6373f2c` and
  `7f39d903` and 0 at the merge, and "twelve" appears in **no** committed note. The correct sequence is
  ten@12 → fourteen@17.
  (b) **A false reason for not pinning the `remaining.is_zero()` mutant** — the note says it would need a
  read landing exactly on the expired budget and "a controlled clock, not a socket". Measured by R1: a
  temporary direct call `read_request_head(&mut s, Duration::ZERO)` returns `TimedOut(0ns)` on the shipped
  code, and with the guard deleted it returns `Io(InvalidInput "cannot set a 0 duration timeout")` — a
  **7-line pin** needing no clock control and no socket timing.
  (c) **A false comment** on `read_request_head_stops_at_the_terminator`: it says the mutant "would hand the
  routing step a different path". Routing is `split_whitespace().nth(1)`, which yields `/jwks` with or
  without the pipelined tail; the equality assertion is the entire catch.
  (d) **The deadline pin guards the constant, not the delegation.** Wiring `oidc_mock_server()` to
  `oidc_mock_server_with_timeout(Duration::from_secs(60))` while the 5 s constant stays put leaves all 17
  `oidc` tests green (R2's `M_delegation_60s`).
  (e) **The immediate-write elapsed is a distribution, not a constant.** R1's 10-run medians were 7.583 µs
  macOS / 5.917 µs Linux (min 2.083/4.958, max 11.333/8.125); R2's 20-trial probes ranged 2–5 µs macOS and
  6–1576 µs Linux; the author's 192.08 µs and R1's 1.635 ms both sit inside the spread. Quote a range or
  attribute the figure, and keep `n=16` / `path` as the durable fact.
  **Done-when:** (a)–(c) say what is actually true; (b) either adds the 7-line `Duration::ZERO` pin or drops
  the claim; (d) names the delegation bypass or pins it; (e) quotes a range or attributes the number.

  Done: fixed in #417 (`77c987da`); (a) corrected where it was written. (b) The new pin
  `read_request_head_reports_a_zero_budget_as_a_named_timeout` calls
  `read_request_head(&mut s, Duration::ZERO)` directly: deleting the guard at
  `frp-server/src/control/login.rs:2301-2303` gives 17 passed / 1 failed with
  `got Io(Error { kind: InvalidInput, message: "cannot set a 0 duration timeout" })` (17/17 green
  before the pin). (c) The terminator pin's comment now says the equality assertion is the whole
  catch — `split_whitespace().nth(1)` yields `/jwks` with or without the pipelined tail. (d) The
  delegation `oidc_mock_server()` → `oidc_mock_server_with_timeout(MOCK_REQUEST_HEAD_TIMEOUT)` is
  documented as unguarded, with why the pin is not taken (seven bindings in
  `frp-server/src/control/login.rs` call it — five through the default constructor, two through the
  `_with_timeout` form — so the
  constructor would have to carry its timeout back out, or the test would wait out the shipped 5 s);
  measured: wiring it to 60 s leaves 18 passed. (e) The constant's doc names the shape (`n=16`,
  `path="/.well-known"`) and quotes an attributed spread (10-run medians 7.583 µs macOS / 5.917 µs
  Linux, 20-trial spread 2–1576 µs, one-offs 192.08 µs and 1.635 ms) instead of one figure. (a) The
  count history is corrected: the sequence is ten@12 → fourteen@17.
- [x] **Three residuals from #410's round-2 reviews: the warning-message pin is a substring list, and
  the feature split's reachable build shapes.** All three were marked **non-blocking** by both
  reviewers, none makes an emitted sentence false in any build a lane or a release produces, and
  PR #410 merged on two MERGE verdicts — so they are recorded rather than fixed.
  (a) **The pin cannot detect a clause being added or dropped.** `frp-core/tests/server_tls_enable_warning.rs`
  asserts a substring allow/deny list per variant. R1's mutant **G1** (`41010b14…`) appends an
  unmeasured clause to the `tls` variant and stays **8/8 green**; R2's **M3** deletes the new
  `" or unreadable"` clause and also stays **8/8 green**, while that clause is measured true
  (`open cert file: No such file or directory (os error 2)`, rc 1 on a real `frps`). The `tls`
  variant's text can therefore drift in either direction unnoticed. The same class as round-1 F4,
  which the round-2 commit closed for the *detector* (`:622:9` is now load-bearing) but not for the
  message.
  **Done-when:** either the assertions pin each variant string end-to-end (or the clause list is
  derived from the constants, so a new clause cannot slip in), or the test's "what it does not cover"
  says plainly that clause-level drift is not caught.
  (b) **The variant is keyed on frp-core's `tls`, not on the binary's acceptor gate.** The
  `#[cfg(feature = "tls")]` split in `frp-core/src/config/loader.rs` is necessary but not sufficient
  for an `frps` binary to build an acceptor: in the hand-rolled per-package mix
  `cargo build -p frps -p frpc --no-default-features --features "frps/micro,frpc/tls"` (measured
  normal-graph rustls = 11) frp-core's `tls` is on while frp-server's is off, so `frps-micro` would
  print the "refused at startup / auto-generates" text with no acceptor — exactly the round-1 F1
  defect. Measured: **no** lane produces that shape (`release.yml:100/102/108/110/159/162/210/213`
  are workspace-root `cargo build … --no-default-features --features tiny|micro`; `ci.yml:921`/`:925`
  the matching `cargo check --workspace … tiny|micro`), and frp-core cannot observe frp-server's
  features, so the constants' own doc comment correctly keys on frp-core's feature.
  **Done-when:** either the variant is gated on a cfg frp-core can actually see (or its text is
  written to hold under either), or a note beside the constants names the mixed-feature build as a
  known, unshipped shape.
  (c) **The two variants are covered by two different CI lanes, not by one test.** The `#[cfg]` split
  means the default run asserts nothing about the no-TLS text and the `--no-default-features` run
  nothing about the `tls` text; both are exercised across `ci.yml:192` (default) and `:224`
  (`--no-default-features --all-targets`), and both variants red under mutation (M1/M4 at `:622:9`;
  M2 at `:261:9` / R1's narrower mutant at `:275:13`). No change requested by either reviewer;
  recorded so the coverage is not mistaken for single-lane coverage.
  **Done-when:** the note says which lane covers which variant — or the assertion is split across two
  feature-gated targets so that each variant is named in the CI guard list.

  **Not filed (deliberately):** R1's N1 — doc comments cite author-local `/tmp/tls-warn-probe/*.sh`
  paths. Recording probe provenance that way is already this repository's style
  (`frp-client/src/service.rs:1436` cites `/tmp/frp-source/client/service.go`,
  `frp-core/src/config/normalize.rs:524` cites `/tmp/ws-probe-before.txt`,
  `frp-client/tests/reload_warning_delivery.rs:11` cites `/tmp/enable-warn-probe/http_smoke.sh`), and
  both reviewers reproduced the measurements independently, so no action is needed.

  Done: fixed in #417 (`fec27dd1`). (a) Both variants are now pinned with an exact `assert_eq!`
  on the whole sentence, so a clause added or dropped reds: dropping `" or unreadable"` reds at
  `frp-core/tests/server_tls_enable_warning.rs:273:5` (7 passed / 1 failed) and appending
  `", or an unmeasured claim"` reds the same way, where the substring allow/deny lists stayed 8/8
  green under both; shipped: 8 passed in the default lane and 8 passed under
  `--no-default-features`. (b) A note beside the constants names the hand-rolled mixed-feature shape
  `-p frps -p frpc --no-default-features --features "frps/micro,frpc/tls"` as a known, unshipped one
  (the note carries the measured `cargo check` and `cargo tree … -i
  frp-core` / `-i frp-server`: frp-core's `tls` on via frp-client, frp-server resolving to only
  `frps feature "micro"`; the acceptor gate is `frp-server/src/service.rs:603`, its no-acceptor
  branch `:635`); no lane in `.github/workflows/` produces it. (c) "What it does not cover" now
  names which lane covers
  which variant — `.github/workflows/ci.yml:191-194` (default) for the `tls` text and `:195-226`
  (run at `:226`, `--no-default-features --all-targets`) for the no-TLS text. The citations the new
  note introduced were corrected in `3ade4968`.
- [x] **A doc comment in `frp-core/src/transport/mod.rs` cites the wrong line for `connect_ws_raw`.**
  `frp-core/src/transport/mod.rs:3281` says the helper is `#[cfg(feature = "websocket")]` and cites
  `transport/mod.rs:2187`, but the definition is `pub async fn connect_ws_raw<S>(` at `:2254`
  (stale at the base too: the same comment sits at `:3280` in `9fd76852`, where the definition is
  also `:2254`). One-line comment correction found by the #412 adversarial review; that PR was
  test-only, so it filed rather than fixed. **Done-when:** the citation names `:2254` (or drops the
  line number), with the definition re-located at the fix's head.

  Done: fixed in #415 (`66c72345`): the comment at `frp-core/src/transport/mod.rs:3281` now cites
  `:2254`, re-located at the fix's head — `pub async fn connect_ws_raw<S>(` at
  `frp-core/src/transport/mod.rs:2254` with its `#[cfg(feature = "websocket")]` at `:2253`. One
  comment line changed (1+/1−).
- [x] **A symlinked non-`.rs` file is still double-counted by two `repo-health.sh` walks.** The `.rs`
  walks dedupe on `os.path.realpath` (item above), but the `.github/workflows` yml scan
  (`scripts/repo-health.sh:1157`) and the `docs/archive` md/json walk (`:1358`) still enumerate a
  symlink as a second file. Measured 2026-09-29 on `fix/symlink-double-count`: an untracked
  `.github/workflows/zz_probe.yml` holding `- run: rustup default stable` plus
  `.github/workflows/zz_alias.yml -> zz_probe.yml` printed the same hit twice (`zz_alias.yml:4`,
  `zz_probe.yml:4`) and `FAIL 2 floating toolchain selection(s) under .github/workflows/` for one
  aliased file — the **gated** false-FAIL direction; a
  `docs/archive/zz_symlink.md -> plans/2026-06-26-management-api.md` moved
  `archive path refs: 20, resolvable via the docs/archive/ prefix: 19` to `21 / 20` at rc 0
  (info-only). **Done-when:** both walks key their files on realpath like the `.rs` walks, or each
  documents why a symlinked entry is a distinct path (as `docs/README.md` indexing legitimately
  does), with the measured before/after for each.

  Done: fixed in #415 (`83c9d537`): both walks key their files on `os.path.realpath`, like the `.rs`
  walks. Measured on the item's shapes: `.github/workflows/zz_alias.yml -> zz_probe.yml` holding
  `- run: rustup default stable` goes `FAIL 2 floating toolchain selection(s)…` -> `FAIL 1`;
  `docs/archive/zz_alias.md -> plans/2026-06-26-management-api.md` goes `archive path refs: 21,
  resolvable…: 20` -> the clean `20 / 19`. A **hard link** in either walk is still double-counted —
  filed as a new item below.
- [x] **Two symlink shapes still defeat the `repo-health.sh` realpath dedupe: cross-crate targets and
  hard links.** The `.rs` walks dedupe per scope on `os.path.realpath` (item above), which covers an
  alias whose target is a normal path in the same crate, but not these two.
  **(a) A target in another crate is counted in both crates**, because `seen` is per-walk and each
  crate's walk reads the aliased file as its own. Measured 2026-09-29 on `fix/symlink-double-count`:
  with `ln -s ../../frp-server/src/lib.rs frp-core/src/zz_xcrate.rs` (24-line target) present,
  `bash scripts/repo-health.sh` gives rc **0**, `frp-core` Code size **70 files / 76534 lines**
  against 69 / 76510 symlink-free, unsafe row **21/3/1/23** and test functions 2481 unchanged — the
  same 24 lines are counted in `frp-core` *and* in `frp-server`. The rc stays 0 because no gate
  compares a crate's file or line count to a curated figure.
  **(b) A hard link is not deduped**, because `realpath` cannot see hard links. Measured on the same
  tree: `ln frp-core/src/kcp/session.rs frp-core/src/zz_hard.rs` gives rc **1**, **70 files / 78342
  lines**, unsafe row **22/3/1/24**, test functions 2501, and `FAIL #33 CLAUDE.md:172 says 21, the
  tree measures 22 (unsafe-block count, Unsafe usage section)` — the hard link reproduces the
  original defect exactly. **Done-when:** either both shapes are deduplicated (e.g. `(st_dev, st_ino)`
  for hard links, and excluding a target outside the walk root from that crate's own scope), or the
  gate names each shape instead of silently disagreeing with a curated claim, with a measured
  before/after for both.

  Done: fixed in #415 (`587735eb`, hardened in `8efa9aa5`): all four `.rs` walks key on
  `(st_dev, st_ino)` and each crate's walk contains the file to its own root. Measured:
  `ln -s ../../frp-server/src/lib.rs frp-core/src/zz_xcrate.rs` moves `frp-core` `70 / 76534` ->
  `69 / 76510` with `frp-server` unchanged at `32 / 59146`; `ln frp-core/src/kcp/session.rs
  frp-core/src/zz_hard.rs` moves `70 / 78342`, unsafe `22/3/1/24`, `FAIL #33 CLAUDE.md:172 says 21,
  the tree measures 22`, rc **1** -> `69 / 76510`, `21/3/1/23`, rc 0. The same round closed a false
  green the first cut introduced: the containment `continue` ran before the readability check, so an
  unreadable in-crate alias was dropped silently (base rc 1 with `scan error: …` x5, first cut rc 0
  `RESULT: invariants hold`); the stat now runs first. Residual: a **cross-crate hard link** — a
  shape neither key reaches, because `seen` is per scope and the twin sits inside its own crate's
  root — is still counted in both crates; filed as a new item below.

- [x] **A cross-crate *hard link* is still counted in both crates by `repo-health.sh`.** The
  `(st_dev, st_ino)` key added in #415 lives in each walk's own `seen` set, and the containment
  rule excludes a *symlink* whose realpath leaves the crate — but a hard link has no realpath in
  common with its twin and its own directory entry is inside its own crate's root. Measured
  2026-09-30 at `8efa9aa5`: with `ln frp-core/src/kcp/session.rs frp-server/src/zz_hardlink.rs` in
  place, `frp-core` stays `69 files / 76510 lines` while `frp-server` moves `32 / 59146` ->
  `33 / 60978` and its unsafe row `0/0/0/1` -> `1/0/0/2`, at rc 0 (no gate compares a crate against
  a curated figure, so this is a silent count divergence, not a red). **Done-when:** the inode set
  is shared across the four walks while preserving the per-scope row semantics `within` protects (or
  the shape is otherwise counted once, or named), with the measured before/after.
  Done: fixed in #416 (`1f6aedcc`). The four `.rs` walks now share their inode sets across
  the crate loop instead of carrying one `seen` per walk, so a hard link whose twin sits inside its
  own crate's root is counted once. The sets stay split per measurement **scope** (`seen_src` for
  `<crate>/src`, `seen_wide` for the crate directory) so a file legitimately counted in both scopes
  is not treated as a duplicate. Measured 2026-09-30 at `902ba6f4`:
  `ln frp-core/src/kcp/session.rs frp-server/src/zz_hardlink.rs` moves `frp-server` from `33 files /
  60978 lines` + unsafe `1/0/0/2` to `32 / 59146` + `0/0/0/1` at rc 0 (`frp-core` stays
  `69/76510`); a three-way link (`session.rs` aliased into frp-server *and* frp-client) also
  collapses to one count, and a repeat run is byte-identical. The clean-tree gate output is
  byte-identical to the base. **Trade-off (recorded, not fixed):** the first crate in `CRATES`
  order claims the inode, so in the reverse direction
  `ln frp-server/src/lib.rs frp-core/src/zz_hl_rev.rs` gives frp-core `70/76534` and frp-server
  `31/59122` — counted once, but attributed to the earlier crate; the `rs_texts` docstring states
  this convention and `docs/developing.md` records it.
- [x] **A *hard link* inside `.github/workflows/` or `docs/archive/` still double-counts.** #415
  gave those two walks a `realpath` key, which sees a symlink but not a hard link. Measured
  2026-09-30 at `8efa9aa5`: an untracked `.github/workflows/zz_probe.yml` holding
  `- run: rustup default stable` plus
  `ln .github/workflows/zz_probe.yml .github/workflows/zz_hard.yml` prints
  ``FAIL  2 floating toolchain selection(s) under .github/workflows/ (rustup default ...)`` and
  `RESULT: FAILURES above` at rc 1 for one aliased file (the gated false-FAIL direction); a
  `ln docs/archive/plans/2026-06-26-management-api.md docs/archive/zz_hard.md` moves the info row
  `archive path refs: 20, resolvable via the docs/archive/ prefix: 19` to `21 / 20` at rc 0.
  **Done-when:** both walks key on `(st_dev, st_ino)` like the `.rs` walks, with the measured
  before/after for each.
  Done: fixed in #416 (`258037f9`). Both walks now key on `(st_dev, st_ino)` via `os.stat`
  and fall back to `os.path.realpath` only when the stat raises `OSError`, so two names for one
  *missing* target still collapse to a single read error. Measured 2026-09-30 at `902ba6f4`:
  `.github/workflows/zz_probe.yml` holding `- run: rustup default stable` plus a hard-link twin
  prints `FAIL  1 floating toolchain selection(s)` (was 2) at rc 1; three hard links added to it
  (four counted names) print 1 (was 4); a hard-link + symlink pair prints 1 (was 2);
  `ln docs/archive/plans/2026-06-26-management-api.md docs/archive/zz_hard.md` gives
  `archive path refs: 20, resolvable via the docs/archive/ prefix: 19` (was `21 / 20`), and two
  hard links (was `22 / 21`) and a hard-link + symlink pair (was `21 / 20`) both give `20 / 19`.
  A directory symlink stays undescended on both versions.
- [x] **`scripts/tests/repo-health-fixtures.sh` fails when invoked through a symlink.** It resolves
  the script under test from an unresolved `BASH_SOURCE`, unlike `repo-health.sh` itself. Measured
  2026-09-30 at `8efa9aa5`: `ln -sf <tree>/scripts/tests/repo-health-fixtures.sh /tmp/rhfx.sh &&
  bash /tmp/rhfx.sh` prints `FAIL  cannot find the script under test: //scripts/repo-health.sh` and
  exits 1. CI invokes it by real path, so this is a developer-convenience hole, not a false green;
  closing it needs the same `readlink` resolution loop `repo-health.sh` carries. **Done-when:** the
  harness resolves its own path so a symlink invocation runs green, or its header states the
  limitation.
  Done: fixed in #416 (`6977481f`). The harness resolves its own path through a bounded
  `readlink` loop, the same shape `repo-health.sh` carries. Measured 2026-09-30 at `902ba6f4`:
  `ln -sf <tree>/scripts/tests/repo-health-fixtures.sh /tmp/rhfx.sh && bash /tmp/rhfx.sh` → rc 0,
  `RESULT: 19 fixture check(s) hold` (was `FAIL  cannot find the script under test:
  //scripts/repo-health.sh`, rc 1). Also green: a 3-hop relative chain, a 30-hop chain, a path
  containing a newline, and a bare-name `PATH` lookup. **Residual (filed):** the loop's `> 40` cycle
  bound never prints on macOS — the kernel refuses the chain long before 40 hops (`Too many levels
  of symbolic links`, rc 126: 30 links green and 31 refused in Reviewer 1's sweep, 26 refused in
  the coordinator's) — so it is a dead fail-closed backstop.
- [x] **Three coverage gaps in the new `repo-health.sh` fixture harness.** The round-2 reviews of
  #415 found all three; none is a gate false-green today (each needs a mutation that also disables
  the check itself, or touches a printed metric no figure depends on).
  **(a) The exit-code scenario has no negative control.** It asserts that the
  `  FAIL  archive path scan failed (exit 3)` row is present when the archive scan fails, but nothing
  asserts its **absence** on a clean scan, so a wrapper that hardcoded that row while the archive
  gate exited 0 stays green (mutation A4, measured by Reviewer 2; one assertion on a clean throwaway
  tree closes it). **(b) Scenario 4 pins only one of the four walk sites.** In a throwaway tree the
  three inline blocks die earlier on `ModuleNotFoundError: No module named 'rust_comments'`
  (`  FAIL  unsafe usage counts not evaluated (exit 1)`), so reverting sites 2–4 alone leaves the
  harness green; it is safe only because `fresh`'s `<crate>/src` walk is a coverage superset —
  measured: a crate-root `frp-core/zz_root_broken.rs` is reported by `fresh` alone (2 errors fixed /
  1 with `fresh` reverted, 1 under `all3`). **(c) The `integration test dirs` metric is untested**
  and the restored rule is a heuristic: a `tests/` directory with no `.rs` anywhere beneath it is
  dropped (measured: `zz-crate/tests/notes.txt` keeps 6, adding `x.rs` makes 7); no curated doc
  figure names it. **Done-when:** (a) a clean-tree negative control exists; (b) either the fixture
  supplies a `rust_comments.py` stub so all four sites are exercised, or the item records why the
  superset argument is sufficient; (c) the metric is asserted, or the heuristic is stated where the
  metric is read — each with the measured before/after.
  Done: fixed in #416 (`450fc72f`, `902ba6f4`). (a) Scenario 5 is the clean-tree negative
  control for the archive `(exit 3)` row: a wrapper that hardcodes
  `  FAIL  archive path scan failed (exit 3)` while the archive gate exits 0 reds it
  (`clean archive scan: the archive exit-3 row was printed anyway`), while scenario 1 stays green.
  (b) Scenario 4 builds a full fixture tree (stub preflight inputs, the real
  `scripts/rust_comments.py` copied in) and reverts each of the four walk sites; each site reds its
  own evidence — site 1 `4 → 2` scan-error lines, sites 2/3 `4 → 3`, site 4 the
  `partial tree: frp-core/src/zz_broken.rs is missing` row — reproduced independently by both
  reviewers **in the real script**, not only through `mut_rwalk`; a mutation whose anchor is
  missing now reds loudly
  (`unreadable src: site N mutation failed to apply`) instead of printing `ok` (`902ba6f4`).
  (c) Scenario 6 asserts `integration test dirs: 2`; a `-maxdepth 1` mutation reds it
  (`expected 2, got 1`). The harness is 19 checks / ~4.6 s, its own step in the `health` job
  (`timeout-minutes: 5`).

- [x] **Residual fixture-harness coverage nits from the `repo-health-residue` reviews.** Both
  reviewers confirmed the four items closed; these are the leftovers neither could pin.
  **(a)** Scenario 4's per-site revert checks accept any count different from the mutated baseline
  rather than the exact expected drop (site 1 → 2, sites 2/3 → 3), so a walk that drops *more* than
  its own evidence still reads `ok` (the positive control pins the baseline, so it is not a gate
  false-green). **(b)** No check pins site 4's `n_present` semantics — that the crate-root
  `has no .rs files` row is *suppressed* when the directory holds only cross-crate aliases (the
  increment runs before the dedupe `continue`, so the row does not appear); Reviewer 1 had to
  build a synthetic cross-crate-aliased tree to pin it (moving the increment after the `continue`
  is count-inert and only changes the row). **(c)** The harness's `readlink` cycle bound (`> 40`)
  is unreachable: the kernel refuses the chain long before 40 hops (`Too many levels of symbolic
  links`, rc 126 — 30 links green / 31 refused in Reviewer 1's sweep, 26 refused in the
  coordinator's), so the `FAIL  cannot resolve the harness path (symlink cycle?)` branch never
  prints. **(d)** `new_tree`/`new_full_tree`'s rc is unchecked, the same class as the `mut_rwalk`
  hole fixed above: with `chmod 000 scripts/repo-health.sh` (so the harness's copy of the script
  under test fails) three checks go vacuous-green — both `newline … no forged hit from the split
  path` checks and `clean archive scan: no archive exit-3 row` — while the run is rc 1 overall (so
  it is not a gate false-green). **Done-when:** each is either asserted (with the measured
  before/after) or its limitation is stated where the check lives.

  **Done (2026-10-01, at `0544b481` on `fix/test-precision-residue`, based on `origin/main` =
  `7c3d5707`).** The two `scripts/tests/repo-health-fixtures.sh` commits (`6b399b66`, `bdd56f2e`
  post-rebase) close all four. (a) Scenario 4's per-site revert checks now assert the **exact**
  remainder, not "anything but the baseline": `case "$site" in 1) want=2 ;; *) want=3` with the
  measured baseline of 4 (`scripts/tests/repo-health-fixtures.sh:457-463`), so a walk that drops
  more than its own evidence is a `bad`, not an `ok`. (b) Scenario 7 (`:507-539`) pins site 4's
  crate-root row with a hard link from one crate's `src` into another crate's tree — the alias
  resolves inside its own crate (containment passes) but its inode is already claimed — plus the
  count-inert mutation that re-raises the row (`mut_npresent`, `:182-198`, moving `n_present += 1`
  past the dedupe `continue`) as its tooth. (c) Scenario 8 (`:540-575`) pins what is actually
  assertable — the kernel refusing a 41-link chain — and the harness comment now records the
  measured bound (32-link chain green / 33 refused on this host, Darwin `MAXSYMLINKS` = 32; the
  earlier "31/32" came from probing under `/tmp`, itself a symlink; Linux allows 40, so 41 is
  refused on both) and states that the in-script `> 40` branch is therefore unreachable. (d)
  `new_tree`/`new_full_tree`'s rc is no longer discarded (`d=$(new_tree "$1") || return 1` at
  `:130`; `TREE=$(new_tree "$1") || setup_die "new_tree $1"` at `:269`), and scenario 9
  (`:576-629`) shows an unreadable script under test fails the run loudly: with `setup_die`'s
  `exit 1` reverted to `return 0` (`:288`) the outer harness goes rc 1, because the awk check at
  `scripts/tests/repo-health-fixtures.sh:608-616` (FAIL emitted at `:615`) refuses any non-blank row
  after the `fixture setup: ` FAIL; the `:603` grep only asserts that the failure names the setup
  step.
  Scenarios 10 and 11 cover the doc-figure walk's failure paths: an unreadable subdirectory must
  print `walk error: ` and must not accuse the crate of holding no `.rs` files (`mut_walkerr b` at
  `scripts/repo-health.sh:2308`, `mut_walkerr c` at `:2337`), and a sibling-directory symlink into
  `frp-core/src` must not be counted (`mut_prefix` at `:2322`). Harness checks 19 → 24 → **32**
  (counter at `:730`; `RESULT: 32 fixture check(s) hold`). No
  `CHANGELOG.md` entry: fixture-harness only, the #415/#416 precedent. Gates on the rebased branch:
  fmt/clippy clean, `bash scripts/repo-health.sh` → `RESULT: invariants hold`, fixture harness 32/32.

- [x] **Two precision residues from the `review-residue-precision` batch.** Both were found while
  closing the three items above; neither is a false green.
  **(a)** The exact `assert_eq!`s in `frp-core/tests/server_tls_enable_warning.rs` duplicate both
  variant strings, so a wording change must move the constant, the literal and the doc measurements
  together — a self-consistent but stale triple would still pass. **(b)** `oidc_mock_server()`'s
  delegation to `oidc_mock_server_with_timeout(MOCK_REQUEST_HEAD_TIMEOUT)` is documented, not
  pinned: wiring it to 60 s leaves 18 `oidc` tests green (`frp-server/src/control/login.rs`).
  Pinning it needs the constructor to return its timeout so a test can assert the value without
  waiting out the shipped 5 s. **Done-when:** (a) the literals are derived from the constants (or a
  drift test compares them); (b) the delegation is asserted cheaply, or the record says plainly that
  it is unpinned.

  **Done (2026-10-01, at `0544b481` on `fix/test-precision-residue`).** Commit `48f009c9`
  (rebased) closes both — (a) through goldens over the **rendered bytes** and (b) through an
  accessor that makes the delegation observable. (a) The duplicated variant literals are gone: the
  shipped message is defined once per variant in `frp-core/src/config/loader.rs` (`WEB_SERVER_TLS_ENABLE_INERT_WARNING`
  `:270`, its no-dashboard sibling `:285`, and `SERVER_TLS_ENABLE_INERT_TLS_CLAUSES` `:345`), and
  `frp-core/tests/server_tls_enable_warning.rs` now pins length + FNV-1a over the string the code
  produces (`TLS_RENDERED_LEN = 433` / `TLS_RENDERED_FNV1A = 0x0a17_2261_4d74_606e` at `:110-116`,
  with the comment at `:331-345`/`:390-403` saying the goldens are to be updated **deliberately**,
  never re-derived from the clause array). Teeth: swapping the two `SERVER_TLS_ENABLE_INERT_TLS_CLAUSES`
  elements panics at `:341`, and rewording `reads it.` → `reads it at all.` panics at `:334`
  (`left 440 / right 433`). Deviation from the obvious choice: dependency-free FNV-1a rather than
  sha256, because `sha2` is not a `frp-core` dependency and `DefaultHasher` is not stable across
  releases. (b) `oidc_mock_server_with_timeout` now stores its deadline and exposes
  `request_head_timeout()` (`frp-server/src/control/login.rs:2343-2349`), and
  `mock_default_ctor_delegates_the_pinned_deadline` (`:2758-2768`) asserts that the handle
  `oidc_mock_server()` returns reports `MOCK_REQUEST_HEAD_TIMEOUT` (`:2235`) — the exact wiring the
  reviewers' `M_delegation_60s` mutant changed while all 18 `oidc` tests stayed green; the literal
  itself is pinned by `mock_default_request_head_deadline_is_pinned` (`:2738-2746`). No
  `CHANGELOG.md` entry: no shipped byte or behaviour changed — the goldens exist precisely to hold
  the rendered bytes fixed — and the only non-test edit is hoisting the diagnostics into constants.

- [x] **The (c) admin-warning fixture cannot distinguish "reads `-c` only" from "reads the cwd first,
  then falls back to `-c`".** Filed by the `review-residue-precision` adversarial review. The fixture
  launches the child with `-c admin-node.toml` while a key-less `frpc.toml` sits in its cwd, so it
  proves the keyed argument file is read at all. Reviewer 1 measured the split: a seed that prefers
  `./frpc.toml` whenever it exists **is** caught (3 passed / 1 failed, records 2 vs 1 — the failure
  the fixture's comment documents), but a seed that falls back to the argument only when the cwd file
  does not set the key stays 4/4 green. **Done-when:** a fixture with the cwd file keyed and the `-c` file
  key-less pins the precedence, or the item records that precedence is deliberately not pinned.

  **Done (2026-10-01, at `0544b481` on `fix/test-precision-residue`).** Commit `a6f4f55f` (rebased)
  gives sub-case (d) provenance instead of a record count. The `-c` file now declares the only
  `main` proxy with a distinctive `local_port` (`MAIN_PROXY`, `frpc/tests/admin_config_get_warning.rs:360-361`),
  while the cwd `frpc.toml` declares none, and (d) asserts the GET body itself carries
  `"local_port":45999` (the `assert!` at `:610-615`). A seed that reads the key-less cwd file first therefore no
  longer passes at 4/4: it answers `HTTP/1.0 404 … proxy "main" not found` and the assertion panics
  at `:610:5`. Combined with the pre-existing assertions, precedence is now pinned in the direction the
  item asked for (the `-c` file wins over a keyed cwd file — the sibling (c) fixture covers the
  opposite split) rather than dropped. No `CHANGELOG.md` entry: test fixture only.

- [x] **A `SIGUSR1` sent to `frps --config-dir` in the pre-registration window silently reloads only the registered subset.**
  Filed by the #419 adversarial review. The handler task logs `SIGUSR1 reload ready (pid=…)` as soon
  as the handler is installed (`frps/src/main.rs:321`), but the registry is filled later, once each
  task has constructed its service (`frps/src/main.rs:258-262`); the observed order is startup line
  → ready → bind. A signal landing between the marker and a registration therefore reloads only the
  services registered so far, and nothing indicates that any were missed. Measured (adversarial
  review, own probe tree): 12 config files → 10/12 summaries once in 4 runs at delay 0; 40 files →
  39/40 twice in 4; clean at 0.3 s. Strictly better than the pre-fix death, but silent — a partial
  reload reads exactly like a complete one. The two-file fan-out pin is structurally exposed too:
  its only population guard is a fixed 600 ms settle after the startup marker, measured 8/8 stable
  (and 48 green runs overall).

  Done-when: the ready marker is gated on registration completing, or the reload logs `reloaded N of
  M`, with a test that sends the signal immediately after the marker and asserts the count.

  **Done (2026-10-01, at `d58166e3` on `fix/config-dir-residue`).** The ready marker is now gated on
  registration: each spawned task holds a `DirRegistryEntry` barrier (`frps/src/main.rs:63-77`, armed at
  `frps/src/main.rs:414`) so the marker cannot appear while the registry is still filling, and the fan-out
  keeps logging `reloaded N of M` (`frps/src/main.rs:571`). Pinned by
  `a_config_dir_sigusr1_immediately_after_the_ready_marker_reloads_everything`
  (`frps/tests/warn_delivery.rs:793`), which sends the signal the instant the marker appears and requires the
  full count; the adversarial review measured the pre-fix partial-reload window (40 files → 39/40) and
  confirmed the pin reds when the barrier is removed — with a bogus `reloaded 4 of 4 services`.

- [x] **A panicking `frps --config-dir` service task is logged but not counted, so a directory where every task panics would still exit 0.**
  Found independently by both reviewers of #419. The aggregation pushes only `Ok(Err(code))` into
  `task_failures` (`frps/src/main.rs:383`); a `JoinError` is logged at `frps/src/main.rs:384`
  ("frps service task panicked") and dropped, so `task_failures.len() == spawned` can never hold when
  the failures are panics and the process falls through to exit 0. Not reachable from a config file
  in either reviewer's probes (the reachable failures are typed `Err` returns) and pre-existing
  log-and-keep-serving behaviour — but it is the same class as the item #419 fixed.

  Done-when: a panicking task contributes to the all-failed decision, or the panic arm is documented
  as deliberately non-fatal, with a test that makes one task panic.

  **Done (2026-10-01, at `d58166e3` on `fix/config-dir-residue`).** The panic arm no longer just logs: a
  `JoinError` joins the same failure list the all-failed decision reads (`frps/src/main.rs:617`), so a
  directory where every task panics exits non-zero instead of 0. Pinned by
  `config_dir_where_every_task_panics_exits_nonzero` (`frps/tests/cli_exit_codes.rs:1102`). The neighbouring
  rule is pinned in both directions too: `failures.len() == files.len()` mutated to `if true` reds the
  pins, and the converse ordered-arm mutant reds only the new ones. `frpc` has the mirrored arm.

- [x] **`frps --config-dir`'s load-failure exit code still diverges from `-c`'s.**
  The rework in #419 covers *spawned* tasks only: a file whose **load** fails never becomes a task,
  so it cannot reach the all-failed decision. Measured at `d9f8e63c`: a directory where every file
  fails to load exits **2** (`handles.is_empty()` → `EXIT_CONFIG`, `frps/src/main.rs:301-304`) where
  `-c` on the same file exits **1**; a directory mixing `a.toml` (unknown key → load failure) with
  `b.toml` (no token → construction failure) exits **3** — `b.toml`'s code — where `-c a.toml` is 1.
  Pre-existing on this lane and recorded in the code comment at `frps/src/main.rs:370-377`.

  Done-when: a load-failing file is tracked in the same all-failed decision so the lane matches
  `-c`'s code, or the divergence is documented as deliberate with the measured table, and pinned.

  **Done (2026-10-01, at `d58166e3` on `fix/config-dir-residue`).** A load-failing file is tracked with the
  same failure list, and when every file fails the lane returns the code `-c` returns:
  `config_dir_where_every_file_fails_to_load_exits_like_dash_c` (`frps/tests/cli_exit_codes.rs:975`), with
  `config_dir_exits_the_first_files_code_when_a_later_file_fails_to_load` (`:1019`) pinning the mixed shape
  and `config_dir_refuses_an_empty_directory_with_2` (`:1064`) keeping the empty-directory refusal at 2. The
  `frpc` twins are `frpc/tests/cli_exit_codes.rs:593`/`:646`/`:696`. Deleting
  `failures.sort_by_key(|(file_index, _)| *file_index)` (`frps/src/main.rs:623`) reds the pins
  (`left: Some(1) right: Some(3)`), and the `frpc` comparator is pinned in both directions by the mirror
  fixture.

- [x] **The `frps --config-dir` SIGUSR1 fan-out has no record of being untested off unix.**
  Filed by the #419 round-2 review. The handler lives behind `#[cfg(unix)]` (SIGUSR1 is a unix
  signal), gated in `frps/src/main.rs` (`:218`, `:220`, `:238`, `:257`, `:278`, `:314`, `:393`),
  so on a non-unix build the reload path does not exist — and the two fan-out pins
  (`frps/tests/warn_delivery.rs:606`, `:636`) carry **no** gating of their own (`grep -c 'cfg('`
  over that file is 0) while both wait on `SIGNAL_READY_MARKER` (`:92`, used at `:227`/`:247`) and
  shell out to `Command::new("kill")` (`:229`/`:250`): off unix they still compile and would
  **fail**, rather than being skipped — which is defensible, but no record states it, so a non-unix
  build's coverage of the lane is invisible.

  Done-when: the unix-only nature is either recorded where the lane is documented and in the test
  file's own gating, or a non-unix no-op arm is pinned, so the omission is deliberate and visible.

  **Done (2026-10-01, at `d58166e3` on `fix/config-dir-residue`).** The unix-only nature is now recorded
  where the lane lives: `frps/src/main.rs:286-294` states that the whole SIGUSR1 lane has no non-unix arm,
  the test module's doc comment (`frps/tests/warn_delivery.rs:80-84`) repeats that the fan-out is behind
  `#[cfg(unix)]` and that the pins would fail rather than skip off unix, and every fan-out pin and helper
  carries its own `#[cfg(unix)]` (`frps/tests/warn_delivery.rs:791`, `:849`, and the helpers at `:241`,
  `:261`, `:284`, `:308`, `:315`, `:376`). No non-unix no-op arm was added: the omission is deliberate and
  visible.

- [x] **The mixed init-fail + run-fail `--config-dir` exit code is a probe value, not a pinned one.**
  Filed by the #419 round-2 review. The `TODO.md:3231` Done block records "mixed init-fail + run-fail
  → rc 3, nothing listening", but the pinned tests (`frps/tests/cli_exit_codes.rs:581` all-init-fail,
  `:633` all-run-fail) only assert a non-zero rc with no `listener started` record; the exact `3` for
  the mixed shape comes from a one-off probe.

  Done-when: a pin asserts the exact code for the mixed shape (or the record says explicitly that only
  non-zero is contractual for it).

  **Done (2026-10-01, at `d58166e3` on `fix/config-dir-residue`).** The mixed shape is pinned by an exact
  code, not a probe: `config_dir_exits_the_first_files_code_when_a_later_file_fails_to_load`
  (`frps/tests/cli_exit_codes.rs:1019`) builds a directory whose later file fails to load (code 1) and whose
  earlier file fails to construct (code 3), and asserts `Some(3)` — the earlier file's code, the same value
  `-c a.toml` exits with. The `frpc` twin `frpc/tests/cli_exit_codes.rs:696` asserts the mirror shape
  (`Some(2)`). Both red under the comparator mutants.

- [x] **The `frps --config-dir` code comments cite probe scripts that are not in the repo.**
  Filed by the #419 adversarial round-2 review. Three comments in `frps/src/main.rs` justify their
  measured numbers by pointing at scratch probes under `/tmp` — `:214`
  (`/tmp/frps-cfgdir-probe/probe-early.py`, the 8/8 `unix_wait_status(158)` window), `:271`
  (`/tmp/frps-cfgdir-probe/probe-bind.py`, the held-port `-c` 1 / `--config-dir` 0 row) and `:372`
  (`/tmp/frps-cfgdir-probe/probe-shapes.py`, the mixed load+construction code table) — so a reader of
  the tree cannot reproduce the figures behind them and the files vanish with the temp directory.

  Done-when: the numbers the comments lean on are either pinned by a test (preferred) or reproduced
  by a command/recipe the comment itself spells out, and no shipped comment points at `/tmp`.

  **Done (2026-10-01, at `d58166e3` on `fix/config-dir-residue`).**
  `grep -c /tmp frps/src/main.rs frpc/src/main.rs` is now `0`/`0`: the comments that leaned on scratch probes
  state the recipe or the pin instead, so a reader of the tree can reproduce every figure. The two surviving
  `/tmp` mentions are not shipped comments about measurements — they are CI log paths inside step scripts
  (`.github/workflows/ci.yml:124`, `:360`, `:368` and the other lane logs), plus the test-harness note at
  `frps/tests/warn_delivery.rs:8`, which names the runner's temp directory rather than citing a probe.

- [x] **`registry.lock().unwrap()` in the `frps --config-dir` reload path has no poisoned-mutex test.**
  Filed by the #419 adversarial review as a residual. The registry is a
  `Arc<Mutex<Vec<(Arc<Service>, String)>>>` (`frps/src/main.rs:218-219`) locked with `.unwrap()` at
  `frps/src/main.rs:259`, `:280` and `:329`; a panic while one of those locks is held would poison
  it and turn every later registration or reload into a panic. No test exercises a poisoned lock.

  Done-when: either the lock is handled without `unwrap()` (a poisoned lock logged and skipped), or a
  test pins the panic-on-poison behaviour as intended.

  **Done (2026-10-01, at `d58166e3` on `fix/config-dir-residue`).** `lock_dir_registry`
  (`frps/src/main.rs:38`) now recovers a poisoned mutex — it logs the recovery and hands back the guard —
  instead of panicking, so one panicking writer cannot make every later registration and reload panic. The
  recovery path is pinned by the bin-unit test `lock_dir_registry_recovers_a_poisoned_registry`
  (`frps/src/main.rs:830`), which prints a completion marker after its last assertion
  (`frps/src/main.rs:1217`) and is verified by a CI step that checks both the listed test name and the marker.
  The marker's own residual — a body that prints it and returns passes with zero assertions — is filed as a
  separate item rather than claimed as closed.

- [x] **`frps --config-dir` freezes its config-file set at startup: a file added later is never loaded, a construction-failed file is never retried, and a removed file keeps serving.**
  Measured by the #419 verification review and re-measured by its adversarial review. The directory
  is read once (`collect_config_files`, `frps/src/main.rs:190`), one task per file is spawned, and the
  registry only ever shrinks (the `run()`-error arm removes the dead entry,
  `frps/src/main.rs:275-295`); nothing rescans the directory or retries a failed construction.
  Measured: a file deleted after startup leaves the process alive and logs
  `SIGUSR1 reload: Failed to reload config: <path>: failed to read config file: No such file or
  directory (os error 2)`; a file created after startup is never picked up, and a config whose
  service failed to construct is never retried on a later signal.

  Done-when: either the lane documents and pins "the file set is fixed at startup; reload only
  re-reads those files", or it rescans the directory on each `SIGUSR1` and retries failed
  constructions.

  **Done (2026-10-01, at `d58166e3` on `fix/config-dir-residue`).** The lane documents and pins the chosen
  contract: "the file set is fixed at startup; a reload only re-reads those files". The comment at
  `frps/src/main.rs:262` says the directory is read once and that SIGUSR1 re-reads exactly those files, and
  `a_config_dir_reload_keeps_the_startup_file_set` (`frps/tests/warn_delivery.rs:851`) adds a config file
  between startup and the signal and asserts it is not served while the startup files still are. No rescan
  and no retry of a failed construction is added, which is now a documented choice rather than an accident.

- [x] **`frpc --config-dir` still exits 0 when its service cannot run, so the client and server lanes now disagree.**
  `docs/developing.md:1013` records `frpc --config-dir <good>, service cannot run` as rc **0** — the
  same shape #419 fixed on the `frps` side (where the code comment at `frps/src/main.rs:183-188`
  notes the divergence from Go's *client* directory mode, which exits 0 for a missing or invalid
  directory). With the `frps` lane now exiting 1
  (`config_dir_where_every_service_fails_to_run_exits_like_dash_c`,
  `frps/tests/cli_exit_codes.rs:633`), the two `--config-dir` lanes answer differently for the same
  failure, and the client is the one reporting success while nothing is served.

  Done-when: `frpc --config-dir` carries its service failure out of the lane the way `frps` now does,
  or `docs/developing.md` records the asymmetry as deliberate with a measurement of both lanes, and
  a test pins the client's rc.

  **Done (2026-10-01, at `d58166e3` on `fix/config-dir-residue`).** `frpc --config-dir` now carries its
  service failure out of the lane: rc **1** where it was **0** (`frpc/src/main.rs:509`, `:578`), matching
  the `frps` lane, with `config_dir_where_every_service_fails_to_run_exits_like_dash_c`
  (`frpc/tests/cli_exit_codes.rs:593`) pinning it. The two lanes now agree for the same failure. Go keeps its
  historical `0` here (measured again: rc 0 in 0.027 s against a refused port) and `docs/developing.md:1019`
  records both columns and the reason the divergence from Go is deliberate.

- [x] **`docs/developing.md:1471`'s `--config-dir`/`bindAddr = ""` row is a superseded stage record.**
  The row's frp-rs column still reads "**rc 0 with nothing bound**" for `--config-dir` with
  `bindAddr = ""`, with `-c` exiting 1 on a lookup error and "the defect is that exit code".
  Measured at `971e0fa0`: `bind_addr = ""` is completed to `0.0.0.0` on both paths —
  `frps --config-dir <dir>` with that file logs `listener started on 0.0.0.0:19961` and keeps
  running; `SIGTERM` rc 0 once the shutdown handler is installed (`frp-server/src/service.rs:1858`; a signal in the startup window dies with rc 143 on both lanes), and `frps -c <file>` binds `0.0.0.0:19955`. `CHANGELOG.md`'s
  bind-address round already records the fill that made the row stale; only the qualifier is missing.

  Done-when: the row carries a superseded note (or its "now" column is re-measured), so it cannot be
  read as today's behaviour.
  Done: fixed in #419 (`e050b1df`, wording corrected in `52a40a36`). The row now carries the
  superseded note with the measured fill (`frps --config-dir` with that file logs `listener started on
  0.0.0.0:19961` and keeps running) and the corrected shutdown figure — `SIGTERM` rc 0 once the
  handler is installed (`frp-server/src/service.rs:1858`; a signal landing in the startup window dies
  with rc 143 on **both** lanes), per the adversarial round-2 measurement.

- [x] **Strict mode checks unknown keys in the legacy `.ini` dialect, where Go's legacy reader ignores them even with `strict_config` on.**
  Measured while closing the typeless-`.ini` item (#418). A legacy-shaped `.ini`
  (`[common]` plus sections) is decoded by Go's legacy reader, which accepts-and-ignores
  unknown keys regardless of `--strict-config`; frp-rs runs the same section-level strict
  check it runs for the v1 formats. Measured, `frpc verify -c <ini>`:
  * `[common]` + `[webServer] zzz_unknown_key = 1` → Go rc **0** in both modes; frp-rs
    `--strict-config=false` rc 0, `--strict-config` rc **1**
    (`unknown field "web_server.zzz_unknown_key"`).
  * `[common]` + `[webServer.foo] bar = 1` → Go rc **0** in both modes; frp-rs
    `--strict-config=false` rc 0 with `Proxies: 0`, `--strict-config` rc **1**
    (`unknown field "web_server.foo"`).
  * v1 TOML control (unknown top-level key) → Go rc 1 by default and rc 0 with
    `--strict-config=false`, frp-rs the same, so the gap is the legacy dialect and not the
    strict setting.
  The direction is a **false refusal**: frp-rs rejects a config Go accepts. The
  element-level half of Go's accept-and-ignore is already implemented
  (`strip_unknown_legacy_element_keys`); this is the section-level half.

  Done-when: the legacy dialect is exempted from the section-level strict check (with the
  `.ini`-only boundary stated in `docs/config.md`), or the stricter refusal is recorded as
  deliberate in `docs/developing.md` with this measurement, and either way pinned by a test.

  **Done (2026-09-30, at `8211fcd9` on `fix/legacy-ini-parity`).** The section-level strict walk is split in two:
  `frp-core/src/config/strict.rs:456 run_strict_check_top_level` delegates to
  `frp-core/src/config/strict.rs:464 run_strict_check_scoped(.., recurse)` and the descent into
  sub-tables stops at `frp-core/src/config/strict.rs:903` (`if !recurse { continue; }`); the `.ini`
  path takes the top-level-only walk while every v1 format keeps the full one. Measured `frpc
  verify -c <ini>`: `i1a.ini` (`[common]` + `[webServer] zzz_unknown_key = 1`) Go rc 0/0, before
  frp-rs rc 0/1 `unknown field "web_server.zzz_unknown_key"`, now rc 0/0; `i1b.ini`
  (`[webServer.foo] bar = 1`) Go rc 0/0, before rc 0/1 `unknown field "web_server.foo"`, now
  rc 0/0; the v1 TOML control `i1c.toml` (unknown top-level key) stays rc 0/1 on both, so the
  exemption is `.ini`-only. The **top level** of an `.ini` therefore still carries the full check —
  the boundary is stated in `docs/config.md` (§ Supported Formats, scope bullets). Pinned by
  `legacy_ini_section_keys_are_exempt_from_strict_only_in_ini`
  (`frp-core/src/config/tests.rs:7016`); replacing the dispatch with a bare `run_strict_check`
  reddens it. Residue: an unknown key merged out of `[common]` (`c1.ini`,
  `zzz_unknown_common = 1`) is hoisted to the top level before the check and is still refused in
  strict mode where Go is rc 0 — deliberate, filed below.

- [x] **A legacy `.ini` proxy section with `type = ""` is refused here and defaults to `tcp` on Go.**
  Measured while closing the typeless-`.ini` item (#418). `frpc verify -c <ini>` on
  `[common]` + `[p] type = "" local_port = 8080 remote_port = 18080`: Go rc **0** in both
  loader modes (its legacy proxy config defaults an empty type the same way it defaults a
  missing one) and frp-rs rc **1** in both modes with `proxy 'p': invalid proxy_type ''`.
  The new rule covers a *missing* `type` key, but an explicitly empty one still reaches
  validation, so this is a false refusal one step away from the item #418 closed.

  Done-when: an empty `type` in the `.ini` dialect is defaulted like a missing one, or the
  refusal is recorded as deliberate with this measurement, pinned in both loader modes.

  **Done (2026-09-30, at `8211fcd9` on `fix/legacy-ini-parity`).** Go's legacy collector reads the type with
  `section.Key("type").String()`, which cannot distinguish an absent key from an empty one
  (`proxyType == ""` defaults to `ProxyTypeTCP`), while frp-rs defaulted only a *missing* key. New
  `frp-core/src/config/normalize.rs:1948 type_missing_or_empty` (None → true, `String("")` →
  true, anything else → false) is consulted where the default is applied. Measured `frpc verify -c
  i2.ini` (`[p] type = "" local_port = 8080 remote_port = 18080`): Go rc 0/0 and the frps log
  shows `new proxy [p] type [tcp]`; before frp-rs rc 1/1 `proxy 'p': invalid proxy_type ''`; now
  rc 0/0 with `Proxies: 1`. The v1 control `t4.toml` (`type = ""`) stays rc 1/1 on both (Go
  `unknown proxy type: `, frp-rs `invalid proxy_type ''`), so the defaulting is `.ini`-only.
  Pinned by `legacy_ini_empty_type_defaults_to_tcp_like_go` (`frp-core/src/config/tests.rs:7090`);
  reverting the empty-string arm of `type_missing_or_empty` to `false` reddens it.

- [x] **A typeless `role = "visitor"` section in a legacy `.ini` is dropped silently in non-strict mode and refused with a different message than Go's in strict mode.**
  Measured while closing the typeless-`.ini` item (#418). The exclusion itself is
  deliberate (Go refuses a typeless visitor, so defaulting it to a `tcp` *proxy* would be
  worse), but neither verdict matches. Config: `[common]` + `[v] role = "visitor"` +
  `server_name`. Go rc **1** in both loader modes, stdout `failed to parse visitor v, err:
  type shouldn't be empty`. frp-rs: `--strict-config=false` rc **0** with `Proxies: 0` (the
  section disappears with no diagnostic), and `--strict-config` rc **1** with
  `unknown field "v" in config file … — did you mean 'v2'?` — a different code path and a
  different message.

  Done-when: a typeless visitor reports Go's `type shouldn't be empty` in both modes (or at
  least is refused in non-strict mode instead of dropped), pinned in both modes.

  **Done (2026-09-30, at `8211fcd9` on `fix/legacy-ini-parity`).** A typeless section whose `role` is `visitor` is now
  refused **before** collection, in both loader modes, with Go's message: the guards at
  `frp-core/src/config/normalize.rs:1989` (the nested walk) and `:1995` (the top level) return the
  error built at `frp-core/src/config/normalize.rs:1996-1998` (`failed to parse visitor {name}, err: type shouldn't be
  empty`), and it is applied at any depth — the collector walks the top level *and* every nested
  table, so `[auth.foo] role = "visitor" server_name = s`, which the top-level-only walk missed,
  is refused too. Measured `frpc verify -c i3.ini` (`[v] role = "visitor" server_name = s`): Go
  rc 1/1 `failed to parse visitor v, err: type shouldn't be empty`; before frp-rs rc 0 (lenient,
  `Proxies: 0`) / rc 1 `unknown field "v" … did you mean 'v2'?` (strict); now rc 1/1 with Go's
  message. Pinned by `legacy_ini_typeless_visitor_is_refused_at_any_depth`
  (`frp-core/src/config/tests.rs:7228`); disabling the guard reddens it. The v1 `[[visitors]]` /
  `[visitors.foo]` typed path is untouched.

- [x] **`--vhost-http-timeout` is modelled as `Option<u64>` where Go's is `int64`, so a negative value is refused here and accepted there.**
  Residual from the `--vhost-http-timeout` item closed in #418. Go registers the flag with
  `Int64VarP` (`pkg/config/flags.go:237`) and the config field is `int64`; frp-rs uses
  `Option<u64>`. Measured on `frps verify -c <valid>`: `--vhost-http-timeout -1` → Go rc
  **0** (`frps: the configuration file … syntax is ok`), frp-rs rc **1**
  `Error: couldn't parse '-1': invalid digit found in string`; `--vhost-http-timeout 30`
  agrees at rc 0 on both. The gap is two-sided, not only negative: a value that fits `u64`
  but not Go's `int64` diverges the other way — `--vhost-http-timeout 9999999999999999999`
  is rc **0** here (`syntax is ok`) and Go rc **1** (out of range), measured by #418's
  round-2 review. A negative Go value is almost certainly meaningless downstream (a
  `time.Duration` built from it), so the question is only whether to accept-and-ignore the
  argv or refuse it loudly.

  Done-when: the flag is typed to match Go's `int64` (accepting the same argv, and refusing
  what Go refuses), or the refusal is recorded as a deliberate divergence with both
  measurements, and a test pins whichever answer is chosen.

  **Done (2026-10-01, at `4b9c9951` on `fix/cli-flag-binding`, PR #427).** The first branch: the
  flag and `ServerConfig::vhost_http_timeout` are `i64`, matching Go's `Int64VarP`
  (`/tmp/frp-go-src/pkg/config/flags.go:237`) and Go's `int64` field; the internal
  `clamp_vhost_timeout` keeps its `u64` return and its `<= 0` floor, so `--vhost-http-timeout -1`
  is accepted and ignored like Go while `--vhost-http-timeout 9999999999999999999` is refused like
  Go. Pinned end to end by
  `frps/tests/cli_exit_codes.rs::verify_accepts_vhost_http_timeout_both_spellings_and_prints_go_line`
  (`frps/tests/cli_exit_codes.rs:2289`). The refusal **text** for an out-of-range value is still
  Rust's rather than Go's `strconv.ParseInt` wording plus the `Usage:` block (**R4** at the end of
  this file).
  Ledger after this batch: **29 open / 163 closed** (base `f503b4e7`: 25 open / 161 closed; the
  batch closes the two log-flag/`--vhost-http-timeout` items and files six residues R1–R6 at the end
  of this file).

- [x] **An `.ini` section named exactly a reserved settings root cannot be a legacy proxy, so the proxy is lost in lenient mode and refused in strict mode where Go registers one.**
  Measured at base971 and at the #418 fixed head by that PR's round-3 adversarial review.
  `[web_server] type = "tcp"` + `local_port`/`remote_port`, and `[transport] local_port`, give
  frp-rs `--strict-config=false` rc 0 with `Proxies: 0` (the section stays a settings table) and
  `--strict-config` rc 1 `unknown field "web_server.local_port"`; Go v0.71.0 is rc **0** in both
  modes. The exemption is pre-existing and is what keeps `[web_server]` itself a settings table, so
  the fix has to be key-based rather than name-based: on Go, a reserved-root section that carries
  proxy keys (`type`, or `local_port`/`remote_port`) is a proxy.

  Done-when: the reserved-root exemption stops applying to a section carrying `type` or the port
  keys, or the loss is recorded as deliberate with this measurement and pinned by a test.

  **Done (2026-09-30, at `8211fcd9` on `fix/legacy-ini-parity`) for the port-carrying spelling.** A reserved-root section
  that carries `local_port`/`remote_port` is collected as a legacy proxy again, keyed on the
  **ports** and never on `type`
  (`frp-core/src/config/normalize.rs:2097`: `is_ini && (local_port || remote_port)`), so
  `[web_server]` itself, the portless `[web_server] port = 7500` admin block and
  `[log] type = "custom"` all stay settings tables. Measured: `[web_server] type = "tcp"
  local_port = 8080 remote_port = 18080` Go rc 0/0 with `new proxy [web_server] type [tcp]
  success`, before frp-rs rc 0 (`Proxies: 0`) / rc 1 `unknown field "web_server.local_port"`, now
  rc 0/0 with `Proxies: 1`; `[transport] local_port = 8080` likewise (before strict
  `unknown field "local_port"`). Pinned by `legacy_ini_headers_naming_v1_roots_are_still_proxies`
  (`frp-core/src/config/tests.rs:7159`), whose port-only clause is the discriminator, with the
  counterpart `legacy_ini_typed_settings_root_with_type_stays_a_settings_table`
  (`frp-core/src/config/tests.rs:7428`) recording the opposite verdict for a `type`-only root. The
  `type`-only half is the open residue filed below.

- [x] **A `[visitors.NAME]` / `[proxies.NAME]` legacy `.ini` section with no port key is refused with `invalid type: map, expected a sequence` where Go accepts it.**
  Measured at the #418 fixed head by that PR's round-3 adversarial review. `[visitors.foo]` and
  `[proxies.foo]` without `local_port`/`remote_port` give frp-rs rc **1** `invalid type: map,
  expected a sequence` — the dotted header expands to a v1 sub-table, so the legacy collector no
  longer sees a section to collect — where Go v0.71.0 is rc **0** in both loader modes. The
  typeless-with-ports rule closed the port-carrying half of this shape only.

  Done-when: a portless dotted spelling of a typed root is treated as the section it looks like (or
  the refusal is recorded as deliberate with this measurement), pinned in both loader modes.

  **Done (2026-09-30, at `8211fcd9` on `fix/legacy-ini-parity`).** `proxies`/`visitors` were removed from
  `format::INI_NESTED_SECTION_ROOTS` (`frp-core/src/config/format.rs:259`), so `[visitors.NAME]` /
  `[proxies.NAME]` is no longer expanded into a v1 sub-table, and the collector filter keeps a
  dotted header that names one of those array roots (`normalize.rs:1936 names_an_ini_array_root`,
  used at `frp-core/src/config/normalize.rs:2077`) instead of dropping it. Measured: `[visitors.foo]
  server_name = s` and `[proxies.foo]` — Go rc 0/0, before frp-rs rc 1/1 `config validation error:
  invalid type: map, expected a sequence`, now rc 0/0; `[visitors.foo] role = "visitor" type =
  "stcp" …` → `Visitors: 1`; `[proxies.foo] type = "tcp"` + ports → `Proxies: 1`; a bare
  `[visitors]` → Go registers `new proxy [visitors] type [tcp]` and frp-rs reports `Proxies: 1`.
  Pinned by `legacy_ini_headers_naming_v1_roots_are_still_proxies`
  (`frp-core/src/config/tests.rs:7159`, the array-root clause) and
  `legacy_ini_typed_array_root_visitor_is_collected` (`frp-core/src/config/tests.rs:7378`);
  re-adding the two roots to `INI_NESTED_SECTION_ROOTS` reddens the first.

- [ ] **Four more test-precision residues the `test-precision-residue` round-2 reviews measured.**
  Same class as the fixture-harness nits the `repo-health-residue` reviews filed (`TODO.md:7191`): a
  test that pins less than its name claims, so a real regression stays green.
  (a) The pinned warning bytes are the shipped static, but the **emitted** record is only
  substring-checked: `frp-core/tests/server_tls_enable_warning.rs:441` asserts
  `c.logged_by_warning_call.contains(NEEDLE)` (`NEEDLE` at `:93`), never equality against
  `SERVER_TLS_ENABLE_INERT_WARNING`. Measured: appending a clause at the emit site
  (`frp-core/src/config/loader.rs:597` → `tracing::warn!("{} (see docs/tls.md)", …)`) keeps all 8
  tests green while the user-visible log line drifts from the static. Done-when: the assertion pins
  the emitted record (equality, or a suffix check that tolerates only the tracing prefix) and the
  appended-clause mutant reds.
  **(a) Done (PR #428, head `dbcf5cbf`).** The emitted record is now pinned byte-exactly:
  `frp-core/tests/common/mod.rs:88` `assert_record_is_exactly_the_message(tag, record, want, target)` asserts
  the whole record — `contains(want)`, exactly one occurrence, a tail that is empty or a single `\n`, and a
  prefix that ends with `" frp_core::config::loader: "` — and both captures call it
  (`frp-core/tests/server_tls_enable_warning.rs:459`,
  `frp-core/tests/web_server_tls_enable_warning.rs:244` and `:468`). The append-a-clause mutant at the
  web_server emit site (`frp-core/src/config/loader.rs:723`) now reds `4 passed; 2 failed` at
  `frp-core/tests/common/mod.rs:102` (`got tail: " (see docs/tls.md)\n"`), and an `EXTRA ` prefix mutant at the
  server site (`:680`) reds `7/1` at `common/mod.rs:114` (`got prefix: " WARN
  frp_core::config::loader: EXTRA "`). Parts (b), (c) and (d) are untouched.
  (b) `frp-server/src/control/login.rs`'s `request_head_timeout()` accessor is not pinned to a
  non-constant override: a lying accessor that ignores the stored field (`:2343-2349`) and returns
  `MOCK_REQUEST_HEAD_TIMEOUT` keeps all 19 oidc tests green. Done-when: the delegation pin
  (`:2758-2768`) or a sibling drives an override that differs from the constant and asserts the
  stored field.

  **(b) Done (PR #432, code head `df78c203`).** `frp-server/src/control/login.rs:2795`
  `mock_handle_reports_the_override_it_was_built_with` loops three overrides — `125 ms`, `60 s` and a
  deliberately sub-100 ms non-round `Duration::from_micros(31_337)` (`:2799`) — each checked in an in-loop
  `assert_ne!` (`:2805`) against the 5 s `MOCK_REQUEST_HEAD_TIMEOUT` (`:2235`), and asserts the handle's
  accessor (`fn request_head_timeout` at `:2348`) returns the stored deadline (`:2811`). A lying accessor
  that returns `MOCK_REQUEST_HEAD_TIMEOUT` reds it at `frp-server/src/control/login.rs:2811:13`
  (`left: 5s / right: 31.337ms`), and one that special-cases a round threshold or hardcodes the two
  originally pinned values reds the same assertion (`:2811:13`) — both survived the round-1 two-value pin (`1 passed`) while
  the two pre-existing mock pins stay green.
  (c) `frpc/tests/admin_config_get_warning.rs`'s `seed_resolves_spellings_only_the_loader_does`
  spawns four frpc children and calls `free_port()` per sub-case, so a released port can be re-taken
  between spawns: the round-2 run hit `frpc admin server failed: Address already in use (os error
  48)` once, passing on retry. Done-when: the port is held for the fixture's lifetime, or the test
  retries deterministically instead of depending on the race.

  **(c) Done (PR #432, code head `df78c203`).** All five admin tests now spawn through `spawn_ready`
  (`frpc/tests/admin_config_get_warning.rs:389`) → `spawn_admin_ready` (`:425`), which for each of
  `MAX_ADMIN_PORT_ATTEMPTS` (`:116`, 3) attempts writes the config with **that attempt's** freshly leased
  port and re-runs `admin_port_attempt` (`:471`); a lost port is recognized from the child's own stdout
  record `ADMIN_PORT_HELD` (`:112`, `admin server failed: Address already in use`) inside a 250 ms
  `FAST_FAIL_WINDOW` (`:107`) — the child keeps running, so the retry cannot rely on a wait status — and
  costs ~250 ms instead of the 20 s readiness window. `struct PortLease` (`:170`) holds a probe listener
  for the attempt and is released immediately before spawning (`:440-447`), so what is closed is the
  failure mode, not the release→bind window itself. `admin_port_retry_recovers_from_a_held_port` (`:885`)
  forces a deliberately held first port, asserts the printed per-attempt reason, a distinct retry **port**
  (`:911`; the test asserts a port, not a PID) and both directions of `rival_bind_fails` (`:510`); with
  `MAX_ADMIN_PORT_ATTEMPTS = 1` it reds at `:462:5` (`4 passed; 1 failed`), and the two admin files are 13/13
  green (8 runs under four CPU burners plus 5 gate runs). Lane: `cargo test -p frpc --features full,admin
  --test admin_config_get_warning --test warn_delivery` — the unfiltered `cargo test -p frpc --features
  full,admin` is red for a reason this batch did not introduce (`frpc/tests/cli_inputs.rs:1485:9`, `33 passed;
  1 failed`, filed below), so the filtered form is the reproducible lane; with neither feature the plain command
  compiles `admin_config_get_warning.rs` away — it is `#![cfg(all(feature = "full", feature = "admin"))]`.
  (d) The `-z "$TREE"` guard's own `exit 1` (`scripts/tests/repo-health-fixtures.sh:282`) is dormant
  while the `setup_die` path works and no scenario forces an empty root, so reverting it alone stays
  green; the case-variant symlink misclassification in `scripts/repo-health.sh` is pre-existing and
  unreachable on a case-sensitive filesystem. Done-when: either a scenario exercises an empty root
  (killing that guard) or the dormant branch is removed, and the case-insensitive-volume limitation
  is recorded where the containment check is documented.
  Ledger after this batch: **26 open / 154 closed** (base `bebe888e`: 24 open / 153 closed; the
  fixed-settle flip moves one item open→closed and this batch files three new residues — the round-2
  TLS-enable capture item and the two the round-2 delta review measured below).

- [x] **Four residues #428's round-2 adversarial review measured in the new warning pins.** Same
  test-precision class as the item above; none blocks the fix.
  (a) The shared record helper anchors the tracing target only as a counted suffix
  (`frp-core/tests/common/mod.rs:88` checks `prefix.matches(" frp_core::config::loader: ").count() == 1`
  and `prefix.ends_with(…)`), so a rewritten `frp-core/src/config/loader.rs:723`
  `warn!(target: "x frp_core::config::loader", …)` keeps the web_server capture green (measured 6/0) while
  the emitted target changes. Done-when: the anchor rejects a prefix key that differs from the constant, or
  the helper compares the full `target:` field.
  (b) `frp-server/src/service.rs:420`'s resolver is not witnessed by any CI lane: forcing it to
  `cfg!(feature = "tls")` (i.e. always `true`) survives every lane, because every `frps` lane links
  `frp-server` with `tls` on (`.github/workflows/ci.yml:364`, `:633`, `:676`, `:740`, `:776`). In the one
  buildable dashboard-on/tls-off shape the mutant emits the dashboard text. Done-when: a lane runs
  `cargo test -p frps --no-default-features --features micro,dashboard` (the `frps-micro` binary does
  build and does emit the no-TLS text) or the gap is pinned by a unit test on the resolver.
  (c) The two new pin files have no count guard: `ci.yml` never names
  `frp-core/tests/{server,web_server}_tls_enable_warning.rs`, so `#[ignore]` on
  `the_no_tls_build_names_no_tls_behaviour` yields `5 passed / 1 ignored / exit 0` where every sibling
  delivery lane has a guard. Done-when: both targets get an `-- --list`-derived count literal.
  (d) `expected_warning` (`frp-core/tests/web_server_tls_enable_warning.rs:113`) is read only at `:247`
  (through `Captured.expected`), so its `NoWebServer` arm is dead code — either it is exercised or the arm is
  removed.

  **Done (2026-10-01, at code head `b86e3592` on `fix/warning-pin-precision`, PR #433).** All four residues
  closed, each by a pin a mutant reds. (a) The shared helper now compares the whole tracing-level field
  **untrimmed** against the literal: `assert_eq!(level, " WARN", …)` at `frp-core/tests/common/mod.rs:132`
  replaces the round-1 `level.trim() == "WARN"`, which was strictly weaker because `trim()` erases exactly the
  bytes the anchor exists to detect. Mutants at the web-server emit site (`frp-core/src/config/loader.rs:723`):
  a target rewritten to `x frp_core::config::loader`, and three that put a space, `\n` or `\t` between the
  level and the target — all four red at `frp-core/tests/common/mod.rs:132:5` (`4 passed; 2 failed`, exit 101,
  lefts `" WARN x"`, `" WARN \n"`, `" WARN \t"`, `" WARN "`), and a level rewritten to `error!` reds as well.
  The superset proof: the base accepted iff `level.contains("WARN") && !level.contains('\n')`, the head
  accepts iff `level == " WARN"`, and every other line of the helper is byte-identical — so nothing the old
  assertion caught is missed now. (b) `web_server_tls_enable_reader()` (`frp-server/src/service.rs:420`) is
  witnessed by `web_server_tls_enable_reader_answers_from_this_build` (`:2621`), whose `#[cfg]`-gated
  assertions pin which of the three answers this crate's feature pair produces, and which prints the
  completion marker `web-server-tls-enable-reader-pin: ok, {got:?}` (`:2637`) **after** them; the
  name-filtered lane `Run frp-server's web_server.tls.enable resolver test without TLS (count guard)`
  (`.github/workflows/ci.yml:460-514`) runs it in the one shape no other lane builds
  (`cargo test -p frp-server --no-default-features --features dashboard`). Executed in three states at the
  reviewed head: real head rc 0; resolver forced to the literal `true` rc 1 with the step's `::error::` naming
  the missing marker; assertion deleted rc 101. (c) Both pin files are count-guarded from their own
  `-- --list`: `Run frp-core's server tls_enable warning pin (count guard)`
  (`.github/workflows/ci.yml:551-583`, literal `8` at `:570`, `:573`, `:575`, `:577`) and
  `Run frp-core's web-server tls_enable warning pin (count guard)` (`:584-613`, literal `6` at `:600`, `:603`,
  `:605`, `:607`), both carrying the direction-aware failure text (a shrunken list says "restore them rather
  than lowering this literal"); the live `-- --list` counts are 8 and 6 at this head. (d) `expected_warning`
  (`frp-core/tests/web_server_tls_enable_warning.rs:113`) is now read back for **every** reader answer inside
  the three-reader loop (`assert_eq!(c.expected, expected, …)` at `:473`), so the `NoWebServer` arm is
  exercised and a wrong arm is red; the loop's own literal stays the independent witness. Gates:
  `cargo fmt --all -- --check` rc 0; `bash scripts/repo-health.sh` → `RESULT: invariants hold`. The diff is
  +184/−11 in four files (`.github/workflows/ci.yml` +118, `frp-core/tests/common/mod.rs` 36,
  `frp-core/tests/web_server_tls_enable_warning.rs` +12, `frp-server/src/service.rs` +29) — tests and CI only,
  no production behaviour change.
  **Ledger after this batch: 26 open / 155 closed** (base `2e8b1d52`: 26 open / 154 closed; this batch closes
  the warning-pin item and files one new residue), measured with `grep -cE '^- \[ \]' TODO.md` /
  `grep -cE '^- \[x\]' TODO.md`.

- [x] **`frps/tests/warn_delivery.rs`'s TLS-enable captures count the record instead of pinning it — the gap #428 closed for the `frp-core` captures, still open on the server side.**
  Filed by the coordinator while re-deriving part (a) of the item above at `80ed6a85`. The `frp-core`
  captures now call `assert_record_is_exactly_the_message` (`frp-core/tests/common/mod.rs:88`), but the
  `frps` capture still asserts only a count (`frps/tests/warn_delivery.rs:1113` `occurrences(&out, SERVER_KEY)`,
  helper at `:463`; the other count sites are the positive assertions `:539` and `:968`, plus the
  absence check `:564`, which an appended clause cannot drift). Measured on the merged tree: appending a
  clause at the emit site (`frp-core/src/config/loader.rs:680` →
  `tracing::warn!("{} but honestly", SERVER_TLS_ENABLE_INERT_WARNING.as_str())`) reds the `frp-core` lane
  (`written_server_tls_enable_warns_once_and_stays_inert` FAILED at `frp-core/tests/common/mod.rs:102`,
  `7 passed; 1 failed`) while `cargo test -p frps --test warn_delivery` stays **17 passed / 0 failed** — the
  server-visible line can drift from the static unnoticed.
  Done-when: the `frps` capture asserts the emitted record's bytes (equality, or the shared helper with the
  `frps` target) and the appended-clause mutant reds it.

  **Done (2026-10-01, at `a23bd305ba1720673f0f3b20eb814fb801b1bb9b` on `fix/frps-warn-record-pin`, PR #439).** The server-side capture now
  pins the record's bytes: `frps/tests/warn_delivery.rs` carries a local port of the `frp-core` helper
  (`WARNING_TARGET` `:573`, `strip_sgr` `:581`, `assert_record_is_exactly_the_message` `:619`,
  `assert_server_tls_enable_records_are_exactly_the_message` `:668` — `want` read from
  `frp_core::config::SERVER_TLS_ENABLE_INERT_WARNING` — and the count+byte wrapper
  `assert_one_server_tls_enable_warning` `:690`), applied at `:1175`, `:1193`, `:1199`, `:1210`, `:1246` (one
  record each) and `:1263` (two, after the SIGHUP/SIGUSR1 reload). The appended-clause mutant
  (`frp-core/src/config/loader.rs:680` → `tracing::warn!("{} but honestly", SERVER_TLS_ENABLE_INERT_WARNING.as_str())`)
  moved from **17 passed / 0 failed** at the base to `13 passed; 4 failed` at
  `frps/tests/warn_delivery.rs:633:5` (`the emit site appended bytes after the message (only a trailing
  newline is allowed); got tail: " but honestly"`). No `#[test]` was added, so `-- --list` stays 17 in both
  feature shapes. Rounds: verification (`/private/tmp/rev439-verify.md`) and adversarial
  (`/private/tmp/rev439-attack.md`, 20 emit-site mutants — 13 red in this lane, all four escapes caught by the
  unchanged `frp-core` sibling lane) both **MERGE-with-findings**; their residual findings are filed as the new
  row at the end of this file. Gates: `cargo fmt --all -- --check`, `RUSTFLAGS="-D warnings" clippy --workspace
  --all-targets --all-features`, `bash scripts/repo-health.sh` (`RESULT: invariants hold`),
  `cargo test -p frps --test warn_delivery` 17/0 with and without `--features dashboard`,
  `cargo test -p frp-core --test server_tls_enable_warning` 8/0 and `--test web_server_tls_enable_warning` 6/0.
  Ledger after this close: **31 open / 165 closed** (base `a1ae6a9d`: 31 open / 164 closed).
- [x] **The three CI-guard strengths the `warning-pin` round-2 adversarial measured: the guards prove the tests ran, not that they asserted anything.**
  Filed by the coordinator from the round-2 adversarial report (`/private/tmp/rev-g1r2-attack.md`); none blocks
  PR #433. (a) The resolver pin's completion marker is self-reported: deleting its three `assert_eq!`s while
  keeping the `println!`, or hoisting the print before an early `return;`, or renaming the test and adding a
  same-named stub that only prints the marker, all leave the step green — the shell marker cannot witness that
  assertions exist. Done-when: the lane checks the marker's variant name against the arm the shape must take,
  or the pin is structured so a body that skips its assertions cannot print the marker. (b) The two new count
  guards (`.github/workflows/ci.yml:551-583`, `:584-613`) check the *count* only: deleting the
  `assert_eq!(c.expected, expected, …)` this PR adds (`frp-core/tests/web_server_tls_enable_warning.rs:473`),
  or a `return;` as the pinned test's first statement, still leaves the web-server guard green
  (`6 tests listed (expected 6), 0 failed`). Done-when: each guard also requires the run's own
  `N passed; 0 failed` summary to match the `-- --list` count, or pins the test names. (c) The marker coupling
  produces a false red with a misleading diagnosis: removing the pin's `println!` but keeping its assertions
  gives libtest `1 passed` and step exit 1 telling the author to "restore the assertions" — which are intact —
  and a legitimate `WebServerTlsEnableReader` variant rename would fire the same way, because the marker
  embeds the `Debug` spelling. Done-when: the marker and the diagnostics are keyed on something a variant
  rename does not move, or "no marker" and "no assertions" are reported apart.
  **Done (2026-10-01, at `785ac18a`, PR #444).** Each measured weakness now fails closed.
  (a) The resolver lane no longer takes a self-reported marker as proof of shape: the step pins the exact
  `-- --list` entry (`.github/workflows/ci.yml:517`
  `expected="service::tests::web_server_tls_enable_reader_answers_from_this_build"`, which `grep -E -c
  "^${expected}: test$"` must find exactly once), the marker is variant-free (`:521`
  `web-server-tls-enable-reader-pin: assertions ran`, matched with `grep -q -x -F`) and the step adds a
  converse run (`:538` `FRP_WARNING_PIN_SABOTAGE=1`) requiring the pinned test's own `FAILED` line
  (`:542-543`, diagnostic `:562`), so a renamed test plus a same-named stub that only prints the marker
  now reds with `lists 2 tests … expects 1` instead of passing. (b) Both count guards require the run's own
  `N passed; 0 failed` summary to equal the `-- --list` count (`n_run` at `.github/workflows/ci.yml:655`
  for the server step and `:720` for the web-server step; honest echoes `:695`/`:759`), so a listed test
  that silently does not run reds the lane. The deleted-assertion and early-`return` shapes are **not**
  caught by that equality — both leave the summary at `N passed; 0 failed` — but by each step's own
  converse run (`.github/workflows/ci.yml:668-670`/`:732-735`, `FAILED` check `:672-673`/`:736-737`,
  diagnostic `:690`/`:754`), which is the mechanism the lane really relies on; the count equality is a
  redundant second witness for the shapes it can see. (c) The removal diagnostics are keyed on the
  sabotage marker (`:544`/`:546`, predicate `:572`): a stripped `println!` now reports "restore the
  println!; the assertions are intact" (`:578`) rather than "restore the assertions", and the honest-split
  branch is gated so the `hookonly_before` case emits the status header plus exactly one cause message —
  the marker-before-assertion `elif` at `:567` — never the contradicting pair. The 19-row mutant matrix is
  the PR body's own table (each row reverted with `git reset --hard`; the round-2 verification's "13
  scenarios" is that round's smaller matrix). The declared residue is unchanged — the converse run is
  black-box, so a body that deletes the pinned assertion and adds another hook-gated failure
  (`stub_plus_panic`), or replaces it with one that keeps the same sabotage sensitivity (`weak_assert`),
  stays green. Three review notes are recorded rather than changed: the honest-split predicate (`:572`)
  tests `sabotage_marker = 0` and not `named = 1`, so a deleted pin also collects one extra "restore the
  assertions" message (r3 verification F2), and the r3 adversarial's two INFO notes
  (`/private/tmp/rev8069-attack-r3.md`) stand as filed.

- [x] **`--allow-unsafe`'s comma grammar still differs from pflag's CSV reader, and the ignored-flag twin splits nothing at all.**
  The read-path parser splits on `,` and trims each element (`frp-core/src/cli.rs:2637-2646`, inside
  `allow_unsafe_parser` at `:2632`), while Go's pflag parses a repeated string flag with
  `encoding/csv` (leading-space trimming off). Two spellings therefore diverge, measured at
  `a26a5f76` against Go v0.71.0 with an `auth.tokenSource` exec config
  (`frpc verify -c exec.toml --allow-unsafe <value>`): `'"TokenSourceExec"'` → frp-rs rc **1** /
  Go rc **0** (the quotes are CSV syntax to Go and literal bytes here); `'A, TokenSourceExec'` →
  frp-rs rc **0** / Go rc **1** (the space is significant to Go and trimmed here). The agreeing rows:
  `TokenSourceExec` 0/0, `Ignored,TokenSourceExec` 0/0, no flag 1/1. Inherited from the pre-existing
  `.split(',')` reading, not introduced by the repeated-flag fix. The un-read twin
  `ignored_allow_unsafe()` (`frp-core/src/cli.rs:2656-2661`) has `.many()` but no comma-split at
  all, so on the reload/status/stop surfaces a comma form that Go accepts as several features is one
  opaque value here. Its doc comment at `:2650-2652` claims only that repeats append and that the
  value is dropped (`Same spellings … repeats append; the value is dropped here either way`), which
  is true; the missing split is unobservable on those surfaces because
  `ignored_admin_root_flags()` discards the vector.

  Done-when: the flag's value grammar matches pflag's CSV reader for quoted and space-padded
  elements and the un-read twin splits the same way (or both divergences are documented as
  deliberate with these measured rows), and a test pins each row.

  **Done (2026-10-01, at code head `67f67e1b` on `fix/allow-unsafe-grammar`, PR #429).** The value is
  now parsed with pflag's CSV reader: `split_allow_unsafe_csv` (`frp-core/src/cli.rs:2665`) feeds the
  hand-rolled `read_csv_record` (`:2678`), `normalize_csv_input` (`:2799`) and `csv_error` (`:2864`),
  so quotes are CSV syntax, `""` escapes a quote, leading spaces/tabs are significant, repeated flags
  append, and the ignored-flag twin parses the same record instead of one opaque value. Every row of
  this item's table reproduces against Go v0.71.0: the round-1 adversarial review's 3209-value corpus
  carried 1353 mismatches at the base `55fff6e5` and matched 3209/3209 after the fix, and the widened
  round-2 adversarial corpus matched 5455 values (corpus + targeted
  multibyte/multiline/CRLF/NUL/70 kB + long lines) with 0 text/byte-column/line divergences plus a
  165-row CLI differential over `frpc verify` / `frps verify` / plain `-c` with 0 rc and 0 reason
  divergences. Two base-side divergences closed on the way: `--allow-unsafe="TokenSourceExec"` and a
  CRLF/NL junk tail are now rc 0 like Go (base rc 1). The round-1 review's F1 regression (a leading
  blank line — `$'\nTokenSourceExec'` — was refused where Go and the parent accept it, rc 3 on the run
  path) is fixed, and a blank-only value now reports Go's
  `invalid argument "…" for "--allow-unsafe" flag: EOF` instead of failing later at the semantic gate
  (F4). Error positions now match Go's 1-based **byte** columns and its multi-line
  `record on line N; parse error on line L, column C` shape (F2/F3), and the doc block above
  `split_allow_unsafe_csv` no longer misstates the contract (F5; the round-3 comment delta then
  corrected the measured rc cells of its table, which is why the table now says the bare
  `"a""b"`/`"a,b"`/`a,,b` forms exit 1 on the feature gate). Pins:
  `allow_unsafe_appends_and_comma_splits_on_every_reading_surface` (`:5472`),
  `allow_unsafe_reads_pflags_csv_record_on_both_parsers` (`:5697`),
  `allow_unsafe_csv_corners_are_go_shaped_and_never_trimmed` (`:5736`),
  `allow_unsafe_skips_blank_lines_like_go_and_blank_only_is_an_eof_flag_error` (`:5815`) and
  `allow_unsafe_error_positions_are_go_lines_and_byte_columns` (`:5886`). Mutants killed: the author's
  round-1 M1–M6 and round-2 N1–N11 ("the occurrence list is unbounded — a cap of at most 40
  occurrences drops the trailing enabling value" among them), and the reviewers' own batteries (the
  round-1 M1o/M1e/M2/M3 set, the round-2 M-col/M-line/M-rune/M-skip/M-EOF set that killed the
  round-1 `M-col` survivor, and the three from the round-2 verification) — matrices in
  `/tmp/author429-round2.md:195-207` (the author's N1–N11), `/private/tmp/rev429-verify.md`,
  `/private/tmp/rev429r2-attack.md:48-56` and `/private/tmp/rev429r2-verify.md` §5 (the round-2
  verification's three), every restore sha256-verified. Reviews: round-1 verification
  MERGE-with-findings (F1–F5 fixed here, F6 a body nit), round-2 adversarial CONFIRM at `7d806af8`
  (F1–F3 closed), round-2 verification MERGE-with-findings (F7 the rc cells → fixed in `67f67e1b`,
  F8 body staleness → fixed in the PR), and a round-3 comment-delta verification MERGE on
  `7d806af8..67f67e1b` (its only finding, a pin-line bookkeeping nit, is folded into these cites).

- [x] **The `--allow-unsafe` accumulation pins cannot see a duplicated value, a cap at 32, or a shrinking lane, and the two lane literals are equality guards rather than floors.**
  Filed by the coordinator from the round-3 adversarial review of the `--allow-unsafe` gate fix
  (`frp-core/src/cli.rs:5188` `allow_unsafe_appends_and_comma_splits_on_every_reading_surface`,
  `frps/tests/cli_exit_codes.rs:295`, `frpc/tests/cli_exit_codes.rs:651`).
  (a) Every repeated value in the pins is distinct (`frp-core/src/cli.rs:5175` uses `"a"`/`"b"`,
  `frpc/tests/cli_persistent_flags.rs:384-387` likewise), so a parser that de-duplicates or
  collapses equal repeats keeps the unit test and both spawn pins green: "appends like pflag" is
  pinned for distinct values only.
  (b) "No cap" rests on the single wide row that builds 32 occurrences. Measured: `v.truncate(32)`
  leaves the whole `frp-core` lib suite green (`997 passed; 0 failed`) and both spawn rows use at
  most four occurrences, so any cap ≥ 5 is invisible to them; loosening that one assertion to
  `>= wide_n - 1` also passes everything.
  (c) `FRPS_CLI_TESTS` / `FRPC_TINY_CLI_TESTS` (`.github/workflows/ci.yml:243` / `:315`, both in the
  `tests-unit` job) compare the file's test count to the literal for equality
  (`[ "$n" = "$FRPS_CLI_TESTS" ]`, `:567`), so deleting a test and lowering the literal together
  passes by construction, and the full `frpc` lane — the step at `.github/workflows/ci.yml:443`
  running `cargo test -p frpc` at `:494` — has no count guard at all.
  Done-when: a pin repeats one identical value and asserts both copies survive; the unbounded class
  is pinned past any plausible cap (or the assertion states the bound it really enforces); and each
  lane literal gets an absolute floor (or the full `frpc` lane gets a count guard), with the
  delete-plus-lower mutant red.

  **Done (2026-10-01, at code head `67f67e1b` on `fix/allow-unsafe-grammar`, PR #429) for (a) and
  (b); (c) is filed as its own item below.**
  (a) `allow_unsafe_appends_and_comma_splits_on_every_reading_surface` (`frp-core/src/cli.rs:5472`)
  now feeds one identical value twice and asserts both copies survive
  (`an identical value repeated must be kept twice, not de-duplicated`, `:5641`; `the ignored twin
  de-duplicates nothing either`, `:5647`), so a de-duplicating or equal-collapsing parser reddens a
  pin. (b) The same test builds 40 occurrences (`let wide_n: usize = 40;`, `:5655`) and 40 CSV
  elements inside one occurrence, so a cap at either site (`v.truncate(32)` on the accumulated vector,
  `split(',').take(32)` in the reader) is dead — both cap-32 mutants were measured and killed. The
  assertions still state the bound they enforce (`wide_n` is interpolated into the failure message),
  so a future narrowing of the pin cannot silently become an exact-equality check. (c) is untouched
  here and moved to the item below.

- [ ] **The CLI-lane count guards in `.github/workflows/ci.yml` compare for equality, so a deleted test plus a lowered literal passes; the full `frpc` lane has no count guard at all.**
  Filed by the coordinator when closing the `--allow-unsafe` accumulation item (its clause (c)).
  `FRPS_CLI_TESTS` (`.github/workflows/ci.yml:243`) and `FRPC_TINY_CLI_TESTS` (`:315`) hold the lane's
  expected test count and are compared for **equality** (`[ "$n" = "$FRPS_CLI_TESTS" ]`, `:567`) in
  the `tests-unit` job (`.github/workflows/ci.yml:136`), so deleting a test and lowering the literal
  together passes by construction — the guard checks self-consistency only, never an absolute floor —
  and the full `frpc` lane (the step at `:443`, `run: cargo test -p frpc` at `:494`) has no count
  guard at all.
  **Done-when:** every guarded lane asserts an absolute **floor** (or keeps the exact count alongside
  a floor) so a removal fails without a deliberate records bump, and the full `frpc` lane gets a
  guard; the delete-plus-lower mutant must red. Note for whoever takes it: this edits
  `.github/workflows/ci.yml` in two places — the count literals in the `tests-unit` job (`:136`) and the
  compat-stray-guard literals in the `health` job (`:97`) — so it should land after PRs #424/#430, which
  also touch that file, to avoid a literal conflict.

- [ ] **Rust frpc runs the `auth.tokenSource` `exec` command twice per successful login where Go runs it once.**
  Filed by the coordinator from the round-2 adversarial review of PR #429, which measured it and
  confirmed it predates that change: with an exec token source whose command has an observable side
  effect, `frpc -c exec.toml --allow-unsafe TokenSourceExec` against a live frps runs the command
  twice on both the base `ea991757` (log `base\nbase\n`) and the reviewed head `67f67e1b`
  (`head\nhead\n`), while Go v0.71.0 runs it once (`go\n`). The exec path lives in `frp-client`, which
  #429 does not touch, so this is pre-existing and unrelated to the flag grammar. Source report:
  `/private/tmp/rev429r2-attack.md`.
  **Done-when:** the token-source read path executes the command once per login like Go, pinned by a
  test that counts executions across a login (and, if the reload path re-reads the source, that path
  is counted too), or the double read is documented as deliberate with the measured rows and the
  reason it cannot be de-duplicated.
- [ ] **`scripts/compat-test.sh`'s XTCP helper still kills by argument pattern — the class of kill the compat-leak item forbade for its own children.**
  Filed by the coordinator while closing the "`scripts/compat-test.sh` leaks its children" item above.
  Inside `run_xtcp_test` (`scripts/compat-test.sh:4331`), the pre-test cleanup is
  `pkill -f "frpc -c"` / `pkill -f "frps -c"` (`:4343-4344`, under the comment at `:4340-4342`), i.e.
  a kill over *any* process on the host whose command line matches that pattern — including a
  developer's unrelated `frpc -c …` run — whereas the guard the closed item added matches a process
  name **and** the run's own `$TEST_DIR/` prefix, subtracts a baseline, and reaps by exact pid. The
  repository's stray rules say "never by name alone"; name-plus-argument is the same hazard in a
  weaker form.
  **Done-when:** replace the two `pkill -f` calls with the pid-exact sweep the closed item added
  (`scenario_strays`/`assert_no_strays` at `scripts/lib/compat-stray-guard.sh:90`/`:150`, or a per-scenario pid
  file), so a full XTCP run leaves no process it did not start, or record why the pattern kill is
  required there (e.g. a `fuser`/pid-file route is impossible for that shard's Go children).
- [x] **`frpc/tests/warn_delivery.rs` snapshots its counts after a fixed 500 ms settle — the same class of load-dependent wait `frps/tests/log_completion.rs` just lost.**
  Filed by the coordinator while closing the `log_completion` flake item above, correcting that
  close-out's own residual note. This file does **not** read a rotation file — its contract
  (`frpc/tests/warn_delivery.rs:52-57`) is the child's two captured streams — so the closed item's
  appender-record gate does not apply. What it shares is a fixed sleep: `wait_for_marker` (`:219`)
  returns as soon as `STARTUP_MARKER` appears on stdout/stderr, then `SETTLE = 500 ms` (`:92-94`) is
  slept at `:214` before `snapshot()` freezes the buffers, and the tests then assert exact
  per-stream record counts. On a host loaded like the one that produced the sibling item's 2/10
  failure rate (load average 39–41), a record the logger gates can still be in flight at the
  snapshot.
  **Done-when:** reproduce a failure under that recipe — 10 sequential
  `cargo test -p frpc --features full --test warn_delivery` (the file is
  `#![cfg(feature = "full")]`) at load 39–41 — and replace the settle with a condition wait on the
  record itself, or record the non-reproduction with the recipe and the load figures (8 tests in the
  file).
  **Done (PR #432, code head `df78c203`).** The fixed sleep is gone: `QUIET_PERIOD` (500 ms,
  `frpc/tests/warn_delivery.rs:110`) plus a bounded `wait_for_record` (`:270`, `RECORD_TIMEOUT = 10 s` at
  `:101`) returns only once `count >= want` **and** the capture has been quiet for `QUIET_PERIOD` (`:281`),
  so the count is final before `snapshot()` (`:354`) freezes it (no fallback to the live buffers). Teeth:
  a second `--config-dir` emit 150 ms behind the first (`frpc/src/main.rs:545`) leaves the pre-fix file
  `ok. 8 passed` and reds the fixed one `FAILED. 6 passed; 2 failed` at `frpc/tests/warn_delivery.rs:448:5`
  (`left: 2`, the two records 152 ms apart; the 0 ms variant also reds), while the honest lane is
  `ok. 8 passed` in 2.59 s — the condition wait costs ~500 ms per `Warning` row. Load: 10/10 sequential
  `cargo test -p frpc --features full --test warn_delivery` runs green at load 28.0-34.0; the item's 39-41
  recipe was not reachable during the window. Residue: `frpc/tests/admin_config_get_warning.rs:98` keeps
  its own `SETTLE = 500 ms` (used once at `:504`) because its legacy `records() == 0` assertions need a
  negative guarantee a positive condition-wait cannot express.

- [x] **The `frpc/tests/warn_delivery.rs` condition wait is a quiet window, not a finality guarantee: a duplicate emitted more than one `QUIET_PERIOD` behind the first is a false pass.**
  Filed by the coordinator from PR #432's round-2 delta adversarial, which re-ran the closed item's own teeth with
  the delay moved: a second `--config-dir` emit 150 ms behind the first (`frpc/src/main.rs:545`) reds the pin
  (`frpc/tests/warn_delivery.rs:448:5`, `left: 2`), but the same mutant at **700 ms** — past `QUIET_PERIOD`
  (500 ms, `:110`) — leaves `ok. 8 passed`. `wait_for_record` (`:270`) returns once `count >= want` **and** the
  capture has been quiet for `QUIET_PERIOD` (`:281`), so an emit that lands after the last quiet window closes and
  before `snapshot()` (`:354`) freezes the capture is invisible: the pin's detection power is bounded by how long
  the mutant delays, not by the child's own exit.
  **Done-when:** the count is final without picking a window (e.g. assert the captured records against the child's
  exit status and its own emitted-record count), or the bound is stated next to `wait_for_record` and a witness
  shows a duplicate inside the window is caught while one outside it is recorded as undetectable.

  **Done (PR #441, code head `f7319c3c`).** The bound is gone rather than documented: the oracle is now the
  child's own exit. `Spawned::run` waits for the child to exit and then joins both pipe-drain threads, so the
  capture is at EOF before anything asserts on it, and `QUIET_PERIOD`, `wait_for_record` and the live-buffer
  fallback are deleted; the one read-error direction is disclosed at `frpc/tests/warn_delivery.rs:83` (`drain`'s
  `Ok(0) | Err(_) => break` at `:355`). Teeth re-measured in all three review rounds: the duplicate
  `--config-dir` emit at **+700 ms** — the delay that left the pre-fix pin printing `ok. 8 passed` — now reds at
  `frpc/tests/warn_delivery.rs:407:5` (`left: 2`), the +150 ms and 0 ms variants red with it, and the honest
  lane is `ok. 8 passed`. The round-2 adversarial could not construct a false negative for the new oracle: its
  strongest shape, a duplicate 700 ms behind a 512 KB stdout burst, reds with all 1536 padding lines drained to
  EOF (no truncation, no deadlock).

- [ ] **`frpc/tests/warn_delivery.rs`'s drain treats any read error as EOF, so a transport error can end a wait early.**
  Filed by the coordinator from PR #441's rounds 1-3. `drain`'s read loop breaks on `Ok(0) | Err(_)`
  (`frpc/tests/warn_delivery.rs:355`, disclosed in the module doc at `:83`), so a pipe that errors instead of
  reaching EOF makes the joined capture look final. For a count row that fails safe (fewer records than the
  child emitted reds the pin), but for a silence row ("nothing on this stream") it can hide a record that was
  never read.
  **Done-when:** an `Err` other than `ErrorKind::Interrupted` is distinguished from EOF and asserted absent (or
  the join reports it), or the fail-safe direction is argued for both row kinds.

- [x] **`frpc/tests/cli_inputs.rs`'s `a_config_file_named_after_a_subcommand_stays_a_config_file` fails whenever the `admin` feature is on, so `cargo test -p frpc --features full,admin` is red for a reason no CI lane runs.**
  Filed by the coordinator from PR #432's round-2 delta adversarial while correcting that batch's lane quote.
  Measured at the branch head: `cargo test -p frpc --features full,admin --test cli_inputs` → `33 passed; 1 failed`,
  panicking at `frpc/tests/cli_inputs.rs:1485:9` because the config's `[webServer]` port appears in the child's
  output — with `admin` on, frpc's run path logs `frpc admin server starting on 127.0.0.1:<port>`, which the
  assertion `!text.contains(&port.to_string())` reads as "reached the config's admin port". The failure is not
  reachable from #432's diff (`frpc` does not depend on `frp-server`, and `frpc/tests/cli_inputs.rs` is byte-identical
  to `9b2acefb`), but no lane runs `-p frpc` with both features, so it stays invisible.
  **Done-when:** the assertion distinguishes the admin startup line from a dial (or the test is gated to the feature
  combinations a lane actually runs), and a lane runs `cargo test -p frpc --features full,admin`.

  **Done (PR #441, code head `f7319c3c`).** The assertion that could not tell a dial from the child's own
  listener is deleted, with its reasoning recorded in place (`frpc/tests/cli_inputs.rs:1485-1495`, naming
  `frpc admin server starting on 127.0.0.1:<port>` from `frp-client/src/service.rs:4414`), and the claim it
  meant to make is carried where it is observable: `!text.contains("Proxy Status") && !text.contains("NAME  TYPE")`
  (`:1498` — a `status` run that reached the mock prints exactly those headers) plus the mock staying silent
  after the loop (`:1506`, `rx.try_recv().is_err()`). Measured: restoring the base's
  `!text.contains(&port.to_string())` reds at `frpc/tests/cli_inputs.rs:1485:9` (the original failure), the head
  is 34/34, and `--features admin` and `--features full,admin` list the same 34 names. The lane half of the
  done-when shipped **scoped**: `Run frpc's CLI-input tests with the admin feature`
  (`.github/workflows/ci.yml:1124`) runs `cargo test -p frpc --features admin --test cli_inputs`
  (`:1124`-`1194`) behind a fail-closed count guard (`FRPC_ADMIN_CLI_INPUTS_TESTS: "34"` at `:363`; zero and
  non-numeric values rejected at `:1169`; the `--list` count and `test result: ok. 34 passed; 0 failed` both
  checked at `:1180-1181`; the honest lane prints `frpc admin CLI-input guard ok: 34 tests listed (expected 34),
  0 failed` at `:1194`). The package-wide `cargo test -p frpc --features full,admin` literal in this done-when
  was **rejected**, with the exposure it would have covered stated in the step's own comment (`:1133`-`1152`):
  `frpc/tests/admin_cli.rs` is `#![cfg(feature = "full")]` (`frpc/tests/admin_cli.rs:50`), so `admin` never
  selected a different set of its 25 tests — it only changes which `frp-client` features they compile against —
  and the whole-package run would re-run 77 tests the steps above already execute in this job while doubling its
  exposure to the `api_timeout_before_the_subcommand_reaches_the_command` flake (1322 ms measured against its
  5 s bound).

- [ ] **`scripts/tests/repo-health-fixtures.sh` cannot detect its own neutering — the hole the compat guard's `MIN_CHECKS` just closed.**
  Filed by the coordinator from the `test-harness-strays` round-2 adversarial round (read at
  `506f9465`). The suite ends with a bare `exit "$fail"` (`scripts/tests/repo-health-fixtures.sh:371`)
  and keeps no total-count floor, so a regression that stops the scenarios from running still reports
  green in the `health` job. The measured shapes (round-2 adversarial, on copies): an early `exit 0`
  after the `RC_PY` preflight (`:78`) exits 0 with **no output at all**, so no `RESULT:` line exists;
  a scenario body emptied still exits 0, printing `RESULT: 17 fixture check(s) hold` for scenario 4
  (18 for scenario 1); only a suite that runs no check at all prints `RESULT: 0`. The guard suite added by the same
  branch now pins the invariant from a trap installed before its first assertion
  (`MIN_CHECKS=21`, `scripts/tests/compat-stray-guard.sh:72`, checked at `:90-94` with the message
  `suite exited 0 after only N check(s); expected at least 21 — scenarios did not run`) — and the
  round-2 re-check showed that floor is itself bypassable from inside the file (`exec true` skips the
  EXIT trap; `MIN_CHECKS=0` disables it), which is why the hardening round moves the assertion outside
  the file, into the `Stray guard — fixture checks (compat harness teardown)` step
  (`.github/workflows/ci.yml:111`) whose `grep -qF 'RESULT: 21 fixture check(s) hold'` sits at `:127`.
  **Done-when:** `scripts/tests/repo-health-fixtures.sh` enforces its own floor the same way (trap
  installed before the first `ok`/`bad`, the floor equal to the current check count), and emptying a
  scenario body — or inserting an early `exit 0` — reds the suite.

- [ ] **Four more `scripts/tests/compat-stray-guard.sh` residues the delta-3 reviews measured — each is a way the guard can report green while doing less.**
  Filed by the coordinator from the `test-harness-strays` delta-3 round (R1 and R2 both read
  `0a350583`; R1 measured the trait at `scripts/tests/compat-stray-guard.sh:79-86`, R2 at `:86`,
  `:44-60` and `:141`). (a) The trap's own ownership probe treats "`ps` could not run" as "this pid is
  not ours": `cmd=$(ps -o command= -p "$p" 2>/dev/null) || continue` (`:86`), so every LIVE synthetic
  outlives a `ps` failure; R2's fix is
  `cmd=$(ps -o command= -p "$p" 2>/dev/null) || { kill -9 "$p" 2>/dev/null || true; continue; }`.
  (b) `wait_exec`'s "has the child exec-ed yet" test is defeated when the suite is invoked through a
  symlink — the script resolves itself through symlinks (`:44-60`) while the child's pre-exec argv
  carries the `$0` alias, so the match succeeds before the exec and `wait_exec` returns 0; CI calls the
  direct path, so it is latent. (c) A `ps` that exits 0 with empty output is read as "the image
  changed" (`:141`). (d) `MIN_CHECKS=21` is a total, not a shape: deleting four checks and adding four
  dummy `ok` lines keeps the count and exits 0. R2's two remaining notes are accepted as bounded rather
  than fixed: the fixed `/tmp` log path is defended only by `tee` truncation, and a SIGKILL leaves an
  orphan bounded by the 300 s pre-`exec` sleep.
  **Done-when:** (a) uses the kill-then-continue form or the leak is proven unreachable; (b), (c) and
  (d) are each fixed or recorded as deliberate with the mutant that shows the gap — for (d) that means
  the guard's total is replaced by, or supplemented with, a per-scenario shape assertion.

- [x] **A non-regular file named `*.{toml,ini,json,yaml,yml}` inside a `--config-dir` hangs the lane forever.**
  Filed by the #426 round-3 adversarial review while closing the `--config-dir` batch. `collect_config_files`
  admits any directory entry whose name carries a config extension without checking that it is a regular file
  (`frp-core/src/config/file.rs:414-461`), and the read that follows blocks (`frp-core/src/config/normalize.rs:598`
  `std::fs::read_to_string`, in `load_config_from_file` — `frp-core/src/config/file.rs:303`
  is the *include* read in `process_includes`, a different path), so `mkfifo zz.ini` in the directory hangs the process with no output and no
  timeout, before any service exists. Measured: Go `frpc` hangs identically on the same directory (killed after
  15 s, FIFO first and FIFO last), and Go `frps` has no `--config-dir` at all (`Error: unknown flag:
  --config-dir`, rc 1), so a regular-file guard in the shared collector would *diverge* from Go. No guard is
  added: the parity is deliberate.
  **Done-when:** the collector skips non-regular entries (with the Go-parity note removed or re-argued against a
  fresh Go probe) or the lane bounds the read with a timeout, in either case with a test that pins the new
  behaviour.

  **Done (2026-10-01, at `aeb9737a` on `fix/configdir-residues`, PR #431).** The collector's extension-only admission is parity-bound, not a bug to fix: re-probed against Go frp v0.71.0, a FIFO named `*.toml` hangs **both** `frpc --config-dir` implementations unbounded (Go: still running after 5 s with a valid config present, killed `-9`; frp-rs: same), and Go `frps` has no `--config-dir` at all (`Error: unknown flag: --config-dir`, rc 1) — so a regular-file guard in the shared collector would *diverge*.`frp-core/src/config/file.rs:432` (`collect_config_files_inner`, the extension match `:449-458`, the push `:460`) is therefore unchanged; the `is_file()` checks live only in `simple_glob` (`:340`/`:363`), and the blocking read is `std::fs::read_to_string` at `frp-core/src/config/normalize.rs:598` (in `load_config_from_file`; the body's `:198` and this paragraph's earlier `file.rs:303` both named the *include* read — corrected, twice). Pinned by `frp-core/src/config/tests.rs:3711` `test_collect_config_files_admits_a_non_regular_entry_by_extension` (an `if !path.is_file() { continue; }` guard reds it at `frp-core/src/config/tests.rs:3758`) and `frps/tests/cli_exit_codes.rs:1318` `config_dir_fifo_entry_wedges_the_lane_and_a_repeat_signal_ends_it`, which also pins the availability bound this round added: on a wedged lane the first `SIGTERM` is *recorded* instead of lost and a repeat request forces rc 143 with `SIGTERM requested again with no service registered to stop it; forcing exit 143` (pre-fix, the very first `SIGTERM` killed frps rc 143), so a **FIFO-only** lane is no longer unkillable-except-`SIGKILL`. The bound is not general: `EarlyShutdown.states` is append-only, so `states.is_empty()` means "no service *ever* registered", and a *mixed* directory (one valid config plus a FIFO) still survives repeated `SIGTERM` on both this head and the base and needs `SIGKILL` (rc 137) — measured by the round-2 adversarial review, and deliberately not pinned this round.
- [x] **A `SIGTERM` that lands before `frps --config-dir` installs the per-service handler kills the process by signal (rc -15).**
  Filed by the #426 round-3 adversarial review as an accepted bound. The main task installs SIGUSR1
  (`frps/src/main.rs:295`), while SIGTERM is installed per service inside `Service::run`
  (`frp-server/src/service.rs:1855-1868`: `ctrl_c()` alone catches only SIGINT, so the unix handler is
  registered there); a signal landing between the startup line and that registration takes the default
  disposition. Measured window: **~0.16 ms median / 1.10 ms max**, occasionally open (1/40 in one probe, not
  reproduced in a follow-up 30-run loop) — documented in the helper's own doc comment
  (`frps/tests/cli_exit_codes.rs:595-604`). Installing an early handler would convert the race into a *lost*
  SIGTERM, which is worse, so no fix and no flaky pin is added.
  **Done-when:** the main task owns the shutdown handler before any service is spawned (so the signal is
  recorded rather than lost) and a pin drives the window deterministically instead of racing it.

  **Done (2026-10-01, at `aeb9737a` on `fix/configdir-residues`, PR #431).** The main task now owns the shutdown handler before any service is spawned: `EarlyShutdown` (`frps/src/main.rs:123`, `impl` `:140`) is installed at `frps/src/main.rs:526`, before the config-dir startup line, records a `SIGTERM`/`SIGINT` that arrives inside the window, and hands it to each service at registration (`frps/src/main.rs:674` `if early_shutdown.watch(service.state())`), cancelling the token and logging `shutdown signal was recorded before this service installed its own handler`; the main loop's idle arm wakes on `early_shutdown.recorded()` (`:647`/`:713`). The window is driven deterministically instead of raced: the debug-only `FRPS_CFGDIR_TEST_REGISTRATION_DELAY_MS` hold now also wakes on `recorded()`, and `frps/tests/cli_exit_codes.rs:1098` `config_dir_sigterm_inside_the_registration_window_exits_0_through_the_recorded_request` holds `30 000 ms`, sends `SIGTERM` after the startup line, and asserts exit `Some(0)` plus the recorded-signal log line and `Accept loop stopped for graceful shutdown` — the log assertion is what proves the exit came from the recorded path and not from the race won the other way. Mutants: `install()`'s `SIGTERM` arm replaced by `std::future::pending()`, and the `watch()` handoff deleted, each red that pin (`did not exit within 10s of a SIGTERM sent inside the pre-registration window`). The `-c` arm of the Done-when stays open on purpose: that lane has no delay hook, so a fix there could not be pinned deterministically.
- [x] **The `frps` bin-unit guard's completion marker is self-referential: a body that prints it and returns passes with zero assertions.**
  Filed by the #426 round-5 adversarial review. The CI step now checks both the `-- --list` test name and the
  `dir-registry-pin: ok, recovered 3 entries` marker (`frps/src/main.rs:1217`), which catches a renamed or
  deleted test and a bare early `return;` — but a body beginning
  `println!("dir-registry-pin: ok, recovered 3 entries"); return;` still exits the step 0 with
  `ok. 1 passed; 0 failed` and no assertion executed. Every realistic mutant reds, and libtest exposes no
  per-assertion counter, so the residual is bounded rather than fixed.
  **Done-when:** the step asserts something the test body cannot emit without running (an assertion count from a
  custom harness) or the pin moves to a lane where the process exit code itself is the contract.

  **Done (2026-10-01, at `aeb9737a` on `fix/configdir-residues`, PR #431).** The contract is now the process exit code, not a marker the body can emit without asserting: a `#[cfg(debug_assertions)]` hook (`frps/src/main.rs:56`, `FRPS_DIR_REGISTRY_TEST_DISCARD`) makes `lock_dir_registry` recovery return an **emptied** registry, and the `Run frps bin unit tests` CI step (`.github/workflows/ci.yml:374`, `:404`) runs the pin a second time with the hook set and requires that run to FAIL — `test result: FAILED`, the pin named FAILED, marker absent (`ci.yml:429`). Measured on the extracted step: healthy exit 0 (`frps bin unit-test guard ok: 1 tests listed …, marker seen, 0 failed, sabotage reds it`), exit 1 with the hook renamed so it never fires, exit 1 with the pin body reduced to `println!("dir-registry-pin: ok, recovered 3 entries"); return;`. The stale half of the finding was re-measured first: the production mutant (`poisoned.into_inner()` recovered then `clear()`) already reds the pin's own assertions (`left: 0, right: 3`), because the fixture seeds three distinctly-named services and asserts length, order, `Arc::ptr_eq` per entry and the recovery log line.
- [x] **The `frpc --config-dir` SIGTERM pins assert `Some(0)` where Go's plain tcp client dies by signal (rc 143).**
  Filed by the #426 round-4 and round-5 adversarial reviews as inherited from the `-c` lane. Go installs a
  shutdown handler only for the kcp/quic transports (`cmd/frpc/sub/root.go:207-210`), so a tcp client killed by
  SIGTERM exits by signal (`ExitStatus::code() == None`, shell rc 143), while the frp-rs config-dir pins assert
  `Some(0)`.
  **Done-when:** the pins assert what each side actually does (Go's signal death vs frp-rs's graceful 0) or the
  divergence is recorded where the lane's exit contract is documented.

  **Done (2026-10-01, at `aeb9737a` on `fix/configdir-residues`, PR #431) — recorded, not fixed.** Both sides are recorded as they actually behave. Go's frpc installs a shutdown handler for the kcp/quic transports only (`cmd/frpc/sub/root.go:207-210` skips the SIGTERM/SIGINT registration for plain tcp), so a tcp client killed by `SIGTERM` dies by signal — measured on the real binary (v0.71.0, darwin/arm64): rc **143** / `ExitStatus::code() == None`, for both `--config-dir` and `-c` — while frp-rs drains every service and exits `Some(0)`. frp-rs's behaviour is the better one and Go's own `frps` does not offer the flag, so the pins deliberately keep asserting `Some(0)`; the Go measurement is named in the assertion message and the divergence is documented next to the handler that produces it in `frpc/src/main.rs:442-465`, ending `Do not "fix" the pins to Go's signal death.` Ledger after this batch: **24 open / 153 closed**
  (base `9b2acefb`: 26 open / 149 closed; the batch closes the four `--config-dir` residues and the two new
  residues the delta reviews measured are filed below).

- [x] **The release-profile test lane is red wherever it is run — three `frps/tests/cli_exit_codes.rs` pins drive `#[cfg(debug_assertions)]` hooks, and no CI job runs tests in release.**
  Filed by the coordinator from PR #431's delta adversarial. `cargo test --release -p frps --test
  cli_exit_codes` is 41 passed / 3 failed at `frps/tests/cli_exit_codes.rs:1122:5`, `:1226:13` and `:145:17`,
  byte-identically at the parent `89826daf` — not a regression, but the reason the project has no release-mode pin
  coverage. The three failures are the pins that drive the debug-only holds (`FRPS_CFGDIR_TEST_REGISTRATION_DELAY_MS`
  at `frps/src/main.rs:620`, `FRPS_CFGDIR_TEST_POST_REGISTRATION_DELAY_MS` at `:697`, `FRPS_CFGDIR_TEST_PANIC` at
  `:741`); `cargo test --release -p frps --bins` is green (`1 passed`,
  `dir_registry_tests::lock_dir_registry_recovers_a_poisoned_registry`).
  **Done-when:** either a CI job runs `cargo test --release -p frps --test cli_exit_codes` with the three pins
  skipped behind a stated reason (so the lane is honest about what it covers), or the pins become release-runnable.

  **Done (PR #443, code head `ec24f7a2`).** The three pins now carry
  `#[cfg_attr(not(debug_assertions), ignore = "<reason>")]` — `frps/tests/cli_exit_codes.rs:1107-1108`,
  `:1190-1191`, `:1597-1598`, each reason naming the hook it needs, with the rationale in the comments at
  `:1098`, `:1185`, `:1590`. `ignore` rather than `#[cfg(debug_assertions)]` is the load-bearing choice: a
  `#[cfg]` would remove the tests from the release count, so no guard could then assert that the release lane
  still lists the same 44 tests debug does. Measured: base release
  `test result: FAILED. 41 passed; 3 failed`, exit 101 at `frps/tests/cli_exit_codes.rs:1122:5`, `:1226:13`,
  `:145:17`; head release `test result: ok. 41 passed; 0 failed; 3 ignored` (2.79 s) and head debug
  `ok. 44 passed; 0 failed; 0 ignored`; `--list` 44 in both; no profile in the workspace sets
  `debug-assertions` (`Cargo.toml:105`, `:115-117`), so `not(debug_assertions)` is exactly the axis this lane
  covers, and a fat-LTO run gives the same numbers. A new additive job, `release-tests` / `Tests (release
  profile)` (`.github/workflows/ci.yml:1253-1345`, `timeout-minutes: 30` at `:1256`), runs
  `cargo test --release -p frps --test cli_exit_codes` in the same release profile the `build` job uses
  (`lto = false`, `opt-level = 2`, `:1290-1292`) and fails closed on four things: the target was really built,
  the summary is exactly `test result: ok. 41 passed; 0 failed; 3 ignored;`, the ignored **names** are the
  three pins in `FRPS_RELEASE_CLI_IGNORED` (both sides sorted), and `--list` equals
  `FRPS_RELEASE_CLI_TESTS` = 44 (`:1336-1342`, "Update both literals together"). Teeth, re-measured by both
  reviewers: 9 of 11 mutants caught — 41→40 drift, a stray fourth `ignored`, the target missing, 0 tests, an
  unconditional `#[ignore]` on a fourth pin, the pins `#[cfg]`'d out, a rename, the wrong test ignored with the
  count unchanged, an extra passing test; the summary substring is not end-anchored and the reasons are never
  read back, both accepted. What the lane does **not** defend is written down rather than implied
  (`ci.yml:1243-1248`): turning the three attributes into an unconditional `#[ignore]` gives byte-identical
  release output and this guard exits 0 by design, because that case belongs to the pre-existing debug lane
  (`FRPS_CLI_TESTS: "44"` at `:278`, asserted at `:747`). The job is deliberately absent from `build`'s
  `needs` (`ci.yml:1843`) so a cold release build cannot serialize the artifact job, which means it gates a
  merge only once branch protection names "Tests (release profile)" (`:1249-1252`). Cold release build: 5m07s
  at `-j 2`, 9m51s under load, inside the 30-minute cap.

- [ ] **Release-mode test coverage is this one file: no CI job builds or runs any other test target in the `release` profile.**
  Filed by the coordinator while closing the release-profile lane item above. `release-tests`
  (`.github/workflows/ci.yml:1253-1345`) compiles and runs `frps/tests/cli_exit_codes.rs` and nothing else, so
  every other test target — `frp-core`'s config and CLI suites, `frps/tests/warn_delivery.rs`, `frpc/tests/*` —
  is only ever built with `debug_assertions` on. Code a release binary compiles differently
  (`#[cfg(debug_assertions)]` hooks, `debug_assert!`, overflow checks) is therefore pinned in debug only, and
  the `build` job's release artifacts are built, never executed.
  **Done-when:** the workspace's `--release --all-targets` build plus at least one more release test target
  runs in CI with its own count guard, or the decision to cover exactly the pins that need it is recorded with
  the reasoning and the measurements.

- [x] **`frps/src/main.rs:332`'s re-pointed doc link names the wrong loader for the run path it describes.**
  Filed by the coordinator from PR #431's delta adversarial (F1). The link now resolves to
  `frp_core::config::load_server_config_uncompleted`, but the run path the sentence describes calls
  `load_server_config_uncompleted_with_presence` at `frps/src/main.rs:967`; the imprecision predates the link fix,
  which only qualified the path.
  **Done-when:** the sentence names the function the run path actually calls (or states the difference deliberately).

  **Done (2026-10-01, at `e4a313b5` on `fix/frps-doclink-loader`, PR #438).** The sentence at
  `frps/src/main.rs:332` now names `frp_core::config::load_server_config_uncompleted_with_presence`, the function
  the `-c` single-config run path calls at `frps/src/main.rs:967` (then the flag overlay at `:990` and
  `cfg.complete()` at `:993`), described as "the presence-carrying form of
  `load_server_config_uncompleted`, i.e. the completing loader minus `ServerConfig::complete`" — which is literally
  true: `frp-core/src/config/file.rs:18-25` is `:22 load_server_config_uncompleted(...)?` followed by
  `:23 cfg.complete();`, while `load_server_config_uncompleted_with_presence` (`file.rs:75`) returns
  `(cfg, presence)` after `load_config_from_file` plus the transport completion (`file.rs:79-88`), so the only
  config-side delta is `ServerConfig::complete()`. The map is complete for `frps/src/main.rs` (`verify` →
  `load_server_config_checked` `:375`; `--config-dir` → `load_server_config_with_presence` `:565`; `-c` run →
  `:967`); the fourth workspace site (`frp-server/src/service.rs:2331`, the SIGUSR1 reload) is outside the
  sentence's scope. Verified by both round-1 reviews: the diff is one comment sentence (`+5/−2`, no non-comment
  token changed), the link resolves and is resolution-sensitive (a typo'd target yields
  `warning: unresolved link to …` and rc 101 under `RUSTDOCFLAGS="-D rustdoc::broken_intra_doc_links"`), and
  `cargo fmt --all -- --check`, `clippy -p frps --all-targets -D warnings`, `cargo build -p frps` and
  `bash scripts/repo-health.sh` (`RESULT: invariants hold`) are green. The reviewers' remaining items are the
  same-class stale attributions outside this sentence (`frps/src/main.rs:960`, `docs/developing.md:1469`,
  `:1487`, `frps/tests/cli_completion.rs:508-510`) plus the standing note that no CI job runs `cargo doc`.
  Ledger after this close: **25 open / 161 closed** (base `6420d77a`: 26 open / 160 closed).

- [ ] **The RSS-soak fixture step has no outer pins.** The `health` job runs
  `bash scripts/tests/rss-soak-run-dir.sh` bare (`.github/workflows/ci.yml:135-136`), so a step whose
  script is replaced by `exit 0`, or whose checks are skipped, still passes; the `Stray guard` step
  above it wraps the same shape with a `RESULT:` literal and an error branch. Mirror that pattern.
  **Done-when:** the step asserts the script's `RESULT: 269 fixture check(s) hold` line in both
  directions (missing and failed) rather than only its exit code.

- [ ] **Stale "two fixture scripts" comment in the health job.** `.github/workflows/ci.yml:86-88`
  still says the job reads "files with grep/find only, plus two fixture scripts"; it now runs three
  (`scripts/tests/repo-health-fixtures.sh`, `scripts/tests/compat-stray-guard.sh`,
  `scripts/tests/rss-soak-run-dir.sh`).
  **Done-when:** the comment names the three.
- [x] **Legacy `.ini` spellings Go reads as a proxy (or ignores) and frp-rs does not: reserved-root `type`-only sections, portless shapes, and the server side.**
  Measured across the #425 rounds 3-7 against real Go frp v0.71.0 binaries in both loader modes;
  the full per-fixture matrices are in PR #425. Grouped by what a fix has to decide:
  * A section named exactly a reserved settings root carrying `type` but **no** port: `i4c.ini`
    (`[web_server] type = "tcp"`) makes Go register `new proxy [web_server] type [tcp]` (listen
    port 0) while frp-rs reports `Proxies: 0`. Keying the reserved-root bypass on `type` instead
    of the ports would also collect `[log] type = "custom" disable_print_color = true` as a proxy
    where Go is rc 1 `failed to parse proxy log, err: invalid type [custom]` and frp-rs rc 0, and
    would contradict `test_legacy_ini_known_section_with_type_not_collected`
    (`frp-core/src/config/tests.rs`), which pins that opposite verdict. Choosing between the two
    spellings is a decision about whether frp-rs keeps supporting v1 settings roots in `.ini` at
    all — a design question, not a parity patch.
  * Portless typeless section carrying `custom_domains` (`c2.ini`): strict Go rc 0 / frp-rs rc 1
    `unknown field "p"`; pre-existing and pinned by
    `typeless_ini_section_without_ports_stays_a_v1_section` (`frp-core/src/config/tests.rs`).
  * Server side (there is no server-side legacy collector): frps `[proxies.foo]` without a port
    key is strict rc 1 `unknown field "proxies.foo"` where Go is rc 0/0 (`s2.ini`), and
    `[http_plugins.foo]` / `[httpPlugins.foo]` is rc 1/1 `invalid type: map, expected a sequence`
    where Go is rc 0/0 (`i6a.ini`). The strict-only rows `s5`/`s6`/`s7`/`s9`/`sx7` and the
    `[proxies]`/`[visitors]`/`[foo]`/`[Includes]`/`[includes.foo]` unknown-field refusals are
    pre-existing and identical in a pristine build.
  * The reverse gap: frps `[plugin.user] ops = login` (`i6b.ini`) → Go rc 1 `invalid http plugin
    ops, optional values are [Login NewProxy CloseProxy Ping NewWorkConn NewUserConn]`, frp-rs
    rc 0; and `[feature.foo] x = true` (`i7.ini`) → frp-rs rc 1 `invalid type: map, expected a
    boolean`, Go rc 0.
  **Done-when:** each spelling is collected (or ignored, or refused) as Go does, or the divergence
  is recorded as deliberate in `docs/config.md` with its measurement, pinned in both loader modes.

  **Done (2026-10-01, at code head `40fd1f0b` on `fix/legacy-ini-residues`, PR #442) — recorded, not fixed.**
  Every spelling the item names is now measured and pinned in both loader modes instead of left to prose.
  `legacy_ini_reserved_root_type_only_section_is_not_collected_both_modes` (`frp-core/src/config/tests.rs:13911`)
  pins `[web_server] type = "tcp"` staying a v1 settings root here (`Proxies: 0`) where Go registers
  `new proxy [web_server] type [tcp]` with listen port 0; `legacy_ini_server_side_dotted_and_reserved_roots_stay_v1_both_modes`
  (`:13970`) pins the server-side rows (`[proxies.foo]`, `[http_plugins.foo]`, `[plugin.user]`,
  `[feature.foo]`) with their per-mode verdicts, alongside the pre-existing
  `typeless_ini_section_without_ports_stays_a_v1_section`. Keying the reserved-root bypass on `type`
  instead of the ports stays rejected: it would also collect `[log] type = "custom"` (Go rc 1 `failed to
  parse proxy log, err: invalid type [custom]`) and contradict the opposite verdict pinned at
  `test_legacy_ini_known_section_with_type_not_collected` (`frp-core/src/config/tests.rs:9983`) — the
  item's "whether frp-rs keeps supporting v1 settings roots in `.ini` at all" is a design question, and
  `docs/config.md` now records the answer the reader gives. One correction to the item text:
  `[plugin.user] ops = login` beside a `[common]` header does **not** come out rc 0 — both modes are rc 1
  (`http_plugins entry 'user' has no addr`) and only the message differs from Go's. Teeth: the top-level
  strict no-op mutant (`frp-core/src/config/strict.rs:474`, `check_strict_in` → `Vec::new()`) reds both
  pins at `:13940:56` and `:14007:34`.

- [x] **`includes` in a legacy `.ini` is processed before the `[common]` hoist, so a `[common]`-only `includes` is never expanded and a top-level one is expanded where Go ignores it.**
  Measured by the #425 rounds 4-7. `process_includes` (`frp-core/src/config/file.rs:247`) runs
  **before** the `[common]` hoist (`frp-core/src/config/normalize.rs:1163`), so
  `[common] includes = "<file>"` merges that file on Go (Go expands includes from `[common]`,
  `pkg/config/legacy/client.go`) while frp-rs silently keeps its own config — with a bad included
  file Go rc 1 against frp-rs rc 0 (`x12`). The mirror shape: a top-level `includes = "<file>"` in
  a file that also has `[common]` is expanded by frp-rs and ignored by Go, so frp-rs loads a proxy
  Go does not; and a `.ini` with no `[common]` at all plus `includes = "<valid file>"` is rc 0
  here (it merges) against Go rc 1 in both modes. `[includes] type = "custom"` with no ports
  (`x2`) is rc 0 here — the section is dropped as an inert table by
  `drop_legacy_ini_include_tables` — against Go rc 1 `failed to parse proxy includes, err: invalid
  type [custom]`, under the port-only clause at `frp-core/src/config/normalize.rs:2120`.
  `[Includes] foo = 1` / `[includes.foo] foo = 1` are over-refused in strict mode where Go is rc 0
  (round 4 corrected the comment that misdescribed this; the behaviour remains), and a scalar
  `includes` spelling still reaches the collector (`h1c`/`h1d`).
  **Done-when:** the include walk and the `[common]` hoist are ordered as Go orders them (or each
  divergence is recorded with its measurement), with the include spellings pinned in both modes.

  **Done (2026-10-01, at code head `40fd1f0b` on `fix/legacy-ini-residues`, PR #442).**
  `process_includes` (`frp-core/src/config/file.rs:251`) ran before the `[common]` hoist
  (`frp-core/src/config/normalize.rs:1183-1188`), so `[common] includes = "<file>"` was silently
  dropped; the client `.ini` loader now takes that string key out of the raw `[common]` table while it is
  still visible (`frp-core/src/config/file.rs:339-346`) and appends it to the walk ahead of the top-level
  spellings (`:368 for includes in [legacy_common_includes, includes]`). Measured against Go v0.71.0 in
  both loader modes: `x12_good.ini` (`[common] includes = "<valid [p1] file>"`) is Go rc 0 with one proxy
  registered (Go's `verify` prints no proxy count; a live run registers exactly one)
  and was frp-rs rc 0 with **none** before, now rc 0 with `Proxies: 1`; `x12_missing.ini` is Go rc 1
  (`include: directory of … not exist`) and was frp-rs rc 0 before, now rc 1. Teeth: `[None, includes]`
  at `:368` reds seven include pins, `legacy_ini_common_include_is_expanded_like_go`
  (`frp-core/src/config/tests.rs:12381`, panic `:12397:9`) and
  `legacy_ini_common_include_missing_dir_refuses_like_go` (`:12424`, panic `:12439:68`) among them. Three
  spellings stay deliberately different and are written up in `docs/config.md`: a top-level `includes`
  beside `[common]` is still expanded here where Go ignores the default section (existing pin
  `legacy_ini_default_section_string_include_is_still_expanded`, `:12231`), a `[common]`-less string scalar
  `includes`/`include` is still merged where Go is rc 1 in both modes (and `[Includes] foo = 1` /
  `[includes.foo] foo = 1` stay over-refused in strict mode), and includes are still not
  `text/template`-rendered, so a render-invalid include Go rejects is merged as-is; the inert
  `[includes] type = "custom"` table is dropped here under the port-only clause
  (`frp-core/src/config/normalize.rs:2120`) where Go refuses it.

- [x] **The two legacy-format detectors disagree for a `[common.foo]`-only `.ini`, and the v1-path `[DEFAULT]`, dotted-root and range-render shapes still diverge.**
  Measured by the #425 round-6/7 reviews. For a file containing only `[common.foo]`, the detector
  in `frp-core/src/config/normalize.rs:1160` and the one in `frp-core/src/config/format.rs:223`
  reach different verdicts, so `q4` is Go strict 1 / loose 0 against frp-rs 1|1 — loose-only and
  identical on the parent, so a follow-up rather than a blocker. Also open from the #425 sweep:
  `[DEFAULT]` is treated as a normal section (`y10`/`y11`), the range render gaps `y14`/`y16`, and
  the `r_toml.ini` hybrid (`.ini` carrying `server_addr` plus `[[proxies]] name = "p" role =
  "weird"`), where only the strict verdict agrees with Go (both rc 1, on different messages) and the
  non-strict verdicts diverge — frp-rs strict `unknown field "[proxies]" in config file r_toml.ini —
  did you mean 'proxies'?` against Go strict `json: unknown field "server_addr"`, and frp-rs non-strict
  rc 0 with `Proxies: 0` against Go non-strict `decode proxy at index 0: unknown proxy type: `.
  **Done-when:** each shape is pinned to Go's verdict, or recorded as deliberate with its
  measurement.

  **Done (2026-10-01, at code head `40fd1f0b` on `fix/legacy-ini-residues`, PR #442) — recorded, not fixed.**
  Each shape is pinned in both loader modes: a `[common.foo]`-only `.ini` stays loose-only between the
  two detectors (`frp-core/src/config/format.rs:223` vs `frp-core/src/config/normalize.rs:1183`; Go
  strict 1 / loose 0 against frp-rs 1|1 — pin
  `dotted_common_only_section_is_legacy_for_the_collector_both_modes`, `frp-core/src/config/tests.rs:13770`),
  `[DEFAULT]` is treated as an ordinary section
  (`default_section_header_is_an_ordinary_section_both_modes`, `:13800`), a portless `[range:p]` is
  skipped with a warning rather than refused
  (`range_section_without_remote_port_is_skipped_not_fatal_both_modes`, `:13870`), and the `r_toml.ini`
  hybrid agrees with Go on the strict verdict only (frp-rs strict rc 1 `unknown field "[proxies]" in
  config file r_toml.ini — did you mean 'proxies'?` against Go's `json: unknown field "server_addr"`)
  while the non-strict verdicts diverge (Go rc 1 `decode proxy at index 0: unknown proxy type: ` against
  frp-rs rc 0 with `Proxies: 0`) (`r_toml_hybrid_ini_is_a_v1_shape_both_modes`, `:13835`).
  Teeth: turning the legacy detector off (`frp-core/src/config/normalize.rs:1183`, `legacy_ini = false`)
  reds the dotted-`[common.foo]` pin at `frp-core/src/config/tests.rs:13778:18`.

- [x] **`[common] start` is read from the wrong place for a `[common]`-less `.ini`, and that spelling has no pin.**
  Measured by the #425 round-6/7 adversarial reviews. Round 6's `legacy_start_override`
  (`frp-core/src/config/normalize.rs:2507`) removed `start` unconditionally and so deleted a
  legitimate legacy proxy section named `[start]`: `s90` (`[common]` + `[p1]` + a valid `[start]`)
  gave Go rc 0 with **2** proxies and the round-6 head 1; `s92` (`[start]` only) Go 1 / head 0;
  `s93`/`s95` masked Go's `proxy start role should be 'server' or 'visitor'` / `failed to parse
  proxy start, err: invalid type [custom]` refusals to rc 0; `s97` lost a visitor. Round 7 fixed
  the deletion by capturing the pre-hoist `[common] start` and threading it through the collector
  and the override (`frp-core/src/config/normalize.rs:1173 legacy_start_override(table, legacy_ini,
  common_start)`), which restores `s90`→2 and `s92`→1, with pins
  `legacy_ini_start_section_is_still_a_proxy` (`frp-core/src/config/tests.rs:12345`),
  `legacy_ini_start_section_refusals_like_go` (`frp-core/src/config/tests.rs:12304`),
  `legacy_ini_start_comes_from_the_common_section_only`
  (`frp-core/src/config/tests.rs:12149`) and `legacy_ini_common_start_list_selects_named_sections`
  (`frp-core/src/config/tests.rs:12426`). What is still open is the `[common]`-less spelling: a
  `DefaultSection start = p2` beside a `[start]` section gave Go **1** proxy named `start`, round 5
  `4113b413` 1, round 6 head **0**, and nothing in the suite pins it.
  **Done-when:** `start` is read exactly where Go reads it in every spelling (or the remaining
  spelling is recorded as deliberate with its measurement) and the `[common]`-less case is pinned.

  **Done (2026-10-01, at code head `40fd1f0b` on `fix/legacy-ini-residues`, PR #442).**
  Round 7's capture is the shape that stands: `legacy_common_start` (`frp-core/src/config/normalize.rs:2511`)
  reads `[common] start` before the hoist and `legacy_start_override` (`:2530`, called at `:1196`) writes
  it back after collection, so `s90` is 2 proxies and `s92` 1 again, pinned by
  `legacy_ini_start_comes_from_the_common_section_only` (`frp-core/src/config/tests.rs:13182`),
  `legacy_ini_start_section_refusals_like_go` (`:13337`), `legacy_ini_start_section_is_still_a_proxy`
  (`:13378`) and `legacy_ini_common_start_list_selects_named_sections` (`:13459`). The `[common]`-less
  spelling the item left open is now pinned rather than silent:
  `legacy_ini_default_section_start_beside_start_section_both_modes` (`:12279`) records Go's 1 proxy named
  `start` against frp-rs's 1, and `legacy_ini_without_common_start_scalar_is_a_v1_shape` (`:12311`)
  records the residual — a scalar `start` with no `[common]` is Go's v1 type error against frp-rs rc 0 —
  with the divergence written up in `docs/config.md`. Teeth: a `legacy_common_start` that prefers the
  hoisted top-level key (`frp-core/src/config/normalize.rs:2511`) reds
  `legacy_ini_start_comes_from_the_common_section_only` at `frp-core/src/config/tests.rs:13218:68`, plus the
  sibling start pins (seven for this mutation; the count varies with the chosen equivalent mutant).

- [x] **An unknown key merged out of `[common]` is still refused in strict mode, where Go's legacy reader accepts it.**
  Measured by the #425 item-1 round: `c1.ini` (`[common] server_addr = 127.0.0.1` + `[common]
  zzz_unknown_common = 1`) gives Go rc 0 in both loader modes (its legacy reader ignores a key its
  typed struct does not name), while frp-rs is rc 0 loose / rc 1 strict `unknown field
  "zzz_unknown_common"` — the `[common]` merge (`frp-core/src/config/normalize.rs:1163`) moves the
  key to the top level *before* the top-level strict walk, so the `.ini` exemption does not cover
  it. This is **deliberate**: exempting the keys the merge created would also blind the top-level
  half to a genuine v1 typo spelled under `[common]`, and the item's Done-when allows the
  measurement instead. Filed so the exemption is visible rather than silent.
  **Done-when:** the merged keys are told apart from the file's own top-level keys (so a key that
  only exists because of `[common]` is accepted) without weakening the top-level check, or the
  divergence is recorded as deliberate in `docs/config.md` with this measurement, pinned.

  **Done (2026-10-01, at code head `40fd1f0b` on `fix/legacy-ini-residues`, PR #442) — recorded as deliberate.**
  `legacy_ini_common_unknown_key_residual_both_modes` (`frp-core/src/config/tests.rs:12344`) pins the
  measured asymmetry: `[common] zzz_unknown_common = 1` loads on Go in both modes (its legacy reader
  ignores keys its typed struct does not name) while frp-rs is rc 0 loose / rc 1 strict `unknown field
  "zzz_unknown_common"`, because the `[common]` merge (`frp-core/src/config/normalize.rs:1185-1188`,
  `table.entry(k).or_insert(v)`) moves the key to the top level before the top-level walk
  (`frp-core/src/config/strict.rs:474`). Exempting the keys that merge created would also blind the
  top-level half to a genuine v1 typo spelled under `[common]`, so the divergence is recorded in
  `docs/config.md` with the measurement rather than fixed. Teeth: the top-level strict no-op mutant
  (`frp-core/src/config/strict.rs:474`) reds this pin at `frp-core/src/config/tests.rs:12358:58`.
  Ledger after this batch: **24 open / 174 closed** (base `ed2d71a3`: 29 open / 169 closed; this batch
  closes the five legacy-`.ini` residue items).
- [ ] **R1 — With `-c`, a *non-empty* log flag is still honoured on `frps` where Go discards the whole pflag-bound struct.**
  Residual from the empty-`--log-level` item closed in #427. `frps/src/main.rs:989-991` gates only
  `override_server_config` on `cli_overrides_enabled()`; `frps/src/main.rs:994` then calls
  `init_logging(&cli, Some(&cfg))` with the **raw** CLI values, so `frps -c frps.toml --log-level info`
  emits 11 `INFO` records where Go's `-c` lane emits 0 (`/tmp/frp-go-src/cmd/frps/root.go:67-83`),
  contradicting the contract stated at `frp-core/src/cli.rs:3724-3731`. Same for `--log-file`,
  `--log-max-days` and `--log-format`. Verified pre-existing (`git show 3f66d823:frps/src/main.rs`
  is identical in this respect).
  **Done-when:** `init_logging` is gated on `cli_overrides_enabled()` too, or the divergence is
  recorded where `-c`'s override contract is documented and pinned by a test.
- [ ] **R2 — The implicit-config lane (`frps --log-level ""` with an in-tree `frps.toml`) has no Go counterpart.**
  Post-#427 it keeps the file's `warn` (0 `INFO`); Go without `-c` never reads a file and emits 1
  `INFO` (`frps uses command line arguments for config`, 186 B). The lane is an frp-rs extension
  (`FrpsArgs::config_path`, `frp-core/src/cli.rs:3718-3722`).
  **Done-when:** recorded as an extension where the implicit-config behaviour is documented, or made
  argv-identical to Go's flags-only lane.
- [ ] **R3 — `--log-format ""` still writes through, unlike the other three log flags.**
  `--log-format` is frp-rs-only (no Go answer, no `LogConfig::complete` slot), so there is nothing to
  align it with; it is kept intentional and pinned as such by #427.
  **Done-when:** documented at the flag (done: `docs/config.md` `[log] format` row states the
  exception) or made "not supplied" like the other three.
- [ ] **R4 — The out-of-range `--vhost-http-timeout` refusal text is Rust's, not Go's `strconv.ParseInt` wording.**
  Residual from the `int64` item closed in #427: `--vhost-http-timeout 9999999999999999999` is rc 1 on
  both, but frp-rs prints 84 B ``Error: couldn't parse `9999999999999999999`: number too large to fit
  in target type`` where Go prints 2214 B (its `strconv.ParseInt` message plus the `Usage:` block).
  The new rows pin rc and empty stdout only.
  **Done-when:** the text is matched, or which parts of the diagnostic are contractual is recorded.
- [ ] **R5 — `-l` is not a shorthand on `frps`, so its refusal wording differs from pflag's.**
  `frp-core/src/cli.rs:1148` `VALUE_TAKING_SHORTS_FRPS_ROOT: [char; 3] = ['c', 'p', 't']`, so
  `frps -c cfg -l ""` → rc 1 ``Error: `-l` is not expected in this context`` against Go's rc 1
  `unknown shorthand flag: 'l' in -l`. rc parity; wording differs; untested.
  **Done-when:** pflag's wording is matched or rc-only parity is pinned.
- [ ] **R6 — Two bounds on the "accept-and-ignore matches Go" claim for `--vhost-http-timeout`.**
  (a) `frps --config-dir …` with an empty `--log-level` resolves to `info` (not `debug`, which only
  the opt-in `debug-logs` feature reaches — `frp-core/src/logging.rs:101-112`) because the config-dir
  lane calls `init_logging(&cli, None)` (`frps/src/main.rs:470`), i.e. it never reads the loaded
  config's `[log]`; (b) the 24 h cap is frp-rs-only — `VHOST_TIMEOUT_CAP_SECS`
  (`frp-server/src/vhost.rs:654`, applied by `clamp_vhost_timeout` at `:710`) has no Go counterpart,
  so "accept-and-ignore matches Go" is bounded to values `<= 0` or below the cap.
  **Done-when:** the `--config-dir` lane resolves from the loaded config, or both bounds are recorded
  at the flags with their measurements.

- [ ] **The `frps` dashboard `web_server.tls.enable` captures still count their record, and the ported byte-pin helper is weaker than the `frp-core` original on two points.**
  Filed by the coordinator from PR #439's two review rounds. (a) The dashboard `KEY` captures
  (`frps/tests/warn_delivery.rs:471`, `:1100`, `:1113`, `:1177`, `:1224`) still assert a count plus a clause —
  `assert_clause_matches_this_build` (`:495`) pins which build-shape clause is expected, not the record's
  bytes — so appending a clause at the dashboard emit site (`frp-core/src/config/loader.rs:723`) leaves
  `cargo test -p frps --test warn_delivery` green in both feature shapes while
  `cargo test -p frp-core --test web_server_tls_enable_warning` reds (`frp-core/tests/common/mod.rs:113`).
  (b) The port compares the level with `level.contains("WARN") && !level.contains('\n')` where the shared
  helper uses the untrimmed `assert_eq!(level, " WARN")` (`frp-core/tests/common/mod.rs:133-141`), so
  `target: "evil frp_core::config::loader"` and `target: " frp_core::config::loader"` stay green here.
  (c) `clean.lines()` (`frps/tests/warn_delivery.rs:671`) makes the helper's `tail == "\n"` and
  no-following-line guards unreachable, so a bare extra newline or an appended following line stays green,
  while the port's doc comment (`:606-618`) still claims "the same three rejections" as the source. All three
  are caught by the unchanged `frp-core` lanes, so no coverage is lost relative to the base.
  **Done-when:** the `frps` dashboard captures pin the record's bytes, the level is compared untrimmed, the
  following-line bytes are covered, and each of the three mutants reds the `frps` lane itself.

- [ ] **`docs/config.md:22` names `websocketPort` as the Go frp v0.71.0 spelling of `websocket_port`, but Go's `frps` has no such field.**
  Filed by the coordinator from PR #436's delta adversarial (INFO). Measured with the real v0.71.0 binary:
  a server config carrying `websocketPort` is refused with exactly `json: unknown field "websocketPort"`
  and binds neither port; Go's `pkg/config/v1` server config names no WebSocket port at all, and Go's
  server carries WebSocket upgrades on `bindPort`. `frp-core/src/config/strict.rs:105` lists the spelling in
  `known_server_keys()`, a strict-parser acceptance set that also carries implemented keys (`bind_port`),
  and `frp-core/src/config/server.rs:39-41` accepts it as a serde alias of the implemented, feature-gated
  `pub websocket_port: u16` (`frp-core/src/config/tests.rs:270`/`:286` pins that the alias really drives the
  field), so frp-rs acts on the spelling as an extension — which leaves the reference row's Go column as the
  claim the measurement contradicts; `tls_enable`'s row (`docs/config.md:25`) already shows the shape for a
  server key with no Go counterpart.
  **Done-when:** `docs/config.md:22` either gets the `—` shape (`frp-rs` accepts the spelling and Go's `frps`
  has no such option, so it is an frp-rs extension), or the Go mapping is re-measured and kept.
