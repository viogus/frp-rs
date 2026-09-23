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
- [ ] **The same feature-unification defect class survives elsewhere: `AuthMethod::Oidc` in
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

- [ ] **Two observations of `test_tcpmux_proxy_auth` failing are unusable: both fall inside windows
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
- [ ] **The admin HEAD/auth placement matches Go only for *authenticated* requests; a measured
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
- [ ] **Strict mode accepts unknown fields inside `[[proxies]]` / `[[visitors]]`, where Go
  rejects them — a deliberate, documented divergence that is not in this list and not in the
  user-facing docs.** Measured with identical config text on Go frp v0.71.0 and frp-rs, both
  through `GET /api/reload?strictConfig=true`:

  | unknown field in | Go v0.71.0 | frp-rs |
  |---|---|---|
  | `[auth]` / `[log]` / `[webServer]` / `[transport]` | 400 | 400 |
  | a `[[proxies]]` entry | **400** (`decode proxy at index 0: ... unknown field`) | **200** |
  | a `[[visitors]]` entry | **400** | **200** |

  This is **deliberate, not an oversight**: `section_known_keys`
  (`frp-core/src/config/strict.rs:280-285`) documents that sections not listed are not
  recursed into — "Go's RejectUnknownMembers (pkg/config/v1/decode.go) rejects unknown
  proxy/visitor/plugin fields; frp-rs deliberately does not recurse into them — per-type keys
  would make the check a maintenance hazard, and skipping the recursion is the looser
  direction, keeping valid frp-rs configs loading." The point of this item is that the
  decision lives only in that code comment: it is absent from this known-debt list and from
  the user-facing strict-mode prose in `docs/deployment.md`, which lists "a strict-mode
  unknown key" as a 400 source without the exemption. Consequence: a typo in a proxy or
  visitor block is silently ignored in strict mode — the same silent-config-loss class as the
  camelCase wire-field gotcha.
  **Done-when:** either recurse into the arrays with per-type key sets (Go-faithful; needs a
  maintenance story for new proxy types and their aliases), or state the exemption and its
  rationale in the strict-mode prose in `docs/deployment.md`, so a user knows a proxy-block
  typo will not be caught. No sha.
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
  Go exits 1 (now its own item below).

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
  disk and how much point-in-time prose each carried. Every reading below was taken with the
  *broken* script on 2026-09-23 and is therefore not reproducible from the fixed script; the
  coordinator measured `FAIL 3919` (3915 under `.worktrees/*` + 4 in `.superpowers/sdd/*`), then
  4139, then **4140** (4136 + 4) as worktrees came and went, i.e. each nested worktree contributed
  **204-221** refs. The stable facts are the mechanism, the per-worktree contribution, and the 4
  refs that live in `.superpowers/sdd/*` (all four are absent paths quoted by that directory's
  2026-08 insight reports). Two root causes compounded: (a) nested worktrees were scanned at all;
  (b) the exclusions are root-anchored — `p in SKIP_FILES` and `p.startswith(SKIP_DIRS)`
  (`:598-599`, `:699` pre-fix) — so a nested `.worktrees/<x>/TODO.md`, `CHANGELOG.md` or
  `docs/archive/…` was **not** skipped even though the root copy is a deliberate point-in-time
  exclusion, and those files are exactly where the intentional absent paths live. The `health` CI
  job (clean checkout) and an isolated worktree with no nested `.worktrees/` both passed with
  `RESULT: invariants hold` — so a local gate that was red only because the mandated workflow was
  in use was a false positive, and it trained authors to ignore the script (the same trap the
  archive/SKIP list was added to avoid).
  **Done-when:** drive the scan from `git ls-files` (keeping the existing `find` fallback for a
  `.git`-less tree) or prune gitignored paths before walking, falsified by both cases: with a
  nested worktree under `.worktrees/` and a `.superpowers/sdd/` file present, the script exits 0
  and reports the same path counts as the clean checkout; and a genuinely stale backticked path
  added to a tracked file still exits 1. No sha.

  Done (branch `fix/repo-health-tracked-scan`, based on `main` @ `f8f127f`): the first branch of
  the done-when — the file list now comes from the git index. A new `tracked_files()` runs
  `git ls-files -z --full-name --cached` (python3 stdlib `subprocess`, no new dependency) and
  returns `None` when `.git` is absent or git cannot list, in which case `walk_files()` keeps the
  old `os.walk` (still pruning only `.git`/`target`) for a `.git`-less tarball / Docker context.
  `git ls-files -z` is preferred over pruning gitignored directories by hand because the index *is*
  the clean-checkout file set (no re-implementation of `.gitignore` matching, one fast call), and
  it fixes the root-anchoring bug (b) for free. The index supplies the file *list*; content is read
  from the **worktree**, so a tracked file edited locally is gated at its current content. Paths
  are NUL-split and decoded with `surrogateescape`, so spaces, newlines and non-ASCII cannot be
  mis-parsed or silently dropped. The summary line format and every classification rule (`ROOTS`,
  `normalize`, `classify`, `cargo_features`, `SKIP_DIRS`/`SKIP_FILES`) are unchanged, so no count
  changed meaning. Measured in the worktree, macOS arm64, warm cache:
  * clean (no `.worktrees/`, no `.superpowers/`): exit **0**, `ok    272 repo path references
    resolve (file-relative, crate root, then repo root)`, `info  skipped 227 locator-less bare
    ref(s) and 57 locator-less shorthand(s) (no recoverable base); 7 `crate/feature` span(s)`,
    2.42 s wall.
  * case (a) nested worktree + ignored probe: `git worktree add .worktrees/scan-falsify -b
    probe/scan-falsify` (ignored — `git check-ignore -v .worktrees/scan-falsify` →
    `.gitignore:17:.worktrees/`) plus `.superpowers/sdd/probe.md` naming
    `frp-core/src/this-file-does-not-exist.rs` (`git check-ignore` → `.gitignore:20`). The
    **pre-fix** script on that tree exited **1**, `FAIL  222 path reference(s) do not resolve`
    (221 from the nested worktree + 1 from the probe). The fixed script exits **0** with the count
    line **byte-identical** to the clean run above (ok 272 / features 7 / shorthand 57 / bare 227),
    2.39 s wall. Probe worktree removed with `git worktree remove --force` + `git worktree prune`
    and the `probe/scan-falsify` branch deleted.
  * case (b) stale ref in a tracked file: appending a `//` comment naming
    `frp-core/src/this-file-does-not-exist.rs` to tracked `frp-core/src/base64.rs` gave exit **1**
    with `stale: frp-core/src/base64.rs:165` naming that path, and `FAIL  1 path reference(s) do
    not resolve from the referencing file`; `git checkout -- frp-core/src/base64.rs` restored
    exit 0 / `ok 272`. This also pins the index-vs-worktree decision: the file was
    unmodified in the index and the local edit was still caught.
  * fallback (committed tree): `git archive HEAD | tar -x -C /tmp/rh-nogit`, run from there →
    exit **0**, `ok 272`. That exercised `os.path.exists('.git')` → `None` → `walk_files()`. With
    `.git` present but unlistable (an empty `.git` directory, and a `PATH` containing no `git` at
    all, which raises `FileNotFoundError` → `None`) the same fallback runs and the gate still
    evaluates: exit 0 / `ok 272`, no traceback.
  * fail-loud floors, falsified in throwaway copies under `/tmp` (never in the repo): forcing the
    index list to `[]` → `scan error: git ls-files listed no scannable .md/.rs file — refusing to
    report "no stale refs"`; keeping the real list but raising the floor → `scan error:
    implausibly small scan from git ls-files (267 file(s), 12207 span(s); floor 10**9/100) — refs
    not certified`; suppressing the span loop → `scan error: git ls-files examined 267 file(s) / 0
    span(s) — refs not certified`. All three exit **3** and surface as `FAIL  path-reference scan
    produced no result (exit 3) — refs not certified` with `RESULT: FAILURES above`. A tracked path
    that cannot be opened (deleted in the worktree, or a mode-160000 gitlink named `*.md`) prints
    `read error: <path>: No such file or directory` and exits 3, no traceback; a gitlink named
    anything else is filtered out by the extension test before it is opened. `git ls-files -s | awk
    '$1==160000'` is empty in this repo today, and `git ls-files` reports 0 paths with spaces or
    non-ASCII, so neither case is live — they are handled and were probed synthetically as above.
  * scope: the scan is now **tracked-files-only**, so an untracked local file naming a dead path is
    no longer gated. Deliberate: the CI `health` job runs on a clean checkout where untracked ==
    absent, so the gate's CI meaning is unchanged. Stated in the `scripts/repo-health.sh` coverage
    comment, `docs/developing.md` § Repository Invariants and `CLAUDE.md:209`. No Rust file
    touched; `bash -n scripts/repo-health.sh` clean.
- [ ] **`frpc` has no `stop` subcommand and no `--api-timeout`, so its admin-command surface is
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
- [ ] **The `frpc` daemon start path exits 2 where Go exits 1 on the same bad config, and prints a
  tracing line instead of Go's bare parse error.** Measured with identical config text (a valid
  config plus one unknown top-level key), both on **stdout**:
  * Go v0.71.0 `frpc -c badcli.toml` → `json: unknown field "notAKnownFrpKey"`, exit **1**.
  * frp-rs `target/debug/frpc -c badcli.toml` → an ANSI-coloured tracing line
    `ERROR frpc: Failed to load config: unknown field "notAKnownFrpKey" in config file …`,
    exit **2** (`EXIT_CONFIG`, `frp-core/src/lib.rs:193` — "bad config file, unknown field,
    invalid value", part of frp-rs's 1-4 CLI exit scheme, which no live doc states: the only
    prose is that constant's comment and three archived documents that **state** the scheme —
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
- [ ] **The space-separated `--strict-config false` form is an frp-rs extension presented as Go
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
- [ ] **Three pre-existing `frpc` CLI inputs Go accepts and frp-rs does not** (all measured on
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
    (`WebServerConfig.Complete()` fills the empty addr, `pkg/config/v1/common.go:71-73`);
    frp-rs dials `":<port>"` and fails with `failed to lookup address information: nodename nor
    servname provided, or not known`.
  **Done-when:** match Go on all three (last-wins `-c`, case-insensitive config keys, default the
  empty `addr` to `127.0.0.1` at the CLI/load boundary) with a CLI test per case in the style of
  `frpc/tests/admin_cli.rs`, or record each as a deliberate divergence in the feature-surface
  policy. No sha.

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

- [ ] **The compat lanes install a floating Go toolchain that nothing uses.**
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
  It is a leftover of a removed path that `CHANGELOG.md:1329-1330` (0.3.1)
  records — `build_go_frp_v2()` (clone + `go build`, cached to
  `/tmp/frp-source-build/`) exists nowhere in the tree, yet
  `.github/workflows/compat.yml:48` still caches that orphaned
  `/tmp/frp-source-build/` under a step named "Cache cargo + go-frp builds".
  **Done-when:** either drop the `setup-go` step, the stale
  `/tmp/frp-source-build/` cache path and the "go-frp builds" wording with the
  lane still green, or pin the Go version and state what consumes it. Today
  nothing consumes it, and the `>=` range makes the resolved version a
  runner-image property.

- [ ] **The Docker source build is outside the toolchain pin and floats its own compiler.**
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
  Both instances are the item's shape — a scenario failing on a tree that passed the same lane
  elsewhere — and neither can be explained by a data-plane diff.

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
