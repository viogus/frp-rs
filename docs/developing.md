# Developer Guide

frp-rs is a native Rust implementation of [frp](https://github.com/fatedier/frp), a reverse proxy that exposes services on private networks to the public internet. This guide covers the development workflow for contributors.

Topic map — this guide deliberately does **not** restate the others:

| You want | Go to |
|---|---|
| How the system works (wire protocol, control plane, transports, XTCP) | [architecture.md](architecture.md) |
| Workspace layout, crate responsibilities, project tree | [architecture.md § Overview](architecture.md#overview) |
| Build matrix, feature flags, binary tiers | [CLAUDE.md § Binary Variants](../CLAUDE.md#binary-variants) and [README § Binary Variants](../README.md#binary-variants) |
| Dependency policy (allowed/banned crates) | [CLAUDE.md § Dependency Policy](../CLAUDE.md#dependency-policy-mandatory) |
| Rules, invariants and gotchas an agent must not break | [CLAUDE.md](../CLAUDE.md) |
| Config / proxies / plugins / deployment references | [documentation index](README.md) |
| Historical design docs and audits | [archive/](archive/README.md) |

If this guide states how the code is structured, it must point at the relevant
[architecture.md](architecture.md) section or carry a verified `file:line` (and
the symbol name). The process sections below — build, debug, test, release,
dependency policy — are this document's own domain and need no citation.

## Review protocol (mandatory)

A green gate proves a command exited zero; it does not prove the change does what
its author says. Review is what stands between a plausible diff and a merged one,
and this repository has a single author, so an unreviewed change has no second
reader at all.

**Every change gets at least two independent reviews, and at least one of them is
adversarial.** "Independent" means the reviewer did not write the change — an
author reviewing their own work counts as neither. Both are recorded in the pull
request; an unrecorded review did not happen.

### Reviewer 1 — the claim

Read the diff against the claim in the PR description and ask whether the claim is
*earned*. Concretely:

- **Recompute, do not read.** Every number, count and ratio in the diff or the PR
  is recomputed from its source. If a doc quotes a scenario count, run the thing
  that counts them.
- **Open every citation.** Each `file:line` and each quoted upstream claim is
  opened at that line, in this tree, at this commit. A citation nobody opened is a
  rumour with a line number.
- **Check the evidence class.** A passing unit test is not Go-parity evidence; a
  probe of the real binary or a Go source citation is. See
  [§ What a green test run does and does not prove](#what-a-green-test-run-does-and-does-not-prove).
- **Look for what is missing** as hard as for what is wrong: an untested branch, a
  case named in the description but absent from the tests, a claim with no gate
  behind it.

### Reviewer 2 — adversarial

The adversarial reviewer's brief is to **falsify the change**, not to confirm it.
"Looks good" is not a review. A useful adversarial review tries to construct the
world in which the change is wrong, and reports either the construction or the
attempt:

- **Run the opposite direction.** If the author proved "fails when violated", try
  to make it fail *without* violating the thing it claims to catch — a gate that
  passes because it matches nothing, a test that passes because its assertion is
  unreachable, a check whose pattern silently never fires.
- **Attack the negative case.** Feed the fix the input it does not expect: the
  empty value, the malformed value, both channels at once, the concurrent case,
  the value that is *almost* the one it special-cases.
- **Inspect the diff for weakenings.** Removed assertions, loosened assertions,
  widened timeouts, new `#[allow]`/`#[ignore]`/`#[cfg]`, retries, deleted tests,
  or a claim quietly reworded to match what the code does. Each needs a stated
  reason; "to make CI green" is not one.
- **Check the blast radius.** What else reads the thing that changed? For features,
  what happens when it is *off*? For a shared helper, who else calls it?
- **Say what would change your mind.** If the review cannot state the observation
  that would falsify the change, it is not adversarial.
- **Mutate in your own checkout, never the tree being measured.** If you edit a
  crate under test to build a mutant, do it in a separate worktree and rebuild
  from the restored source before measuring anything else in the shared tree.
  The server integration tests mostly run frps *in-process*, and the rest spawn
  the `target/` frps binary, so in both cases the code under test is whatever was
  compiled into `target/` at build time: a mutant left in a shared tree is
  silently measured as the product by every other agent, and it surfaces as a
  plausible-looking flake in whichever test the mutant happens to break. That is
  worse than no measurement — it is a false positive someone else has to
  disprove, and it looks exactly like a real finding.

### What a review must refuse

Reject, or send back with a question, a change that: has no evidence for its
central claim; substitutes a passing test for the real check the repo uses; adds a
retry or an allow where the cause is unknown; states a number nobody measured;
cites a `file:line` that does not say what it is quoted for; or is described in the
PR more strongly than the diff supports.

### Finding a defect

A review that finds a defect is a success, not a delay — record it. The fix is
re-reviewed (both reviewers), because a fix is a change too and is the most
common place for a second defect to hide. If two reviews disagree, the
disagreement is resolved with evidence, not by seniority or by whichever reading
is more convenient.

### Recording it

The pull request carries a short block, so the next reader can tell what was
actually checked:

```
## Reviews
- Reviewer 1 — method: <how>; checked: <what, with evidence>; findings: <...| none>;
  disposition: <fixed in <sha> | rejected: <reason> | follow-up: <where>>
- Reviewer 2 adversarial — method: <how it tried to falsify>; checked: <claim attacked>;
  findings: <...| none>; disposition: <...>
```

The four fields are the ones rule 4 requires — **method, what was checked,
findings, disposition**. A claim of "reviewed" with no method named is not a
review. Where a review could not check something — a Linux-only path on macOS, a
VPS-only XTCP matrix — it says so, because an unstated gap reads as coverage.
`.github/PULL_REQUEST_TEMPLATE.md` carries the same block.

## 1. Workspace at a glance

Six crates in a layered graph; dependencies flow **upward** (binaries → logic
crates → `frp-core`, which has no internal workspace dependencies). The graph
and the crate-by-crate responsibilities are canonical in
[architecture.md § Overview](architecture.md#overview): `frp-server` /
`frp-client` hold the protocol logic but no `main()`, and the binaries live in
`frps/` and `frpc/`. The annotated module tree is
[§ Project Structure](architecture.md#project-structure).

## 2. Adding a New Proxy Type

This section walks through adding a new proxy type called `myproxy`:

### Step 1: Config Parsing (if needed)

If the new proxy type requires new config fields, add them to `ProxyConfig`
(`frp-core/src/config/client.rs:585`, in `frp-core/src/config/`). Existing proxy
config fields are shared across all proxy types in `ProxyConfig` -- if your proxy
type reuses those fields, no config changes are needed.

### Step 2: Register in ProxyManager

`handle_new_proxy` (`frp-server/src/control/proxy_ops.rs:1849`) is the NewProxy
entry point and delegates to `register_proxy_entry` (`proxy_ops.rs:794`), which
inserts into `ProxyManager` (`frp-server/src/proxy.rs:116`); most proxy types
reuse that existing registration logic. If your proxy type needs special
registration:

- **Port allocation**: `register_proxy_entry` allocates via
  `allocate_port_multi()` (`frp-server/src/proxy.rs:821`). SUDP proxies get
  special shared-port handling.
- **sk_index**: STCP/XTCP/SUDP proxies register in `sk_index`
  (`register_sk_index`, `proxy_ops.rs:493`) for secret-key routing. Add your
  proxy type to that predicate if it uses sk-based routing.
- **VHost routing**: HTTP/HTTPS proxies register in `VhostManager`
  (`frp-server/src/vhost.rs:265`). Add your proxy type here if it uses
  domain-based routing.
- **TcpMux routing**: TCPMux proxies register in `TcpMuxManager`
  (`frp-server/src/tcpmux.rs:34`).

### Step 3: Add Listener Setup

Listener setup/invocation is `setup_proxy_listeners`
(`frp-server/src/control/proxy_ops.rs:1456`). Its branches: `udp`/`sudp` bind an
`Arc<UdpSocket>` directly and request work connections with
`InternalMsg::UdpNeedsWorkConn`; `stcp`/`xtcp`/`tcpmux` start **no** per-proxy
listener (NAT hole punch and shared listeners respectively); `tcp` binds a
per-proxy listener and spawns `listen_and_proxy`
(`frp-server/src/control/proxy_ops.rs:2781`) as its accept loop. HTTP/HTTPS use
the shared VHost listeners.

For a new proxy type that needs a different listener pattern:
1. Add a branch in `setup_proxy_listeners` for the proxy type
2. Spawn a `tokio::spawn` task that binds a `TcpListener` on the allocated port
3. On accept, send `InternalMsg::ProxyUserConn` (`frp-server/src/state.rs:344`)
   with the user connection and pre-read bytes

Example pattern (simplified from existing code):

```rust
let listener = TcpListener::bind(&addr).await?;
let internal_tx_clone = internal_tx.clone();
tokio::spawn(async move {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let _ = internal_tx_clone.send(InternalMsg::ProxyUserConn {
                    proxy_name: name.clone(),
                    user_conn: IoStream::Tcp(stream),
                    pre_read: vec![],
                });
            }
            Err(_) => break,
        }
    }
});
```

### Step 4: Implement Bridging Logic

The bridging is handled automatically by the control handler's
`InternalMsg::ProxyUserConn` path -- it pops a work connection from the pool,
sends `StartWorkConn`, and bridges. No special bridging code is needed for basic
TCP-like proxy types.

If your proxy type needs special bridging (e.g., HTTP host header rewriting,
protocol-specific framing), add the logic in `frp-server/src/control/bridge.rs`.
`assign_work_to_proxy` (`bridge.rs:3117`) prepares the assignment and
`run_work_bridge` (`bridge.rs:2430`) chooses plain vs encrypted/compressed
bridging and forwards the pre-read bytes.

For the client side, proxy type handling is in `frp-client/src/service.rs` and
`frp-client/src/work_conn.rs` (proxy registration; `work_conn.rs` reads
`StartWorkConn` to know which local service to connect to).

## 3. Building and Feature Flags

### Quick Reference

```bash
cargo build                  # Debug build (all crates)
cargo build --release        # Release build (opt-level=z, LTO, panic=abort)
cargo test --workspace       # Run all tests
cargo clippy                 # Lint
```

### Toolchain pinning

`rust-toolchain.toml` at the repo root pins the compiler for every rustup-based
job that builds the checked-out tree: an exact `channel` (`X.Y.Z`, never `stable`
and never a floating `X.Y`), `profile = "minimal"`, and the `clippy`/`rustfmt`
components. That is what makes a `cargo fmt` / `cargo clippy` result a property
of the commit rather than of the runner image or a developer's `rustup default`.

The channel is exact because a floating one re-introduces the failure the pin
removes: a new rustc/clippy release can add a lint that fires on untouched code,
which turns the lint gate red on a commit that changed nothing. An exact version
makes a compiler bump a deliberate, reviewable diff.

It is the file, not a workflow step, that selects the compiler: any `rustc`,
`cargo`, `cargo clippy` or `cargo fmt` run anywhere under the repository resolves
it, including subdirectories such as `scripts/frp-stress/`. A job therefore only
has to make sure the toolchain exists — run `rustup toolchain install --no-self-update`
in the repository. With no toolchain argument it installs exactly what the file
asks for: the pinned version, its `profile`, and its two components, reporting
`the active toolchain ... has been installed` and `overridden by
<repo>/rust-toolchain.toml`. A missing toolchain is never a reason to pass
`+toolchain` by hand. Bare `rustup show` also auto-installs the file's
toolchain, but rustup 1.29.1 warns that auto-installation is deprecated, so the
explicit install is what CI runs.

Typo behaviour, measured on rustup 1.29.1. A **misspelled component** is loud
where it matters: with a fresh `RUSTUP_HOME` — the state a CI runner starts in —
`rustup toolchain install --no-self-update` fails with `error: component 'rustfm'
for target '<host>' is unavailable for download for channel '1.98.1-<host>'`,
exit 1, installing nothing; only when that toolchain is **already installed**
does it degrade to `warn: skipping unavailable component rustfm` with exit 0, so
a local typo of that kind can pass unnoticed. An **unknown key** in the
`[toolchain]` table (for example `profilee = "minimal"`, or `component = [...]`
instead of `components`) is ignored with no warning at all and exits 0 in both
cases, so **that** typo rests on review. A typo in a *value* is always loud (a
malformed file, an unknown `profile` and a non-existent `channel` all exit 1),
and no silent case can leave the compiler unpinned: the `channel` rustup actually
resolves is the one the assertion step in `ci.yml` checks. And the file must keep
the standard `[toolchain]` section form:
rustup also honours an inline table (`toolchain = { channel = "..." }`) and a
dotted key (`toolchain.channel = "..."`), but the `repo-health.sh` gate parses
the section form only and **fails closed** on those two spellings rather than
accepting a form it does not check.

**Not covered:** the Docker source build. `docker/Dockerfile.source` starts from
a floating `rust:1-slim-bookworm` and does not copy `rust-toolchain.toml` into
the build context, so images built from it are outside the pin. That is recorded
as an open item in `TODO.md` ("The Docker source build is outside the toolchain
pin and floats its own compiler").

To bump:

1. edit `channel` in `rust-toolchain.toml` to the new exact version;
2. run `rustup toolchain install --no-self-update` — it installs the new
   toolchain and its two components;
3. run `cargo fmt --all -- --check`;
4. run `cargo clippy --workspace --all-targets --all-features -- -D warnings`;
5. fix every lint the new compiler reports **in the same PR**. That diff is the
   point of the pin: it is the reviewable consequence of the bump, not a
   follow-up chore.

`scripts/repo-health.sh` gates the pin itself: exactly one toolchain file, at the
repo root, in `.toml` form (tracked, present, and not shadowed by an untracked
one); an exact `channel` inside its `[toolchain]` table, quoted either way and
tolerating a trailing TOML comment; no `toolchain:` input on a
`setup-rust-toolchain` step — with the step recognised in these forms and no
others: inline `- uses: ...`, `uses :`, a quoted `uses:` value, a named step
(`- name: ...` with `uses:` on its own line, or under a bare `-`), and the flow
form `- {uses: ..., with: {...}}`, in `*.yml` and `*.yaml` — and the key
recognised as a block mapping, a flow mapping, a comma-separated flow mapping,
or a single-/double-quoted key, matched case-insensitively since action input
names are reported to be matched that way; and no floating `rustup default`
selection under `.github/workflows/`. Each of those checks' own comments list the
known shapes it does **not** see (each measured there, and explicitly not a
completeness claim): for the `toolchain:` scan those are, among others, an anchor
or tag token between `-` and `uses:`, a flow sequence with no `-` line, a comment
at or below the step's indentation before the key, a `#` inside an earlier quoted
value on the same line, an anchor/alias on the `with:` block, a key consumed by a
different action, and a case-different action URL (not verified against GitHub) —
plus fail-closed over-catches, where a `{`/`,` inside a quoted scalar or inline
comment, a nested sequence in the step, or a key-like line inside a block scalar
makes the gate fail a workflow that never passes the input. Deliberately not
chased: the check is a text scan, not a YAML parser.

### Binary Variants

Four size tiers via feature flags. The authoritative tier list, exact commands
and measured binary sizes live in the README —
[**Binary Variants**](../README.md#binary-variants). The resulting binaries are
named `frps`/`frpc` (default/full), `frps-tiny`/`frpc-tiny`, and
`frps-micro`/`frpc-micro`.

CI compiles the tiny and micro tiers with `RUSTFLAGS="-D warnings"` (the
`verify` job in `.github/workflows/ci.yml`). Two workspace checks cover the
tier **library and binary** graphs:

```bash
RUSTFLAGS="-D warnings" cargo check --workspace --no-default-features --features tiny
RUSTFLAGS="-D warnings" cargo check --workspace --no-default-features --features micro
```

They deliberately omit `--all-targets`. On a `--workspace` invocation every
member is a root, so the dev-dependency edges enter the graph, and
`frp-server`'s dev-dependency on `frp-client` (`frp-server/Cargo.toml:67`,
default features) plus `frp-client`'s on `frp-server` re-enable both crates'
`default` sets — measured, the micro graph flips from `frp-client = []` to
`frp-client = [chacha20, compression, default, http2http, kcp, oidc, quic,
tcp-mux, tls, websocket]`, and `frp-server` from `[]` to
`[chacha20, compression, default, http-proxy, kcp, oidc, quic, ssh, tcp-mux,
tls, websocket]`.
`--all-targets` there would therefore drop the tier coverage for those two
crates, not extend it.

The tier **test** targets are compiled by five sibling isolated checks instead,
where `-p` makes the crate the only root and the dev-dependency edge cannot
reopen its defaults:

```bash
RUSTFLAGS="-D warnings" cargo check -p frp-client --no-default-features --all-targets
RUSTFLAGS="-D warnings" cargo check -p frp-client --no-default-features --features tls,tcp-mux --all-targets
RUSTFLAGS="-D warnings" cargo check -p frp-server --no-default-features --all-targets
RUSTFLAGS="-D warnings" cargo check -p frp-server --no-default-features --features tls,http-proxy,tcp-mux --all-targets
RUSTFLAGS="-D warnings" cargo check -p frp-core   --no-default-features --all-targets
```

The `frp-core` step was added after the first two. `frp-core` is the only root
there, so its own features are off — measured with `cargo check -p frp-core
--no-default-features --all-targets -v`, every `frp-core` rustc invocation in
that run (the lib, the lib test, all 10 `frp-core/tests/*.rs` targets, and the
`frp-core/benches/crypto_bridge.rs` bench) carries zero `--cfg feature=` flags.
`frp-core`'s dev-dependencies are all external crates
(`frp-core/Cargo.toml`), none of which can depend back on it, so
no dev-dependency edge re-enables a feature of the crate under test. The run
exits 0; before the gates landed it exited 101 with four failing units (lib test,
`kcp`, `xtcp_p2p`, `protocol_round14`). It checks the same property as its two
siblings: a feature-gated item referenced without its gate is a compile error —
or, under `-D warnings`, a `dead_code` / `unused_imports` / `unused_mut` error.

Measured bound on the `frp-core` step, the same bound as the other two: it
covers the code that is *compiled*, not the targets. 6 of `frp-core`'s 10 test
targets are whole-file-cfg'd *empty* here — `kcp.rs` and `xtcp_p2p.rs` (`kcp`),
`mux.rs` and `yamux_rst.rs` (`tcp-mux`), `xtcp_quic_sni.rs` (`tls`),
`ws_tls_stall.rs` (`tls` + `websocket`). `cargo test -p frp-core
--no-default-features --test <t> -- --list` reports 0 tests for each, versus
4/12/13/3/2/1 with default features. The other 4 targets — `config_round14.rs`
(2 tests), `protocol_round14.rs` (4), `proxy_auth.rs` (3),
`v2_handshake_round14.rs` (3) — are compiled and checked in full.

That step is compile-only: it type-checks the test targets but does not link or
run them, so it cannot see a missing `#[cfg]` on a test or bench that still
*compiles*. The runtime half lives in the test lanes: `Tests (unit)` runs the
no-features command for `frp-core` and for `frp-client`, and
`Tests (server integration)` runs it for `frp-server`; the two sibling steps are
spelled out below. For `frp-core`, in the same no-features configuration:

```bash
cargo test -p frp-core --no-default-features --all-targets
```

Measured: it exits 0 with 609 tests passed / 0 failed and 124 criterion bench
cases run (default features: 903 tests / 130 bench cases; `--all-features`: 917 /
130). It is the only gate for the two `frp-core` failures of that class found
here: eight lib tests failed with `"compression not compiled"` (597 passed / 8
failed), and `frp-core/benches/crypto_bridge.rs` panicked the bench binary at
registration time — `thread 'main' panicked at
frp-core/benches/crypto_bridge.rs:60:64: called `Result::unwrap()` on an `Err`
value: "compression not compiled"`. Wall clock, macOS arm64: 5.39 s / 5.42 s /
5.51 s warm on three runs, and 19.84 s with `frp-core`'s lib, its 10 test targets
and the bench touched (forced rebuild). The runner's cost — Linux, cold cache —
was not measured.

Both `frp-core` steps inherit the same bound: neither checks nor runs anything
inside the 6 whole-file-cfg'd *empty* test targets listed in the paragraph above
(each reports 0 tests in this configuration — `cargo test -p frp-core
--no-default-features --test <t> -- --list` reports 0, and the runtime step's
output shows `running 0 tests`). They differ in what they do with the
code that is present — the `verify` step type-checks it, the unit-lane step links
and runs it. Neither *executes* the compression criterion group: the runtime step
does run the bench binary (measured `Running benches/crypto_bridge.rs`, 124
criterion cases), but the group's body is `#[cfg(feature = "compression")]`-gated,
so it is absent in the no-features configuration; the `verify` lane compiles the
group with default features (`cargo bench --workspace --no-run`) but runs no
benchmark. The
`--all-targets` flag drops the doctest target, which for `frp-core` contains 2
tests and both are `ignore`-marked (`frp-core/src/buffer_pool.rs:54`,
`frp-core/src/feature_gate.rs:9`), so nothing is lost.

The same runtime class was live in the sibling crates and now has two sibling
runtime steps.

`frp-client`'s is in the `Tests (unit)` lane, because its test targets need no
`frps`/`frpc` binary — they drive in-process services:

```bash
cargo test -p frp-client --no-default-features --all-targets -j 1 --no-fail-fast
```

`frp-server`'s is in the `Tests (server integration)` lane, because its five
`oidc_integration.rs` tests spawn `frps` and fail environmentally without one
(`failed to start frps: Os { code: 2, kind: NotFound }`,
`frp-server/tests/common/mod.rs`); that lane already builds the binary and sets
`FRPS_BIN`/`FRPC_BIN`:

```bash
cargo test -p frp-server --no-default-features --all-targets -j 1 --no-fail-fast
```

What they close, measured in this worktree (macOS arm64): 34 deterministic
`frp-server` failures and one `frp-client` failure in the no-features
configuration, all of them a missing `#[cfg]`. Per target, with the feature
floor each gate needs (every passing run below enables that feature and nothing
else) — `frp-server/tests/http_plugin.rs` (23 tests) and `http_plugin_ping.rs`
(5) whole-file on `http-proxy`;
`control::proxy_ops::unregister_generation_tests::stale_unregister_keeps_fresh_user_record`
on `http-proxy`; `test_login_via_websocket` on `websocket` and
`test_login_via_tls` on `tls` in `server_protocol.rs`; the two TLS cases in
`slowloris.rs` on `tls`; the three e2e cases in `vhost_https_sni.rs` on `tls`
(its fourth case, `test_hello_construction_extracts_sni`, needs no feature and
still runs in the no-features configuration);
`test_e2e_tcp_proxy_over_websocket` in `frp-client/tests/end_to_end.rs` on
`websocket` — 7 tests with the feature, 6 without, so no case is lost. The gates
are on each crate's **own** features, not `frp-core`'s: measured with `-v`,
`frp-core` is compiled with `websocket`, `tls` and the rest **on** in both graphs
(frp-server's dev-dependency on frp-client supplies frp-client's default
features, which forward `frp-core/websocket`, `frp-core/tls`, …), so
`TransportProtocol::WebSocket` exists and parses there.

Measured after the gates: `frp-server`'s step exited 0 with 436 passed /
0 failed in three of five samples, with an `frps` binary present (2m08s warm);
the other two were 435 passed / 1 failed on the pre-existing
`test_tcpmux_proxy_auth_interior_space_rejected_407` flake, since fixed (it has
its own `TODO.md` entry); it also failed with default features and was the only
measured pre-existing failure in those five samples. Without an `frps` binary
the same command adds 5 environmental
`oidc_integration` failures — that is why it is not in the unit lane.
`frp-client`'s step exits 101 **on this macOS host** with 312-313 passed
and 1-2 failed, both failures not this class and recorded in
[`../TODO.md`](../TODO.md) (a `start_paused` deadline flake and a
filename-containing-`0xFF` `EILSEQ`); both also run in the existing
default-features `Tests (client integration)` lane.

Neither step was measured on the runner (Linux, cache restored from a
default-feature build), and neither says anything about the whole-file-cfg'd
*empty* targets listed below — 9 of `frp-server`'s 35 `tests/*.rs`, 6 of
`frp-core`'s 10, 4 of `frp-client`'s 40 — which compile to nothing in this
configuration and so cannot fail in it.

This is the **no-features** configuration for frp-client — the micro tier — not the
tiny one. frp-client's tiny set is `tls,tcp-mux`, and it has its own isolated check
(the `frp-client` tiny-targets step above). That step exists because
`plugin_h2.rs` was gated on `tls` alone while its `h2`/`http` imports come from
`http2http` — so in tiny it was selected in and failed to compile (5 errors). It
is now gated on `http2http`; see [`../TODO.md`](../TODO.md).

That run compiles frp-client's test targets with `tls` off, which is what makes
a missing gate fail: the 5 `tls`-gated items in the
`frp-client/src/plugin/mod.rs` test module (four tests plus the
`plugin_peer_ip_now` helper) and the `tls`-gated import plus two tests in
`frp-client/tests/plugin_http.rs` reference tls-only items, so dropping their
`#[cfg(feature = "tls")]` turns those references into compile errors (or an
unused import) under `-D warnings`. With the gates present they are excluded
and the run is clean — the `tls`-on path of the same tests is compiled by the
`Lint` lane's `--all-targets --all-features` clippy.

The frp-server sibling compiles `frp-server`'s test targets with **frp-server's
own features at the micro set — none of `tls`, `websocket`, `ssh`, `kcp`,
`quic`, `oidc`, `http-proxy`, `compression`, `chacha20`, `tcp-mux`**. For the
targets that are compiled, every `#[cfg(feature = ...)]` in `frp-server`'s lib
and test targets is complete for that configuration: an optional item referenced
without its gate is a compile error (or an unused import) under `-D warnings`
here instead of a warning nothing promotes.

Measured bound on that guarantee — it is a bound on the **code that is compiled**,
not on the targets. A whole-file-cfg'd target compiles to nothing, and inside a
target that does compile, any `#[cfg]`-excluded item is unchecked in exactly the
same way. Concretely: **9 of `frp-server`'s 35 `tests/*.rs` targets are
whole-file-cfg'd *empty* in this configuration**, so nothing inside them is
checked at all — `dashboard_integration.rs` and `dashboard_v2_integration.rs`
(`dashboard`), `ssh_gateway.rs` (`ssh`), `transport_e2e_kcp.rs` (`kcp`),
`transport_e2e_quic.rs` and `v2_quic_r2r.rs` (`quic`), `vhost_h2c.rs` and the
pair this change gated, `http_plugin.rs` and `http_plugin_ping.rs`
(`http-proxy`). `cargo test
-p frp-server --no-default-features --test <t> -- --list` reports 0 tests for
each of the nine. The same escape exists item-by-item inside a target that does
compile: `vhost_audit_fixes.rs` declares 21 tests, 2 of them `tls`-gated per
item, so 19 are compiled and checked and those 2 are not. `mock_oidc.rs` also
reports 0 tests but is not one of the nine: it has no inner `#[cfg]`, so it is
not whole-file-cfg'd empty — it is compiled as its own test target and simply
declares no tests.

What it does **not** prove, and why it is still meaningful: `frp-core` in that
graph is compiled with *most* of its features, not with them off.
`frp-server`'s dev-dependency on `frp-client` (default features,
`frp-server/Cargo.toml`) pulls `frp-client`'s `default` set in, and that
forwards `frp-core/websocket`, `frp-core/tls`, and the rest — measured,
`frp-core`'s enabled set in that graph is exactly

```
chacha20 compression http-client kcp oidc quic stun tcp-mux tls websocket
```

ten features; six further features are off (`vnet`, `admin-auth`,
`mem-profile`, `profiling`, `debug-logs`, `otel`), `default` aside — `default`
itself is not activated either, since both `frp-server` and `frp-client` depend
on `frp-core` with `default-features = false`. So `frp-core` can hand
`frp-server` a type, variant or function that frp-server's matching feature does
not know about. That mismatch is exactly what this step exercises:
`ConnectionType::WebSocket` exists in `frp-core` regardless of frp-server's
feature set (it is deliberately **not** feature-gated — see the doc comment on
the variant in `frp-core/src/transport/mod.rs`), so
`frp-server/src/service.rs`'s `match` has an unconditional arm whose body is
gated per feature. Before that fix the run failed with `error[E0004]` —
non-exhaustive patterns, `ConnectionType::WebSocket` not covered.

Why this broke on `websocket` and not on the other nine features `frp-core` has
on: `websocket` is the only `frp-core` feature that gated a variant of
`ConnectionType` — before this change the `WebSocket` variant was the only
`#[cfg]`-gated item inside that enum. The other features on in this graph
(`tls`, `kcp`, `quic`, `oidc`, `compression`, `chacha20`, `tcp-mux`,
`http-client`, `stun`) disagree with frp-server's empty set just as much, but
none of them changes the shape of `ConnectionType`, so none of them can make a
`match` **on `ConnectionType`** non-exhaustive. That is why the fix belongs on
the type — the variant now always exists, so exhaustiveness of `ConnectionType`
matches no longer depends on the two crates' feature sets agreeing.

**That guarantee is scoped to `ConnectionType` and is not a systematic property
of the workspace.** `oidc` — one of the nine features named just above — has a
live sibling of exactly this class: `AuthMethod::Oidc` is gated in `frp-core`
and matched in `frp-server`, so
`cargo check -p frp-server --no-default-features --features dashboard --all-targets`
still fails with `E0004` at `frp-server/src/dashboard.rs:2344`. [`../TODO.md`](../TODO.md)
records it; the fix here was per-variant, not a guarantee that no other
feature-gated variant exists.

The step therefore checks frp-server's **own** gates, not frp-core's: a missing
`#[cfg(feature = "tls")]` on a tls-only item in frp-server is caught, while
frp-core's feature-off configuration is not compiled by this step at all (the
`-p frp-core` step above is what covers frp-core's test targets with its own
features off; the two `--workspace` tier checks cover frp-core's lib and the
tier binaries in a genuinely small graph). The two TLS-driving cases in
`frp-server/tests/vhost_audit_fixes.rs`
and the whole of `frp-server/tests/vhost_h2c.rs` carry `#[cfg(feature = "tls")]`
/ `#![cfg(feature = "http-proxy")]` respectively, so the rest of the first file
stays compiled — and therefore checked — with `tls` off; the `tls`-on path of
all of them is compiled by the `Lint` lane's `--all-targets --all-features`
clippy. `frp-server`'s tier library graph is also covered by the two workspace
checks above.

### Feature Flags

The authoritative flag table — every feature, the crate it belongs to, what it
removes, which are default-ON, and which are opt-in/dev-only — is
[**CLAUDE.md § Binary Variants**](../CLAUDE.md#binary-variants). It is not
duplicated here.

Which crates are vendored (and why, and when each can be dropped) is in
[**README § Vendored crates**](../README.md#vendored-crates).

### Release Profile

```toml
# Cargo.toml
[profile.release]
opt-level = "z"       # Optimize for size
lto = "fat"           # Link-time optimization across all crates
codegen-units = 1     # Single codegen unit for better optimization
strip = "symbols"     # Strip debug symbols
panic = "abort"       # Abort on panic (smaller binary, no unwind tables)
```

After `cargo build --release`, further compress with UPX:

```bash
upx --best --lzma target/release/frps target/release/frpc
```

## 4. Debugging

### RUST_LOG Levels

The project uses `tracing` for structured logging. Available levels: `error`, `warn`, `info`, `debug`, `trace`.

```bash
# Debug logging for everything
RUST_LOG=debug cargo run --bin frps -- -c frps.toml

# Target-specific logging
RUST_LOG=frp_server::control=debug cargo run --bin frps -- -c frps.toml

# Trace-level for wire protocol inspection
RUST_LOG=frp_core::protocol=trace cargo run --bin frps -- -c frps.toml

# Multiple targets
RUST_LOG=frp_server=debug,frp_core::protocol=trace cargo run --bin frps -- -c frps.toml
```

Key tracing targets:
- `frp_core::protocol` -- V1 frame writes (`trace` level includes full JSON payloads)
- `frp_server::service` -- connection accept, TLS handshake, dispatch
- `frp_server::control` -- control handler lifecycle, internal message routing, heartbeat
- `frp_server::control::bridge` -- work connection bridging
- `frp_core::transport` -- connection type detection, magic byte stripping
- `frp_server::nathole` -- NAT hole punch session lifecycle
- `frp_client::service` -- client lifecycle, proxy registration
- `frp_client::work_conn` -- work connection management

### Inspecting Wire Protocol

Enable trace-level logging for `frp_core::protocol` to see every frame sent and received:

```bash
RUST_LOG=frp_core::protocol=trace cargo run --bin frps -- -c frps.toml
```

This outputs the type byte, payload length, and full JSON content for each V1 frame. For hex dumps of the raw bytes, use an external tool like `tcpdump` or `wireshark`:

```bash
# Capture frp traffic on loopback
sudo tcpdump -i lo -A -s 0 port 7000

# Capture with hex dump
sudo tcpdump -i lo -X -s 0 port 7000
```

### Common Issues

**"Connection reset by peer" on startup:**
- Check that `bind_port` is not already in use
- Verify the server and client `token` match
- Check that `server_addr` is reachable from the client

**Proxy connections time out:**
- Check `heartbeat_timeout` -- client must ping within this interval
- Check `pool_count` -- if too low, proxy connections queue and expire after 10s
- Verify firewall allows traffic on proxy ports

**Enrypted bridge corruption:**
- Both sides must agree on `use_encryption` and `use_compression`
- The encryption key derives from the auth token -- mismatched tokens = corrupted bridge

**TLS handshake failures:**
- TLS requires valid cert/key files (`tls_cert_file`, `tls_key_file`)
- When `tls_only` is true, non-TLS connections are rejected
- WebSocket over TLS requires the client to connect with `wss://` and `transport_protocol = "wss"`

**XTCP hole punch failures:**
- Both provider and visitor need public internet access for STUN
- Symmetric NAT on both sides usually prevents hole punching -- STCP fallback is needed
- Check that `sk` is set and identical on both provider and visitor proxies

## 5. Testing

### What a green test run does and does not prove

Read this before quoting a test count as evidence of compatibility. It is the
single easiest mistake to make in this repository.

**Hard evidence — these compare frp-rs against a real Go frp binary:**

| Gate | What it establishes |
|---|---|
| `scripts/compat-test.sh` — 86 scenarios + 17 XTCP pairwise, vs Go frp v0.71.0 | Wire and behavioural parity with the reference implementation |
| `scripts/protocol-matrix.sh` — 11 transport rows | Data actually moves through frps+frpc for every transport / encryption / mux combination |
| Daily `xtcp-compat.yml` on a VPS | XTCP hole punching against Go frpc across a real NAT |

Every count in that table is re-measured from the scripts by `bash
scripts/repo-health.sh` (it prints each claim next to the source that produces
it) — the figures are cross-checked, not remembered.

**Proxy evidence — the unit and integration tests (`repo-health.sh` counts the
in-tree test functions; the number that *pass* is a runtime fact):**

They pin *frp-rs's own* behaviour. That is genuinely valuable (they catch
regressions, and most were written by reading Go's source), but a passing suite
does **not** establish Go parity, because a test encodes the author's *model* of
Go's behaviour — and that model can be wrong.

This is not hypothetical. The project's own history records it, repeatedly:

- **Round 4**: "the slowloris ponging test was RED — the round-3 claim was
  wrong". The test assumed yamux's ping frame tag was `4`; it is `2`. A whole
  round's confidence rested on a test that was failing.
- **Round 16**: the round-15 suite "encoded a **FALSE `SplitHostPort` claim**".
  All three oracles in `vhost.rs` and `vhost_h2c.rs` had to be flipped once Go's
  `net/ipsock.go:216` was actually read.
- **Round 16**: "two round-14/15-era tests that pinned the trim behaviour [were]
  flipped".
- **Round 6**: a stale pin in `server_protocol.rs:81` — a target-only test run
  was blind to the integration file that held the real expectation.
- **Round 7**: a round-9-era "established reject policy" pin turned out to rest
  on a false premise; the expectation was flipped after probing the real
  Go 1.25.12 binary.
- **Round 9** returned a verdict of "production code healthy, **test
  completeness below standard**" while **1253 tests were green**.
- **Round 9** also surfaced that the shared test fixture kept
  `authentication_timeout = 0`, so replay protection — the thing under test —
  was never exercised at all.

**A caveat about the hard evidence itself.** The compat gate is the strongest
evidence available here, but it is not perfectly reliable *as a signal*: on
2026-09-17 the `compat` CI job failed **2 of 3 consecutive runs on the same
commit**, with **different** scenarios each time (`go-to-rust-quic:
FAIL:CONNECT_TIMEOUT`, then `tcp-tls`/`tcp-tls-mux` zero throughput and `ws-plain`
proxy port unreachable), and passed on the third. The diff under test could not
have been responsible — its only compiled change was inside a
`#[cfg(not(target_os = "linux"))]` block, absent from Linux CI entirely.

So: a **red** compat run should be re-run before it is believed, and a **green**
one is strong but not absolute. Flakiness in the one gate the project treats as
authoritative is a defect in its own right — see [`../TODO.md`](../TODO.md).
A flaky test is a bug in the test's timing assumptions, not a re-run button:
fix it (per-invocation names, a retry bounded to the specific transient, the
original assertion kept) instead of learning to ignore it.

**The practical rules:**

1. A green suite means "no *known* regression", not "compatible with Go frp".
2. Before claiming a compatibility fix, cite Go source (`file:line`) or a probe
   of the real binary — not a passing test.
3. When a test expectation is the *only* thing asserting a behaviour, say so.
   That is a hypothesis, not evidence.
4. For a parity claim, prefer adding a `compat-test.sh` scenario over another
   unit test.

### Unit Tests

Unit tests live inline in `#[cfg(test)] mod tests` blocks within source files. Integration tests live in the `frp-server/tests/` and `frp-client/tests/` directories (see "Writing New Tests" below).

```bash
# Run all tests
cargo test --workspace

# Run tests for a specific crate
cargo test -p frp-core
cargo test -p frp-server
cargo test -p frp-client

# Run a specific test by name
cargo test -p frp-core -- protocol::tests

# Run with output (show println! and tracing)
cargo test -- --nocapture

# Run ignored tests (e.g., tests requiring network access)
cargo test -- --ignored
```

### Cross-Compatibility Tests

The compat test suite verifies Go frp <-> Rust frp interop across all proxy types and transport protocols:

```bash
# Full suite (86 run_test scenarios, 7 of which are gated on Go frp V2)
bash scripts/compat-test.sh --verbose

# Filter by proxy type and direction
bash scripts/compat-test.sh tcp g2r     # TCP proxy, Go client -> Rust server
bash scripts/compat-test.sh xtcp        # All XTCP tests
bash scripts/compat-test.sh transport   # Transport protocol tests only

# Filter by direction
bash scripts/compat-test.sh g2r         # All Go->Rust tests
bash scripts/compat-test.sh r2g         # All Rust->Go tests
```

The compat tests require Go frp binaries. Download them first:

```bash
bash scripts/download-go-frp.sh
```

This downloads Go frp v0.71.0 binaries to `/tmp/frp_<version>_<os>_<arch>/` (for
example `/tmp/frp_0.71.0_linux_amd64/`) — that is where `compat-test.sh` looks for
them. Override the location with `GO_FRP_DIR=/path/to/dir`. The CI gate is
`.github/workflows/compat.yml`.

> Do **not** commit the downloaded Go binaries. They are platform- and
> version-specific and a stale copy is worse than none: `scripts/go-frp/` used to
> hold v0.69.1 macOS x86_64 binaries while the project targeted v0.71.0, and any
> size/memory comparison against them was meaningless. (For scale, the v0.71.0 Go
> binaries measured 17.7 MB (`frps`) / 14.2 MB (`frpc`) — see the generated table
> in [`../README.md`](../README.md#technical-differences-vs-go-frp), reproduced by
> `scripts/compare-go-frp.sh`.) Use
> [`scripts/compare-go-frp.sh`](../scripts/compare-go-frp.sh), which verifies
> platform and version before it compares anything.

### XTCP CI Tests

XTCP tests require public internet (for STUN) and run on a VPS:

```bash
# Setup VPS (one-time)
bash scripts/vps-setup.sh

# Run XTCP tests on VPS
bash scripts/remote-frps.sh xtcp
```

XTCP CI uses sharded matrix jobs (`.github/workflows/xtcp-compat.yml`) with per-shard directories for isolation. 17 tests covering the 2x2 implementation matrix (Go/Rust server × Go/Rust client) plus QUIC-data-plane and encrypted variants.

### Writing New Tests

Follow these conventions:

1. **Inline tests**: add to the relevant source file's `#[cfg(test)] mod tests`
2. **Integration tests**: add to `frp-server/tests/` or `frp-client/tests/`
3. **Use `test_utils`**: each crate may provide test helpers for spawning servers/clients
4. **Avoid port conflicts**: use port `0` for auto-allocation or pick unique ports
5. **Clean up**: ensure spawned tasks/processes are killed on test completion
6. **Wait on a deadline, not an attempt count**: a readiness/retry loop should poll against a wall-clock deadline (`Instant::now() + timeout`) rather than a fixed `for _ in 0..N` plus sleep — the attempt count is a hidden, load-dependent time budget that flakes on CI — and it must report the last error on exhaustion, not a bare `expect`.

### Benchmarks

Criterion micro-benchmarks in `frp-core/benches/crypto_bridge.rs` (8 groups) and `frp-server/benches/nathole.rs` (2 groups):

```bash
# Run all benchmarks (slow — runs each bench many times)
cargo bench -p frp-core
cargo bench -p frp-server

# Quick compile-time check (used in CI)
cargo bench --workspace --no-run

# Run specific groups
cargo bench -p frp-core -- protocol_all_types
cargo bench -p frp-core -- bridge
cargo bench -p frp-server -- nat_analysis
```

CI gate: `cargo bench --workspace --no-run` in `.github/workflows/ci.yml` ensures benchmarks don't bit-rot.

### Stress Tests

Long-running load test (`scripts/stress-test.sh`) that runs frps + frpc under connection churn:

```bash
bash scripts/stress-test.sh
```

Monitors memory, connection counts, and throughput. Runs weekly in CI via `.github/workflows/stress-test.yml`. The `scripts/frp-stress/` crate contains the load generator (not part of the main workspace).

### Property & Fuzz Tests

Proptest-based tests verify correctness under adversarial inputs:
- **Config normalization** (`frp-core/src/config/tests.rs`): proptest blocks covering idempotency, flat↔nested equivalence, camelCase→snake_case
- **Protocol fuzzing** (`frp-core/src/protocol.rs`): all 256 V1 type bytes × arbitrary payloads, V2 arbitrary type IDs, truncated frames, magic detection

> Raw test counts are deliberately **not** curated: adding a test would otherwise
> fail the `health` job, and the workspace total was observed to differ between
> environments on the *same* tree (215/2069 locally vs 216/2071 in CI, PR #353 —
> cause not established). The `Tests` section of `bash scripts/repo-health.sh`
> prints `test functions`, `files with tests`, `frp-server/tests` and
> `proptest blocks`; per-file counts are read from the tree when needed. Fuzz
> *targets* are not curated either — a text grep cannot tell a live target from
> a `#[cfg]`-disabled one — so their count and enablement are covered by the test
> suite, not by the gate.

### CLI exit codes (`frpc` / `frps`)

The CLI contract is Go's **on the config/flag-failure surface**: exit 0 on
success, exit 1 on a failure the command detects and reports through its own
error path. The qualifiers are measured and listed below, not rhetorical — Go
itself exits 2 when frps panics on an oidc config with no issuer, and it does not
exit at all on a tokenless token config (it starts and runs), while frp-rs keeps
three codes of its own (`2`/`3`/`4`): `2` only for a `--config-dir` refusal
(a surface Go answers with 0, or has no flag for at all), and `3`/`4` for
service-construction failures — including some like `auth.tokenSource` and
`[store]` that Go *has* and refuses with 1, and some like the empty-token check
that Go does not refuse at all. There is no per-class scheme to preserve, and
`EXIT_CONFIG`/2 no longer covers a single-config or `verify` failure.

Measured 2026-09-26 against Go frp **v0.71.0** (darwin/arm64) and the frp-rs
`frpc`/`frps` binaries, with one unknown top-level key added to an otherwise
valid config (plus the variations named):

| command | Go v0.71.0 | frp-rs (now) |
|---|---|---|
| `frpc -c bad.toml` (unknown key) | 1 | 1 |
| `frpc -c missing.toml` / `-c <dir>` / `-c badport.toml` | 1 | 1 |
| `frpc --strict-config=foo -c good.toml` | 1 | 1 (message differs) |
| `frpc verify -c bad.toml` (and missing / bad port) | 1 | 1 |
| `frpc verify -c good.toml` | 0 | 0 |
| `frpc reload\|status\|stop -c bad.toml` | 1 | 1 |
| `frps -c badfrps.toml` (and missing / dir / bad port) | 1 | 1 |
| `frpc` with `[auth] tokenSource` → a missing file | 1 (0.26 s) | **3** (0.25 s) — extension |
| `frps` with `[auth] tokenSource` → a missing file | 1 (0.26 s) | **3** (0.25 s) — extension |
| `frpc` with `[store] path` → a file that is not JSON | 1 (0.26 s) | **4** (0.25 s) — extension |
| `frpc --config-dir <nonexistent\|empty\|bad>` | **0** | **2** (deliberate) |
| `frpc --config-dir <good>`, service cannot run | 0 (0.026 s) | 0 (0.026 s) |
| `frps --config-dir <…>` | 1 — `unknown flag: --config-dir` | 2 (extension flag) |
| `frpc -c empty.toml` (defaults only, peer accepts and never answers) | 1 after 10.04 s | 1 after 30.07 s |
| the same, with the port genuinely refusing | 1 after 0.026 s | 1 after 0.023 s |
| `frps` on an occupied `bindPort`, `auth.token` set | 1 | 1 |

The good-directory row is deliberately qualified: a directory whose service
actually *runs* is long-running on both sides and has no natural exit code, so a
`0` obtained by signalling a live process must never be recorded here. The `0`
above is measured for the case where the service cannot run (the example config
points at a closed port: both exit in 0.026 s, Go after
`connect to server error`, frp-rs after `frpc service error for config file
[...]`), and it is the only directory-mode `0` this table asserts. The same
`--config-dir` shape pointed at a peer that accepts TCP and never answers also
returns **0** on both sides, but slowly: re-measured with the directory's config
dialling `127.0.0.1:7000` (macOS Control Center accepts and stays silent) →
**Go 0 at 10.06 s, frp-rs 0 at 30.06 s**, twice each. Those are the same
timeouts as the `empty.toml` row, not the ~0.03 s of the refused case.

The `frpc -c empty.toml` rows exist because the durations are **peer-dependent,
not a bound**. The default empty config dials `127.0.0.1:7000`; on the host these
were measured on, macOS Control Center *accepts* that port and never speaks frp,
so the timeout is what is being measured (10.04 s / 30.07 s, Go then frp-rs).
With a port that genuinely refuses, the same shape returns in ~0.02 s on both
sides. That case is a *runtime* stop, not a config-parse failure — the exit code
is 1 on both sides, which is what the row is for.

Some things this table does not say, each measured:

- **Directory mode is a deliberate divergence, not an oversight.** Go's
  `frpc --config-dir` returns **0** for a directory that does not exist, is
  empty, *or holds a config that fails to parse* — the bad case prints only
  `frpc service error for config file […]` and exits 0. A config that was never
  loaded is not a success, so frp-rs keeps its pre-existing non-zero refusal
  (`EXIT_CONFIG`/2) on that path. Go `frps` has no `--config-dir` flag at all
  (`Error: unknown flag: --config-dir`, exit 1); frp-rs's is an extension.
- **`EXIT_AUTH`/3 is an extension, and its documented example is
  `auth.tokenSource`.** Worst measured case: a `tokenSource` whose file does not
  exist exits **3** on both binaries, where Go exits **1** immediately
  (`failed to resolve auth.tokenSource: failed to read file …`). A rejected
  login is *not* an example: it leaves the client through `service.run()` and
  exits **1**, matching Go.
- **`EXIT_BIND`/4 is not specifically a bind error** — it is the daemons'
  fallback for *any* service-construction error whose text lacks `token`/`auth`
  (`frpc/src/main.rs`'s init-error arm). Measured input: **`frpc`** with
  `[store] path` pointing at a file that is not JSON exits **4**, where Go exits
  **1** (`failed to create store source: … failed to parse JSON: …`). It is an
  frpc example on purpose: `[store]` is not a key Go's *frps* accepts
  (`json: unknown field "store"`), and on frp-rs frps the same key is also an
  unknown-field error, both rc 1. A real port conflict does *not* take this arm —
  `frps` on an occupied `bindPort` returns 1 on both sides, because the listener
  binds inside `service.run()`. Both codes are tracked in `TODO.md`;
  `frpc/tests/cli_exit_codes.rs` pins the two measured inputs.
- **Both codes 3 and 4 are picked by a substring match on the whole error text**
  (`is_token_error` → `msg.contains("token") || msg.contains("auth")`,
  `frp-core/src/logging.rs`), and that text embeds the config path and any URL
  in it — so the *same* failure can land on different codes. Measured: the same
  malformed-`[store]` failure exits **3** when the file is named
  `authstore.json` and **4** when it is `plainstore.json`. The pins in
  `frpc/tests/cli_exit_codes.rs` use an auth-free filename (`badstore.json`), so
  they cannot catch that flip; the substring coupling is tracked in `TODO.md`.
- **Three inputs where the two binaries disagree without a like-for-like exit
  code** — one where frp-rs refuses and Go does not, one where Go crashes on a
  code frp-rs handles, and one the other way round:
  - `frps` with `[auth] method = "token"` and an empty `token`: frp-rs exits
    **3** in ~0.01 s (`security misconfiguration: CRITICAL: [auth].token …
    server would accept ALL connections`); Go **starts and keeps running**
    (`frps started successfully`, still alive after 6 s), because it has no such
    check. This is a hardening divergence, not the same failure with another
    code — do not describe it as "Go exits 1 here". Go exits 1 on that config
    only when the port is *held*, which is the occupied-`bindPort` row above.
  - `frps -c <[auth] method = "oidc"` with no issuer>`: frp-rs refuses with
    **3**; Go **panics** (`panic: Get "/.well-known/openid-configuration":
    unsupported protocol scheme ""`) and its runtime exits **2** — a code frp-rs
    uses only for a `--config-dir` refusal, never for a service-construction
    failure. Go does exit here, so this bullet is *not* a
    "refuses-where-Go-does-not" case. That panic is also why no blanket statement
    like "Go only ever returns 0 or 1" belongs in this document.
  - `frpc verify -c <config whose [[proxies]] block has an unknown key>`: frp-rs
    reports `Config file … is valid` and exits **0** while Go exits **1**
    (`decode proxy at index 0: … unknown field "notAKnownProxyKey"`). The
    disagreement runs the *other* way — frp-rs accepts what Go refuses. Tracked
    at `TODO.md:1168` (#375), not changed here.

Tests that pin this — real binaries, no mocks:
`frpc/tests/cli_exit_codes.rs` (`frpc -c <bad>` start, `verify -c <bad>`,
`verify -c <missing>`, a `verify -c <good>` positive control, the directory-mode
divergence for a missing / empty / invalid directory, the `tokenSource` → 3 case,
the `[store]` → 4 case, and — under `--features tiny` — the same two assertions
against `frpc-tiny`) and `frps/tests/cli_exit_codes.rs` (`frps -c <bad>`,
`-c <missing>`, a starts-then-SIGTERM positive control, and the extension flag's
refusal). The admin-subcommand refusals stay pinned by
`frpc/tests/admin_cli.rs`, and the repeated-`-c` / empty-`addr` inputs by
`frpc/tests/cli_inputs.rs`. Executing lanes: `Run frpc CLI tests`, `Run frps CLI
tests` and `Run frpc's CLI exit-code tests under tiny` in `.github/workflows/ci.yml`
(the `frps` lane and the `tiny` lane were added with these tests — nothing ran a
`cargo test` target of the `frps` package, or executed the `tiny` CLI binary,
before them).

Still divergent, and **not** covered by those tests: the *shape* of the output.
Go prints one bare parse error to **stdout** and nothing else; the frp-rs daemon
prints an ANSI-coloured `tracing` line on stdout, and `frpc verify` prints its
message to **stderr** where Go uses stdout. Only the exit code is pinned.

#### CLI inputs: repeated `-c`, an empty `webServer.addr`, case-insensitive keys

Three `frpc` inputs Go accepts and frp-rs used to refuse (`TODO.md:1632`). Two
are now Go-faithful; the third is a **recorded divergence**, because the honest
fix is not bounded and a partial one would be a false claim of parity. Measured
2026-09-26 against Go frp **v0.71.0** (darwin/arm64) and the frp-rs `frpc` at
this branch's head.

**1. A repeated `-c`/`--config` is last-wins — now matched.** Go registers `-c`
with pflag `StringVarP` in a package-level initializer (`cmd/frpc/sub/root.go`),
so each occurrence overwrites the last and repetition is never an error. frp-rs's
bpaf parser exited before loading anything with
``argument `-c` cannot be used multiple times in this context``. Every frpc
config argument now goes through `config_arg()` (`frp-core/src/cli.rs`), which is
`.last()` — bpaf's contradicting-options combinator — wrapped in the same
`fallback`/`optional` each command already had. Measured, both binaries:

| command | Go v0.71.0 | frp-rs (now) | frp-rs (before) |
|---|---|---|---|
| `frpc status -c noweb.toml -c p7499.toml` | dials `127.0.0.1:7499` | dials `127.0.0.1:7499` | rc 1, ``argument `-c` cannot be used multiple times`` |
| `frpc reload \| stop -c noweb.toml -c p7499.toml` | dials `7499` | dials `7499` | same refusal |
| `frpc status -c p7499.toml -c noweb.toml` | `web server port should be set …` | same sentence | same refusal |
| `frpc verify -c noweb.toml -c p7499.toml` | `syntax is ok` for `p7499.toml` | `Config file …/p7499.toml is valid` | same refusal |
| `frpc status --config p7499.toml -c p7498.toml` | dials `7498` | dials `7498` | same refusal |
| `frpc status -cp7498.toml` / `-c=p7498.toml` | dials `7498` | dials `7498` | dials `7498` (bpaf already accepted both) |
| `frpc status -c p7498.toml -c` (dangling) | `Error: flag needs an argument: 'c' in -c` | ``Error: `-c` requires an argument `FILE` `` | same refusal |
| `frpc status -c ""` | rc 1, `open : no such file or directory` | rc 1, `: failed to read config file: …` | same (message shape differs; see the output-shape note above) |

The last two rows are the guard rails: an empty value stays a value (no fallback
to the `127.0.0.1:7400` default) and a dangling occurrence is still an error, not
a reused previous value. Pinned by `frpc/tests/cli_inputs.rs` and the
parser-level tests in `frp-core/src/cli.rs`. `frps` is unchanged — a separate
surface, not part of that item.

Three argv shapes around that change are **still divergent**, all measured on the
same pair of configs and all one underlying rule — bpaf will not take a
`-`-prefixed token as `-c`'s value, and the admin subcommands define no
`--config-dir`:

Every Go cell below ends rc 1 **because nothing is listening** on the port the
command resolves to (the connection refusal); with a mock answering, the same
argv exits 0. What the cells pin is *which port* Go resolved, so a reader running
a listener should expect 0, not a contradiction:

| argv | Go v0.71.0 (no listener) | frp-rs |
|---|---|---|
| `frpc status -c --strict-config=false -c p7498.toml` | rc 1, dials `7498` — Go consumes `--strict-config=false` **as `-c`'s value** (measured: `frpc status -c --strict-config=false` alone is `open --strict-config=false: no such file or directory`, and had it been parsed as the flag the first `-c` would have dangled), then the later `-c p7498.toml` overwrites it | rc 1, ``-c` requires an argument `FILE`` |
| `frpc status -c p7498.toml -- -c p7499.toml` | rc 1, dials `7498` (flags after `--` are positional) | rc 1, `` `-c` is not expected in this context`` |
| `frpc status -c p7498.toml --config-dir cDir` | rc 1, dials `7498` (`--config-dir` exists on the root command) | rc 1, `` `--config-dir` is not expected in this context`` |

They are recorded with the single-proxy `-c` item in `TODO.md` rather than fixed
here: the first two are the same "what may follow `-c`" question, and the third
is "which persistent root flags each subparser declares".

**2. An empty `webServer.addr` is completed to `127.0.0.1` — now matched, and
only the empty string.** Go's `ClientCommonConfig.Complete()` calls
`c.WebServer.Complete()` (`pkg/config/v1/client.go:96`), which is
`c.Addr = util.EmptyOr(c.Addr, "127.0.0.1")` (`pkg/config/v1/common.go:71-73`).
frp-rs's serde field default only fires when the key is **absent**, so an explicit
`addr = ""` survived and every dial became a lookup of the empty host. Measured
with `[webServer] port = 7499` and the `addr` varied:

| `addr` | Go v0.71.0 | frp-rs (now) | frp-rs (before) |
|---|---|---|---|
| `""` | dials `127.0.0.1:7499` | dials `127.0.0.1:7499` | `connect :7499: failed to lookup address information` |
| `" "` | rc 1, `parse "http:// :7499/api/status": invalid character " " in host name` | rc 1, the whitespace host reaches the dialer | same |
| `"0.0.0.0"` | dials `0.0.0.0:7499` | literal | literal |
| `"::1"` | dials `[::1]:7499` | literal | literal |
| `"localhost"` | dials `[::1]:7499` (dialer resolution) | dialer resolution | dialer resolution |

The rule mirrored is exactly Go's: **the empty string becomes `127.0.0.1`;
anything else is used verbatim** — no trimming, no whitespace special case. The
completion lives in `ClientConfig::complete_with_heartbeat_set`
(`frp-core/src/config/client.rs`), the same load/complete boundary the item
names, so it applies to the admin subcommands *and* to the client's own
`[webServer]` admin listener. Pinned by `frpc/tests/cli_inputs.rs` (empty,
whitespace and no-`[webServer]` shapes) plus `frp-core/src/config/tests.rs`.

**The server side is *not* matched, and an earlier draft of this section claimed
it was.** Go's `ServerConfig.Complete()` calls `c.WebServer.Complete()`
(`pkg/config/v1/server.go:107`) — the same `EmptyOr(Addr, "127.0.0.1")` as the
client — *before* the `if c.WebServer.Port > 0 { c.WebServer.Addr =
util.EmptyOr(c.WebServer.Addr, "0.0.0.0") }` branch at `:116-118`, so that
branch is dead and an empty `addr` with a set port stays loopback. Measured with
`[webServer] addr = "" port = 7597 user/password`: Go frps logs
`dashboard listen on 127.0.0.1:7597` and listens on `127.0.0.1:7597`, while
frp-rs (`--features dashboard`) logs `Dashboard listening on 0.0.0.0:7597` and
listens on `*:7597`. `frp-core/src/config/server.rs` defaults the address to
`0.0.0.0` when the port is set, which is the second half of the two-step
without the first. The server keeps its behaviour here (this item is
frpc-scoped); the divergence is pinned by a test and tracked in `TODO.md`.

**3. Config keys are matched case-sensitively — a recorded divergence, not
parity.** Go decodes with `encoding/json`, whose matching is case-insensitive
for **field and table names at every level**, including inside array items. That
is a property of the decoder, not of one struct, so it cannot be closed with a
bounded set of `#[serde(alias)]`: serde's aliases are exact strings, and a
complete fix means either per-field aliases for every case permutation across
the whole config tree or a canonicalising pre-pass in front of
`serde_json::from_value`.

Measured against Go v0.71.0, cell by cell, with the exact configs named. `verify`
and `status` differ on the same file — `verify` parses and reports, while
`status` also has to resolve an admin address, which is where a dropped
`[webServer] port` turns into Go's refusal sentence:

| config | command | Go v0.71.0 | frp-rs strict | frp-rs `--strict-config=false` |
|---|---|---|---|---|
| `cap-top.toml` = `ServerAddr`/`ServerPort` | `verify -c …` | rc 0, `syntax is ok` | rc 1, `unknown field "ServerAddr" … did you mean 'serverAddr'?` | rc 0, `is valid` |
| the same | `status -c …` | rc 1, `web server port should be set …` | rc 1, the unknown-field error | rc 1, the same Go sentence |
| `caps-all.toml` = `SERVERADDR`/`SERVERPORT` | `verify -c …` | rc 0 | rc 1, `unknown field "SERVERADDR"` (no suggestion — distance > 3) | rc 0 |
| `caps-web.toml` = `ServerAddr`/`ServerPort` + `[webServer] port = 7499` | `status -c …` | rc 1, dials `127.0.0.1:7499` | rc 1, the unknown-field error | **rc 1, dials `127.0.0.1:7499`** |
| `port-only.toml` = `[webServer] Port = 7499` | `status -c …` | rc 1, dials `7499` | rc 1, `unknown field "web_server.Port" … did you mean 'port'?` | rc 1, `web server port should be set …` |
| `section-only.toml` = `[WebServer] port = 7499` | `status -c …` | rc 1, dials `7499` | rc 1, `unknown field "WebServer" … did you mean 'webServer'?` | rc 1, `web server port should be set …` |
| `cap-proxy.toml` = `[[proxies]] name/type` + `LocalPort`/`RemotePort` | `verify -c …` | rc 0 (Go's loader reads the keys) | **rc 0 — the keys are silently dropped, no unknown-field error** | rc 0 |

The last row is the sharp edge and the reason the earlier "refused (strict) or
silently mis-defaulted (lenient)" phrasing was wrong in **both** directions:

- **Strict mode does not refuse everywhere: it walks only the tables it has a
  key list for.** `section_known_keys`
  (`frp-core/src/config/strict.rs:277-285`) has nine arms, plus the top level
  that `check_strict` is entered with. Each is listed here with a capitalised
  nested key measured as refused at the head: the top level (`"ServerAddr"`),
  then the nine arms — `[auth]` (`"auth.Token"`), `[log]` (`"log.Level"`),
  `[webServer]` (`"web_server.Port"`), `[transport]` (`"TcpMux"`), `[quic]`
  (`"quic.MaxIdleTimeout"`), `[observability]` (`"observability.OtlpEndpoint"`),
  `[store]` (`"store.Path"`), `[virtual_net]` (`"virtual_net.Address"`) and the
  server-only `[sshTunnelGateway]` (`"ssh_tunnel_gateway.BindPort"`; the client
  side has no such table). Three categories fall outside the walked set (the top
  level plus those nine arms) and are **dropped silently even in strict mode**,
  with `frpc verify` exiting 0:
  - **array elements** — `[[proxies]]`/`[[visitors]]` (and the server's
    `[[httpPlugins]]`). Stated in
    [§ Deployment § Dashboard Web UI](deployment.md#dashboard-web-ui), lines
    710-747, which also carry the end-to-end consequence: the same config makes
    Go frpc bind the configured port while frp-rs registers `remote_port: 0` and
    frps auto-allocates one. Pinned (with the value) by
    `case_insensitive_proxy_array_key_is_dropped_in_strict_mode` and
    `strict_mode_exempts_proxy_and_visitor_array_elements` in
    `frp-core/src/config/tests.rs`, and at the CLI level by
    `case_insensitive_proxy_array_keys_are_dropped_in_strict_mode` in
    `frpc/tests/cli_inputs.rs`.
  - **a table alias the normalizer leaves alone** — `check_strict` looks up the
    section by the spelling it sees, so a camelCase alias survives (no key list)
    and is not descended into. Measured with `[virtualNet] Address =
    "10.1.0.0/24"` (no array anywhere): Go `verify -c` fails with
    `VirtualNet feature is not enabled; enable it by setting the appropriate
    feature gate flag`, while frp-rs prints `is valid` and exits 0, the load
    returns `Ok`, and `virtual_net.address` is `""` — the dropped key even
    **hides** the feature-gate refusal. The canonical `[virtual_net] Address` IS
    refused (`unknown field "virtual_net.Address" … did you mean 'address'?`)
    and `[virtualNet] address` IS read, so this is specifically the alias arm;
    `normalize_client_config` canonicalises `webServer`/`featureGates`/… but not
    `virtualNet`. Pinned by
    `case_insensitive_key_in_a_table_alias_is_dropped_in_strict_mode` in
    `frp-core/src/config/tests.rs`.

  - **a nested table inside a walked section** — the key-list lookup happens for
    the *table being visited*, so a sub-table below a walked section has no list
    of its own and nothing inside it is visited either. Measured with
    `[auth.tokenSource] type = "exec"` +
    `[auth.tokenSource.exec] command = "echo tok"` and a capitalised `Env`:
    frp-rs strict `verify` exits **0** and prints `is valid`, and it does so for
    the correctly-spelled `env` too. frp-rs *does* have the `TokenSourceExec`
    gate (`frp-core/src/unsafe_features.rs:10`, enforced by
    `validate_token_source_unsafe` in `frp-core/src/auth.rs` and called from
    `frp-client/src/service.rs`); it runs at **service start**, not in `verify`'s
    load path, which is why `verify` cannot surface the drop either way —
    measured, `frpc -c <that config>` is rc **3** with
    `auth.tokenSource exec blocked: TokenSourceExec not in UnsafeFeatures
    allowlist. Pass --allow-unsafe TokenSourceExec to enable.`, identical for
    `Env` and `env`. So the drop is visible only at the parsed-value level:
    `env` is read into the token-source struct, `Env` leaves it empty. Go refuses
    both spellings (`unsafe feature "TokenSourceExec" is not enabled …`). Already
    documented in
    [§ Deployment § Dashboard Web UI](deployment.md#dashboard-web-ui), line 719
    (`auth.tokenSource.exec.env` has no key set at `tokenSource`). Pinned by
    `case_insensitive_key_in_a_nested_table_is_dropped_in_strict_mode` in
    `frp-core/src/config/tests.rs`.

  So neither "the walked sections refuse" nor "arrays are dropped" is the whole
  rule: the rule is *a mis-cased key is refused only where strict mode has a key
  list for the table being visited — everywhere else it is dropped silently, and
  the dropped key can change a value or hide a later refusal*.
- **Lenient mode need not end in an error.** With a `[webServer] port` present,
  frp-rs in non-strict mode drops the mis-cased top-level key and then uses the
  defaults — `ServerAddr` becomes `0.0.0.0` and `ServerPort` becomes `7000`
  where Go uses what the file says — and the domain the command is about
  (`status` here) still succeeds on `127.0.0.1:7499`. Whether the load ends in
  an error depends on which key was dropped and what the command needs next: a
  dropped `[webServer] port` surfaces as `web server port should be set …`, a
  dropped `[[proxies]] name` as `missing field \`name\``, and a dropped optional
  key as nothing at all.

Scope of what *is* matched: the exact snake_case names, plus the documented
Go camelCase aliases (`serverAddr`, `serverPort`, `webServer`, `tokenSource`,
`oidcClientId`, …) which serde accepts per struct. What is **not** matched:
arbitrary case variants of any key, at any level, on either frpc or frps. The
practical advice is the same as the README's: use the documented spellings; the
camelCase aliases cover the Go-authored configs. The array-element half is the
`TODO.md:1168` strict-mode item's territory, not this one's.

#### `--strict-config`: the space-separated value form

`--strict-config false` (a space, two argv tokens) is an **frp-rs extension**,
kept, documented and made **loud** rather than dropped (`TODO.md:1613`). Go frp
v0.71.0 registers `strict_config` as a pflag bool on both binaries, and a pflag
bool never consumes a following token — so the same argv behaves differently.
The `=` spelling (`--strict-config=false`) is the **Go-faithful** one and is the
spelling to use when an argv must behave identically under both binaries.

The extension is announced on **stderr**, once, on the path only:

```text
warning: --strict-config <bool> is an frp-rs extension; Go's pflag does not consume the token and stays strict. Use --strict-config=<bool> for identical behaviour.
```

It fires for the space-separated form on all six parsers (`frps`, and `frpc`'s
`run`/`verify`/`reload`/`status`/`stop`) and for nothing else: not the `=` form,
not the bare switch, not an absent flag, and not a non-bool token (there no value
is consumed and the parse fails before the warning point — the entry points print
it only after a successful parse). The reason it exists at all is that the
divergence is otherwise **silent**: `frpc verify --strict-config false -c
<config with an unknown key>` exits **0** where Go exits 1, and the admin
commands dial a config Go would have refused. Documentation alone never surfaces
at the moment it bites.

Measured 2026-09-26 against Go frp **v0.71.0** (darwin/arm64,
`/private/tmp/frp_0.71.0_darwin_arm64/`) and the frp-rs `frpc`/`frps` at this
branch's head. Client config: a valid config plus `notAKnownFrpKey = 1` and
`[webServer] port = 7499`, so "strict" (refuse the unknown key) and "lenient"
(dial `7499`) are distinguishable; a second client config `host.toml` has
`[webServer] addr = "localhost"` and no unknown key; server configs are
`/private/tmp/goprobe/badfrps2.toml` (`bindPort = 7511`, `auth.token`, the same
unknown key) and `/private/tmp/goprobe/goodfrps.toml` (`bindPort = 7513`,
`auth.token`, no unknown key). Every row was run through a bounded runner;
**rc 124 means the process started successfully and was killed by the bound**,
which is how the lenient server rows are recorded. Rows marked *(warns)* print
the stderr line above; every other row is silent.

| argv | Go v0.71.0 | frp-rs |
|---|---|---|
| `frpc reload -c bad.toml` (absent) | rc 1, `json: unknown field "notAKnownFrpKey"` | rc 1, `unknown field "notAKnownFrpKey" in config file …` |
| `frpc reload --strict-config -c bad.toml` (bare) | rc 1, same | rc 1, same |
| `frpc reload --strict_config -c bad.toml` (bare, `_`) | rc 1, same | rc 1, same |
| `frpc reload --strict-config=true -c bad.toml` | rc 1, same | rc 1, same |
| `frpc reload --strict-config=false -c bad.toml` | rc 1, dials `127.0.0.1:7499` | rc 1, dials `127.0.0.1:7499` |
| `frpc reload --strict-config false -c bad.toml` *(warns)* | rc 1, `json: unknown field …`, **no dial** (`false` is a positional) | rc 1, dials `7499` — **extension** |
| `frpc reload --strict-config foo -c bad.toml` | rc 1, `json: unknown field …`; the stray token is ignored and strict stays `true` | rc 1, ``Error: `foo` is not expected in this context`` |
| `frpc reload --strict-config=foo -c bad.toml` | rc 1, `Error: invalid argument "foo" for "--strict-config" flag: strconv.ParseBool: parsing "foo": invalid syntax` | rc 1, ``Error: `foo` is not expected in this context`` |
| `frpc --strict-config false -c bad.toml` (run) *(warns)* | rc 1, `Error: unknown command "false" for "frpc"` (the root command takes no positional) | rc 1, lenient: connects to `127.0.0.1:7500` |
| `frpc --strict-config=false -c bad.toml` (run) | rc 1, lenient: connects to `7500` | rc 1, lenient: connects to `7500` |
| `frpc verify --strict-config false -c bad.toml` *(warns)* | rc 1, `json: unknown field …` | **rc 0**, `Config file … is valid` — **extension** |
| `frpc verify -c bad.toml --strict-config false` *(warns)* | rc 1, `json: unknown field …` — position changes nothing | **rc 0**, `is valid` — **extension** |
| `frpc verify --strict-config=false -c bad.toml` | rc 0, `syntax is ok` | rc 0, `is valid` |
| `frpc status \| stop --strict-config false -c bad.toml` *(warns)* | rc 1, `json: unknown field …`, no dial | rc 1, dials `7499` — **extension** |
| `frpc verify --strict-config "" -c bad.toml` | rc 1, `json: unknown field …` — the empty token is a positional | rc 1, ``Error: `` is not expected in this context`` |
| `frpc verify --strict-config "" -c good.toml` | **rc 0**, `syntax is ok` — positional ignored, config valid | rc 1, ``Error: `` is not expected in this context`` |
| `frpc verify --strict-config= -c bad.toml` | rc 1, `invalid argument "" for "--strict-config" flag: strconv.ParseBool: parsing "": invalid syntax` | rc 1, ``Error: `` is not expected in this context`` |
| `frpc verify --strict-config=true --strict-config=false -c bad.toml` (repeated) | **rc 0**, `syntax is ok` — pflag is last-wins, so lenient | rc 1, ``argument `--strict-config` cannot be used multiple times in this context`` |
| `frpc verify --strict-config=false --strict-config=true -c bad.toml` (repeated) | rc 1, `json: unknown field …` — last-wins, so strict | rc 1, the same repetition refusal |
| `frps --strict-config=false -c badfrps2.toml` | rc 124 — starts (lenient) | rc 124 — starts (lenient) |
| `frps --strict-config false -c badfrps2.toml` *(warns)* | rc 1, `Error: unknown command "false" for "frps"` | rc 124 — starts (lenient) — **extension** |
| `frps verify --strict-config false -c badfrps2.toml` | rc 1, `json: unknown field …` | n/a — frp-rs `frps` has no `verify` subcommand (separate `TODO.md` item) |
| `frps --strict-config foo -c badfrps2.toml` | rc 1, `Error: unknown command "foo" for "frps"` | rc 1, ``Error: `foo` is not expected in this context`` |
| `frps --strict-config=foo -c badfrps2.toml` | rc 1, `invalid argument "foo" … strconv.ParseBool` | rc 1, ``Error: `foo` is not expected in this context`` |

What the table says, precisely:

- **The `=` form is Go-faithful on every parser for a single occurrence** —
  `frps` and `frpc`'s `run`/`verify`/`reload`/`status`/`stop` — for `=true`,
  `=false`, and a bad `=foo` (both exit 1; only the message differs). A
  **repeated** flag is *not* Go-faithful and is not covered by that sentence:
  Go's pflag is last-wins (`=true =false` → rc 0 lenient, the reverse → rc 1
  strict) while frp-rs refuses the repetition outright with rc 1 in both orders.
  The rc agrees on one of those orders and not on the other; the reason differs
  on both.
- **The space form is the only divergence in flag *values*.** frp-rs consumes
  the next token as the value, which is why the lenient rows above dial where
  Go refuses. On the two *root* commands (`frpc`, `frps`) Go answers
  `unknown command "false"` instead — it takes no positional — while the four
  `frpc` subcommands accept the argv and silently ignore the token, keeping
  strict on. **Position does not matter**: with `-c` first the same divergence
  reproduces on both binaries (measured above), so the warning is tied to the
  flag, not to where it sits in the argv.
- **Only a bool value is consumed — the empty token is not.** `--strict-config
  ""` is an argv error on frp-rs (bpaf takes no empty value), and on Go the empty
  token is an ignored positional, so with a valid config Go exits **0** where
  frp-rs exits 1. That is a second, pre-existing "frp-rs stricter than Go"
  divergence on the same flag, in the opposite direction from the extension; it
  is recorded here rather than fixed. The attached `--strict-config=` fails on
  both (Go: pflag's `ParseBool`; frp-rs: the same leftover-token message as
  `--strict-config foo`), and neither warns.
- **`--strict-config foo` is a different divergence from `--strict-config=foo`.**
  Go ignores the stray space-separated token (the config is still loaded, rc 1
  only because the config itself is refused) where frp-rs refuses the argv
  outright; Go's `=foo` is pflag's own `strconv.ParseBool` error. All three exit
  1, and frp-rs's message is the same for both spellings.
- **`frps` is covered, not out of scope.** Go's server registers the same pflag
  bool (its `--help` carries Go's text `strict config parsing mode, unknown
  fields will cause errors (default true)`), so the extension applies there too,
  is stated in the same help text, and warns from the same detection.
- **"The `=` spelling is Go-faithful" is a per-flag rule, not a CLI-wide one.**
  It happens to hold for `--strict-config` and does not generalise: `frps
  --tls-only=false -c goodfrps.toml` is accepted by Go (rc 124, it starts) while
  frp-rs refuses it (``Error: `false` is not expected in this context``, rc 1),
  and the same holds for `--enable-prometheus=false` and
  `--disable-log-color=false` on `frps`. Those flags are bpaf switches, not the
  shared value parser, and the divergence runs the *opposite* way from this
  item (frp-rs refuses an argv Go accepts). Tracked as its own `TODO.md` item.

Why the extension is kept, as the measured trade the done-when asks for:

- **Keeping preserves argv acceptance and every existing invocation.** The
  measured cost is a *silent* behaviour difference for a Go-written argv: `frpc
  verify --strict-config false -c good.toml` is rc 0 on **both** binaries today
  (Go: strict but the config is valid; frp-rs: lenient), and
  `frpc reload --strict-config false -c host.toml` is rc 1 on both (Go's request
  carries `?strictConfig=true`, frp-rs dials the same address). What differs is
  *which load happened*, which is why the warning — not just the docs — is the
  mitigation.
- **Dropping (bpaf `ParseArgument::adjacent()`, one method call) makes that
  divergence loud but converts a Go-succeeding argv into an frp-rs failure.**
  Measured with the drop branch built:
  `frpc verify --strict-config false -c good.toml` → Go **rc 0**
  (`syntax is ok`), drop branch **rc 1** (``Error: `false` is not expected in
  this context``); `frpc verify --strict-config false -c bad.toml` → Go rc 1,
  drop rc 1 (rc agrees, reason does not); `frpc reload --strict-config false -c
  host.toml` → Go rc 1, drop rc 1; `frps --strict-config false -c
  goodfrps.toml` → Go rc 124 (starts), drop rc 1; and the `=` spellings keep
  working (`frps --strict-config=false` still starts). So the drop branch
  improves raw rc agreement on the config-refusal rows by turning *behaviour*
  differences into *acceptance* differences — it refuses argv Go accepts and
  simply ignores the token on. This document does not quote a global mismatch
  count; the reviewers' matrices are theirs, and the rows above are the ones
  measured here.
- **The decision is keep + warn.** The space form honours the user's obvious
  intent, existing invocations keep working, and the silent part of the
  divergence — the part that made this item worth filing — is now printed on
  stderr by every parser that can consume it, with the Go-faithful spelling in
  the same line. The repo already keeps bounded, documented extensions
  (`--config-dir`, `--admin-addr`, the V1 type bytes 7/8); this one announces
  itself on every use.
- **The blast radius of changing it is small, but non-zero.** A tree-wide
  `git grep` for the two-token form finds no script and no other doc — only the
  unit tests and this item — so nothing *documents* a dependency on the form;
  changing it would still alter behaviour for any user who typed it.

Carriers, all of which agree:

- the **warning**: `STRICT_CONFIG_SPACE_FORM_WARNING` (`frp-core/src/cli.rs`),
  printed from `parse_frps_args`/`parse_frpc_args` after a successful parse and
  gated by `strict_config_space_form_used`, which mirrors bpaf's consumption rule
  (a `--strict-config`/`--strict_config` token immediately followed by a
  non-`-`-prefixed bool). Pinned by `strict_config_warning_text_is_the_documented_line`
  (exact text), `strict_config_warning_detection_matches_the_consumed_shape`
  (the shapes that must and must not be detected, including the bare switch and
  `--strict-config --config x`), `space_form_warning_fires_on_each_frpc_parser`
  (real binary, one row per `frpc` parser, plus the silent `=` rows) and
  `space_form_strict_config_warns_on_stderr` (`frps/tests/cli_exit_codes.rs`);
- the **help text** of every parser that takes the flag, from one definition
  (`strict_config_parser` in `frp-core/src/cli.rs`) — the bare-form line names
  the Go-faithful spellings, states that frp-rs additionally consumes a
  space-separated value "which Go's pflag does not", and says a warning is
  printed; the `=BOOL` line names the Go-faithful value spelling. Pinned by
  `strict_config_help_text_states_the_extension` (`frp-core/src/cli.rs`), which
  asserts **each entry separately** — the rendered `--help` of all six parsers
  must contain the squashed help const *and* the const must still carry its
  meaning (independent literals), so neither a deleted value-form `.help()` nor
  an inverted bare-form help passes;
- `CHANGELOG.md` (Unreleased § Changed, for the warning, and § Docs) and this
  section;
- the parser tests `strict_config_defaults_to_true`,
  `strict_config_bare_flag_is_true`, `strict_config_equals_true_parses`,
  `strict_config_equals_false_parses_and_disables`,
  `strict_config_space_separated_value_parses` and
  `strict_config_invalid_value_errors_cleanly` (`frp-core/src/cli.rs`), each run
  across all six parsers (their `.unwrap()`s carry the parser label, so a
  failure names which parser broke);
- the real-binary pins `verify_strict_config_spellings_match_their_measured_rows`
  (`frpc/tests/cli_inputs.rs`: rc, which load happened, the warning for every
  spelling, both repeated-flag orders, both empty-value spellings and the
  position row) and `reload_space_separated_strict_config_is_consumed_as_the_value`
  / `reload_bare_strict_config_stays_strict_and_never_connects`
  (`frpc/tests/admin_cli.rs`, the mock-admin connection as proof of the consumed
  value and its strict-mode control).

### Repository Invariants (`repo-health.sh`)


`bash scripts/repo-health.sh` mirrors the `health` CI job. On top of version
alignment it gates the `Docs` section: every `docs/*.md` and `docs/*/` must be
reachable from `docs/README.md`, and **backtick-delimited** repo paths anchored
at a known root (`src/`, `tests/`, `docs/`, `frp-core/`, …) in current docs or
source comments must still resolve — against the directory of the file that
names it first, then the nearest ancestor holding a `Cargo.toml` (the owning
crate root — so a test that names src/v2_handshake.rs means
frp-core/src/v2_handshake.rs), then the repo root. A `crate/feature` span such
as `frp-core/tls` is recognised as Cargo feature syntax, not a path.

The path scan is **tracked-files-only**: its file list comes from the git index
(`git ls-files -z`), i.e. the set a clean checkout tracks. Untracked and
gitignored local state — `.worktrees/`, `.superpowers/`, a nested worktree's
point-in-time backlog and archive prose, editor backups — is therefore never
scanned, so the local mirror does not fail merely because the mandated worktree
workflow is in use. The index supplies the file *list* while content is read
from the worktree, so a tracked file edited locally is gated at its current
content. Local index state is visible too, so the list is not *exactly* a clean
checkout's file set: an intent-to-add (`git add -N`) entry is scanned, and an
unmerged path is listed once per stage and collapsed by path. Submodule contents
are never scanned — the index lists only the gitlink, and CI does not initialise
submodules. Because the scan follows the index, an *untracked* local file that
names a dead path is not gated — deliberate, since CI runs on a clean checkout
where untracked is absent, so the gate's CI meaning is unchanged.

Only a tree with no `.git` entry at all — not even a dangling symlink or a
gitfile whose gitdir is gone — falls back to walking the filesystem (release
tarball, Docker build context), pruning `.git` and `target` at any depth. A tree
that has any such `.git` entry but whose index cannot be read is **not**
certified: the path scan exits 3 rather than silently walking, because a walk
would scan the gitignored state this gate exists to avoid. A sparse checkout, or
any worktree missing a tracked path, is likewise not certified — that path is a
read error, not a skip; a partial clone (`--filter=blob:none`) materialises every
tracked file and does pass. The scan's minimum-size floors apply to the walk path
as well, and the `git ls-files` call runs with `GIT_DIR`/`GIT_WORK_TREE`/
`GIT_INDEX_FILE`/`GIT_COMMON_DIR`/`GIT_OBJECT_DIRECTORY` and any `GIT_TRACE*`
removed so the list comes from the repository git resolves for that directory,
not from an inherited environment: `git rev-parse --show-toplevel` must equal the
working directory (`realpath` on both sides) or the path scan exits 3, which is what
stops an enclosing repository's index from certifying a cwd whose own `.git` is
invalid. (The guard identifies the tree by where git says it is; it does not
prove the index file itself belongs to that tree — a symlinked or foreign
`.git/index` is tampering outside this gate's threat model.)
Hit lines are sorted by path and then by line number rather than in the old
depth-first walk order (per-directory filename sort); the counts and the hit set
are unaffected.

This is deliberately **not** "every repo path named resolves": un-backticked
prose and tree diagrams are not scanned, spans with no locating root (`mux.rs`,
`control/mod.rs`) are counted and left to review, and a directory that still
exists but has been emptied is not detected (existence is all that can be
checked mechanically). Third-party vendored markdown (`vendor/*/README.md`) is
out of scope; the frp-rs-authored `vendor/*/README-FRP-RS.md` notes stay in.
Historical records (`docs/archive/`, `docs/history/`, dated audits) and the
point-in-time files `CHANGELOG.md`, `TODO.md`, `performance-audit.md` and
`docs/refactor-large-modules.md` are out of scope because they quote an older
tree on purpose; see [`../TODO.md`](../TODO.md).

The same run also cross-checks the **quantitative claims the live docs make**
against the source that produces each number, and prints the whole inventory with
a witness line (`file:line`) for every entry. It is a curated list, not a regex
sweep over "numbers in docs" — a general sweep reports every port, buffer size
and version in the tree. Each entry pins (file, exact claim wording, source); the
expected value is recomputed from that source on every run, so two stale copies
can never agree with each other. The list is **curated, not exhaustive**: it
catches only the claim wordings it enumerates, so a quantity restated in new
words, or stated in a new doc, is **not** detected. When you add or reword a
count in a live doc, add the matching entry in the same change — or, better,
point at the source instead of typing the number. One definition is shared so
claim and counter cannot drift: "test function" is one `#[test]`/`#[tokio::test]`
attribute that starts a line after optional indentation, parameterised or not
(comment mentions do not count). Raw test counts are deliberately **not** in the
curated set — they change whenever a test is added, so gating them would make
"add a test" fail the `health` job; the script prints them instead. Two further
things are deliberately **not** gated because a text match cannot establish them:
**client-plugin wiring** (whether the `virtual_net` start-up skip and the
work-conn handoff actually compile and run) and **fuzz-target enablement** (a
`#[cfg]`-disabled target reads the same as a live one). Both are covered by the
plugin/compat test suite and `scripts/compat-test.sh`, not by a grep — a gate
that claimed them would be certifying text, not behaviour. The inventory is meant
to be read at release time; a claim that no longer matches fails the `health` CI
job.

A tree the gate cannot measure is **not** certified. Every file that supplies an
*expected* value for an entry — `scripts/compat-test.sh`,
`scripts/protocol-matrix.sh`, `scripts/rust_comments.py`, `frp-core/Cargo.toml`,
the two bench sources and each vendored crate's manifest — is checked before it is
read. An input the tree does not carry prints a partial-tree line (a missing path,
or `vendor manifest missing: …`); one it cannot read names the reason
(`Permission denied`, `not a regular file`, `not valid UTF-8`); a crate source
directory with no `.rs` file is refused rather than counted as zero. The block then
exits 3, a source walk that cannot complete exits 2, and `repo-health.sh` maps both
to its own failure line and a red run — so a sparse checkout or an unreadable input
is reported as unmeasurable, never as "a live doc quotes a figure the tree no
longer matches".

The same rule holds for every other read in the script: a gate reports a source it
could not read rather than comparing an empty value. Named paths (the version
sources, each vendored manifest, `rust-toolchain.toml`, the workflow files) are read
through `read_regular` — one `python3` doing an `O_NONBLOCK` open plus `fstat` on
the same descriptor — so a path flipping between a regular file and a FIFO cannot
slip between a test and the open, and a FIFO's blocking `open()` is never reached
(the `health` runner has no `timeout` binary, so a shell-level bound is not
portable). The recursive source counts are one python walk with the same guard
instead of `find | xargs cat`, and `.git` is resolved *without* git: `HEAD`, the
common `config`, `index` and `commondir` must be regular files before any git call,
every git call is bounded (15 s there, 30 s in the path scan), and the git
environment is sanitised. A refusal prints the reason and never an `ok`; a scan
whose file set was incomplete prints `not evaluated`. Known, deliberate holes are
listed next to the code (a directory named `*.yml`, a symlinked directory under
`.github/workflows/`); the symlinked `.rs` double count is recorded in `TODO.md`.

## 6. Release Process

### Pre-release checklist

Run through this before tagging. Most of it is automated, but two items are not
covered by any gate and are the ones that have actually been missed before.

- [ ] **Version alignment** — `bash scripts/repo-health.sh` exits 0. This is a CI
      gate (the `health` job), but check it locally first: it covers the 5 crates,
      the `VERSION` constant, `scripts/download-frp-rs.sh` and the README.
- [ ] **Doc figures reconciled** — read the `Docs` section of the same
      `repo-health.sh` run and reconcile every `claimed … measured …` line with
      its witness `file:line`; the run already fails on any *enumerated* claim
      whose figure no longer matches, but a count reworded or added since the
      last pass is not covered, so skim the witness lines for a claim that has
      drifted in *meaning* (a stale number usually means the sentence around it
      is stale too).
- [ ] **Gates green on `main`** — `cargo fmt --all -- --check`,
      `cargo clippy --workspace --all-targets --all-features -- -D warnings`,
      `cargo test --workspace --all-features`, the two `RUSTFLAGS="-D warnings"`
      tiny/micro tier checks, `bash scripts/compat-test.sh`
      against the matching Go frp release, `bash scripts/protocol-matrix.sh`, and
      the daily XTCP VPS matrix.
- [ ] **Notes written in the right place** — the user-facing summary in
      [`CHANGELOG.md`](../CHANGELOG.md), the detailed round record in
      [`docs/history/development-log.md`](history/development-log.md). Do not write
      the same detail twice (see the [docs conventions](README.md#conventions-for-these-docs)).
- [ ] **Security audit** —
      `cargo audit --ignore RUSTSEC-2026-0194 --ignore RUSTSEC-2026-0195 --ignore RUSTSEC-2023-0071`
      and `cargo deny check`.
- [ ] **Vendored crates — the step no tool covers.** `[patch.crates-io]` pins
      `rustls`, `yamux` and `russh`, so **`cargo update` will not pick up upstream
      security releases for them**. Before every release:
      - check <https://github.com/rustls/rustls/releases> for 0.23.x security
        backports and re-vendor if needed (frp-rs patches TLS code — this is the
        highest-risk item on this list);
      - re-read each `vendor/*/README-FRP-RS.md` and confirm the patches still
        match the code and the exit condition has not arrived;
      - confirm the `health` job still reports a README for every vendored crate.
      *Exit condition to watch:* `vendor/rustls` can be deleted as soon as the
      workspace moves to rustls ≥ 0.24, which has `invalid_sni_policy` natively.
      As of 2026-09-17 that upgrade is **blocked upstream**: crates.io's
      `max_stable_version` is `0.23.45` and the only 0.24 artifact is the
      `0.24.0-dev.1` prerelease, so the trigger and plan are tracked in
      [`../TODO.md`](../TODO.md). The vendored line is current in the meantime
      (`0.23.45`, the GHSA-2mjx-qc3c-rqvc fix).
      *Owner:* the sole maintainer — there is no second reviewer for this repo
      (see the bus-factor item in the backlog), so this checklist line **is** the
      control.
- [ ] **Regenerate the Go-frp comparison table** —
      `bash scripts/compare-go-frp.sh --build --memory`, then replace the table in
      the README's "Why frp-rs?" section. The script verifies platform *and*
      version against the current `VERSION` and aborts on a mismatch, so it cannot
      produce the apples-to-oranges table the old hand-written one was: a
      cross-platform or cross-version comparison is not a measurement.
- [ ] **All four size tiers build**, and record the sizes with the platform and
      rustc version — the numbers in the README are meaningless without them.
- [ ] **Release binaries are built with the declared profile.** CI overrides
      LTO/opt-level for speed; CI artifact sizes do not reflect the release.

### Version Bumping

**frp-rs 自身版本号严格对齐 Go frp 的发布号** (mandatory): the version
equals the current compat target Go frp release — currently **0.71.0** — and
bumps only when Go frp releases a new number. Update the version in ALL
sync locations:

```bash
# All crates share the same version
# Update in:
#   Cargo.toml (workspace)
#   frp-core/Cargo.toml
#   frp-server/Cargo.toml
#   frp-client/Cargo.toml
#   frps/Cargo.toml
#   frpc/Cargo.toml
#   frp-core/src/lib.rs  (VERSION constant)
#   scripts/download-frp-rs.sh  (default version)
#   README.md
```

Exception: `frp-vnet` stays independent at `0.1.0`.

### Building Release Binaries

The release workflow (`.github/workflows/release.yml`) cross-compiles for 13 targets:

- **Linux**: x86_64, aarch64, armv7, arm, i686, riscv64gc — glibc builds for all six, musl only for x86_64/aarch64/armv7 (built with `cargo zigbuild`)
- **macOS**: x86_64, aarch64 -- native builds
- **Windows**: x86_64, aarch64 -- native builds

Each target produces three variants: full, tiny, and micro.

To build locally for your platform:

```bash
# Full
cargo build --release -p frps -p frpc

# Tiny
cargo build --release -p frps -p frpc --no-default-features --features tiny

# Micro
cargo build --release -p frps -p frpc --no-default-features --features micro
```

### UPX Compression

After building, compress with UPX for additional size reduction (optional):

```bash
upx --best --lzma target/release/frps target/release/frpc
```

UPX is not required -- the release profile already produces compact binaries via `opt-level=z`, `lto=fat`, and `strip=symbols`.

### Docker Image Publication

The Docker image is built from source in a multi-stage build (`docker/Dockerfile.source`):

```bash
# Build for frps (from repo root)
docker build --build-arg FRP_COMPONENT=frps -t frps:latest -f docker/Dockerfile.source .

# Build for frpc
docker build --build-arg FRP_COMPONENT=frpc -t frpc:latest -f docker/Dockerfile.source .
```

Also available: `frps-tiny`, `frpc-tiny`, `frps-micro`, `frpc-micro` variants. The release workflow (`.github/workflows/docker.yml`) builds and pushes multi-arch images for all 6 variants. The image uses a `scratch` base (~2 MB total) with a musl-static binary.

### Triggering a Release

Releases are triggered by pushing a version tag or manually via workflow dispatch:

```bash
# Tag and push (triggers .github/workflows/release.yml)
git tag v0.71.0
git push origin v0.71.0
```

The release workflow:
1. Builds all 13 targets (9 Linux via cargo-zigbuild + 2 macOS + 2 Windows)
2. Packages each as `.tar.gz` (Linux/macOS) or `.zip` (Windows)
3. Creates a GitHub Release with auto-generated notes
4. Uploads all artifacts

The Docker workflow runs separately (`.github/workflows/docker.yml`) and can be triggered manually or on release.

## Maintenance policy: feature surface

frp-rs has one maintainer and more surface than one maintainer can hold at full
Go parity. The policy is **tiered by maintenance effort, not by deletion**:
every surface below has an explicit decision and none is removed. The parity
debt behind each decision is in [`../TODO.md`](../TODO.md); the per-surface Go
comparison is in [`go-frp-compat-audit.md`](go-frp-compat-audit.md), and the
end-to-end evidence for the surfaces its scenarios actually cover is
[`scripts/compat-test.sh`](../scripts/compat-test.sh)
(see [§ Cross-Compatibility Tests](#cross-compatibility-tests)). That suite
does **not** cover every surface below: the frozen ones — SUDP, h2c, Windows
TUN, the non-default XTCP KCP+yamux plane — have no compatible scenario, and
`virtual_net` has none either. Their unfreeze conditions therefore rest on a
user report, an upstream Go change, or someone committing to test the surface —
never on a compat-matrix failure.

This is a **single-maintainer decision with no second reviewer** — the same
posture as the vendored-crate release check
([§ Pre-release checklist](#pre-release-checklist)) and the bus-factor item in
[`../TODO.md`](../TODO.md). It is recorded so a contributor can tell, for a
given surface, whether new Go-parity work is welcome, tolerated, or out of
scope.

| Tier | What a change means | Surfaces |
|---|---|---|
| **Keep** — full parity maintained | Go-parity work and cross-compat coverage are welcome; a regression is a bug. | TCP, UDP, HTTP, HTTPS, STCP, XTCP; V1 and V2 wire protocol; encryption and compression; TCP multiplexing; the transports (TCP, WebSocket, TLS, KCP, QUIC); OIDC; the dashboard; the SSH gateway; 9 of the 10 client plugins; the server-side `[[httpPlugins]]` manager. |
| **Opt-in** — best-effort | Fixes when a user needs them; no proactive parity investment. Staying out of the default build is intentional. | `vnet` (L3 VPN/TUN) and the `virtual_net` client plugin that rides it, `mimalloc`, `otel`, the frpc `admin` API. |
| **Freeze** — bug-fix only | No new Go-parity work, no Go-parity-only tests, no refactor. Not removed. | SUDP; h2c; Windows TUN; the non-default XTCP data plane (KCP+yamux). |

Three build-tier facts the tier names alone would hide. The dashboard is
**Keep** even though it is an opt-in Cargo feature (`frp-server/Cargo.toml:45`)
— it is part of the product, just not of every binary — while the SSH gateway
is default-on (`frp-server/Cargo.toml:44`). The `http-proxy` feature is
**default-on** (`frp-server/Cargo.toml:43`), so the server-side
`[[httpPlugins]]` manager is Keep; that same feature gates the frozen h2c module
(`frp-server/src/vhost.rs:23`), so h2c's freeze is a code-review rule rather
than a build gate — the frozen code still compiles into the default and tiny
tiers, and splitting the feature is not part of this policy. Finally, one of
the 10 client plugins, `virtual_net`, is the TUN-backed path with no listener
of its own (`frp-client/src/plugin/mod.rs:331`), so it follows the opt-in
`vnet` tier: it is named in the Opt-in row above and is the one client plugin
not counted in Keep.

### Frozen surfaces, and what would unfreeze each

A freeze is a recorded decision, not neglect: each one names the evidence that
would lift it. Unfreezing moves the surface to **Keep** and resumes full parity
work; a bug fix on a frozen surface never needs an unfreeze.

- **SUDP** (`type = "sudp"`) — a distinct proxy type, not a UDP variant
  (`frp-core/src/config/loader.rs:219`), with frp-rs-specific shared-port
  handling. Unfreeze if a deployment is shown to use it (a user report — the
  repo carries no usage telemetry) or if Go frp changes its SUDP/VisitorManager
  behaviour and compat breaks beyond what a fix can cover.
- **h2c** (`frp-server/src/vhost_h2c.rs`) — HTTP/2-cleartext decode/re-encode
  on the server vhost path. Unfreeze if Go frp changes its h2c handling (its
  `net/http` upgrade path or `pkg/util/vhost`) or a user report shows an h2c
  interop failure that must be re-derived from Go source.
- **Windows TUN** (`frp-vnet/src/tun_windows.rs`) — an explicit stub whose
  `open()` and `configure()` always error. Unfreeze if someone commits to the
  Wintun (`wintun.dll`) integration *and* can test on a Windows host; this
  repo's CI does not exercise vnet on Windows.
- **Non-default XTCP data plane (KCP+yamux)** — selected by `protocol = "kcp"`;
  the default is QUIC (`frp-core/src/config/client.rs:823`,
  `docs/config.md:659`). Unfreeze if a case is reported that the QUIC plane
  cannot serve (for example a hole punch where the QUIC handshake never
  completes but KCP does).

### How a surface moves between tiers

The maintainer makes the move in a commit that edits this section and the
matching item in [`../TODO.md`](../TODO.md), and the commit must name the
evidence: a user report of real use, a Go frp release-note or source change, or
a compat-matrix failure on that surface. Moving a surface into **Keep** means
deleting its "unfreeze if" line; that edit plus the reason is the whole change.
There is no second reviewer, so the recorded reason **is** the control.

## Dependency Policy

The dependency policy — the pre-approved tech stack table, the banned list and
the justification each new crate must carry — is maintained in exactly one
place: [**CLAUDE.md § Dependency Policy**](../CLAUDE.md#dependency-policy-mandatory).

It is not duplicated here because a second copy drifts: the copy that used to
live in this file had already fallen behind (it listed four vendored `yamux`
patches when there are five, and its TLS row omitted the pointer to
`vendor/rustls/README-FRP-RS.md`).

Adding a dependency: declare it in the workspace `[workspace.dependencies]`
table in the root `Cargo.toml`, then reference it by name (no version) from the
sub-crate.
