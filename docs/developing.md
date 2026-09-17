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
  is recomputed from its source. If a doc says 86 scenarios, run the thing that
  counts them.
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
- Reviewer 1 (<what they did>): <findings, or "no findings">
- Reviewer 2 adversarial (<what they attacked>): <findings, or "no findings">
```

A claim of "reviewed" with no method named is not a review. Where a review could
not check something — a Linux-only path on macOS, a VPS-only XTCP matrix — it says
so, because an unstated gap reads as coverage.

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

### Binary Variants

Four size tiers via feature flags. The authoritative tier list, exact commands
and measured binary sizes live in the README —
[**Binary Variants**](../README.md#binary-variants). The resulting binaries are
named `frps`/`frpc` (default/full), `frps-tiny`/`frpc-tiny`, and
`frps-micro`/`frpc-micro`.

CI compiles the tiny and micro tiers with `RUSTFLAGS="-D warnings"` (the
`verify` job in `.github/workflows/ci.yml`). A feature-gated item whose `#[cfg]`
gate is missing therefore fails CI instead of only emitting a warning locally;
run the same two commands before pushing a change that touches `#[cfg]` code:

```bash
RUSTFLAGS="-D warnings" cargo check --workspace --no-default-features --features tiny
RUSTFLAGS="-D warnings" cargo check --workspace --no-default-features --features micro
```

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
# Full suite (86 run_test scenarios, 5 of which are gated on Go frp V2)
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

Proptest-based tests verify correctness under adversarial inputs (`repo-health.sh`
re-measures both figures below from the source on every run):
- **Config normalization** (`frp-core/src/config/tests.rs`): 11 proptest! blocks — idempotency, flat↔nested equivalence, camelCase→snake_case
- **Protocol fuzzing** (`frp-core/src/protocol.rs`): 6 fuzz tests + 40 regular tests — all 256 V1 type bytes × arbitrary payloads, V2 arbitrary type IDs, truncated frames, magic detection

### Repository Invariants (`repo-health.sh`)

`bash scripts/repo-health.sh` mirrors the `health` CI job. On top of version
alignment it gates the `Docs` section: every `docs/*.md` and `docs/*/` must be
reachable from `docs/README.md`, and every repo path named in a backtick span in
current docs or source comments must still resolve — against the directory of
the file that names it first, then the repo root. A `crate/feature` span such as
`frp-core/tls` is recognised as Cargo feature syntax, not a path. Two limits are
deliberate: spans with no locating root (`mux.rs`, `control/mod.rs`) are counted
and left to review, and a directory that still exists but has been emptied is not
detected (existence is all that can be checked mechanically). Historical records
(`docs/archive/`, `docs/history/`, dated audits, `CHANGELOG.md`) are out of
scope; see [`../TODO.md`](../TODO.md).

The same run also cross-checks the **quantitative claims the live docs make**
against the source that produces each number, and prints the whole inventory with
a witness line (`file:line`) for every entry. It is a curated list, not a regex
sweep over "numbers in docs" — a general sweep reports every port, buffer size
and version in the tree. Each entry pins (file, exact claim wording, source); the
expected value is recomputed from that source on every run, so two stale copies
can never agree with each other. If you add a count to `README.md`, `CLAUDE.md`
or a reference doc, add it here in the same change — or, better, point at this
script instead of typing the number. The inventory is meant to be read at
release time; a claim that no longer matches fails the `health` CI job.

## 6. Release Process

### Pre-release checklist

Run through this before tagging. Most of it is automated, but two items are not
covered by any gate and are the ones that have actually been missed before.

- [ ] **Version alignment** — `bash scripts/repo-health.sh` exits 0. This is a CI
      gate (the `health` job), but check it locally first: it covers the 5 crates,
      the `VERSION` constant, `scripts/download-frp-rs.sh` and the README.
- [ ] **Doc figures reconciled** — read the `Docs` section of the same
      `repo-health.sh` run and reconcile every `claimed … measured …` line with
      its witness `file:line`; the run already fails on any figure the tree no
      longer matches, so a green run only needs the witness lines skimmed for a
      claim that has drifted in *meaning* (a stale number usually means the
      sentence around it is stale too).
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
end-to-end evidence is [`scripts/compat-test.sh`](../scripts/compat-test.sh)
(see [§ Cross-Compatibility Tests](#cross-compatibility-tests)).

This is a **single-maintainer decision with no second reviewer** — the same
posture as the vendored-crate release check
([§ Pre-release checklist](#pre-release-checklist)) and the bus-factor item in
[`../TODO.md`](../TODO.md). It is recorded so a contributor can tell, for a
given surface, whether new Go-parity work is welcome, tolerated, or out of
scope.

| Tier | What a change means | Surfaces |
|---|---|---|
| **Keep** — full parity maintained | Go-parity work and cross-compat coverage are welcome; a regression is a bug. | TCP, UDP, HTTP, HTTPS, STCP, XTCP; V1 and V2 wire protocol; encryption and compression; TCP multiplexing; the transports (TCP, WebSocket, TLS, KCP, QUIC); OIDC; the dashboard; the SSH gateway; the 10 client plugins; the server-side `[[httpPlugins]]` manager. |
| **Opt-in** — best-effort | Fixes when a user needs them; no proactive parity investment. Staying out of the default build is intentional. | `vnet` (L3 VPN/TUN), `mimalloc`, `otel`, the frpc `admin` API. |
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
`vnet` tier.

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
