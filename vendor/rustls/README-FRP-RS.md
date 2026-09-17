# Vendored rustls 0.23.45 (frp-rs)

This directory vendors `rustls` 0.23.45 (crates.io) with **one** server-side
patch, wired in via `[patch.crates-io]` in the workspace root `Cargo.toml`
(`rustls = { path = "vendor/rustls" }`).

This is the most security-sensitive vendored crate in the tree: it is the TLS
implementation for frps/frpc. Read the maintenance note below before bumping or
shipping a release.

## License

Upstream: `Apache-2.0 OR ISC OR MIT` (see the `LICENSE-*` files copied from
`https://github.com/rustls/rustls`). The vendored copy keeps the same terms.

## Patch: treat an invalid TLS SNI as "no SNI"

**Site:** `src/server/hs.rs`, the `let sni = match &client_hello.server_name`
block (the `Some(ServerNamePayload::Invalid)` arm).

**Behavior:** upstream rustls 0.23 parses a `server_name` extension whose host
is not a valid DNS name into `ServerNamePayload::Invalid` and then rejects the
handshake with a fatal alert. This patch instead returns `None` — i.e. it acts
as if the client had sent no `server_name` extension at all.

**Why:** Go frp's XTCP QUIC data plane sends the **peer `"ip:port"`** as the TLS
SNI. An `ip:port` string is not a legal DNS `host_name`, so a stock rustls
server fails the handshake and Go↔Rust XTCP QUIC interop is impossible. See
[`docs/go-frp-compat-audit.md`](../../docs/go-frp-compat-audit.md) and
[`docs/archive/notes/2026-08-04-xtcp-quic-sni-compat.md`](../../docs/archive/notes/2026-08-04-xtcp-quic-sni-compat.md)
for the full plan and the compat matrix.

**Security argument** (why this is not an auth regression):

- SNI is advisory for certificate *selection*. With or without it, the client
  still performs a full certificate verification against whatever cert the
  server presents.
- frp's XTCP QUIC listener runs on a **self-signed** certificate and the peer
  uses `InsecureSkipVerify`-equivalent semantics — SNI was never an
  authentication input on this path.
- The patch is **server-side only** (`src/server/hs.rs`). Client-side SNI
  parsing and validation are untouched, so no client-trust decision changes.
- Rejecting the handshake was arguably worse: it made the peer address an
  accidental protocol input, and the upstream default is a hard failure with no
  operator override in 0.23.

**Test:** the patched behaviour is covered by
[`frp-core/tests/xtcp_quic_sni.rs`](../../frp-core/tests/xtcp_quic_sni.rs),
which drives a hand-crafted TLS 1.3 ClientHello carrying `"1.2.3.4:7000"` as SNI
through a real `rustls::ServerConnection` and asserts the server produces its
first flight instead of a fatal alert. It runs in CI as part of
`cargo test --workspace --all-features`.

> **Known stale test in this tree:** upstream's
> `src/server/test.rs::server_rejects_sni_with_illegal_dns_name` still asserts
> the *unpatched* reject behaviour and would fail if the crate's own unit tests
> were run. They are not: vendored crates are not workspace members (only
> `frp-core`, `frp-server`, `frp-client`, `frp-vnet`, `frps`, `frpc` are), so
> `cargo test --workspace` never builds this crate's test targets, and CI has no
> step that does. The file is otherwise byte-identical to crates.io, and this
> has been true since the patch was first vendored — do not "fix" it on a bump
> unless you also start running these tests.

## Security release history of the vendored line

- **0.23.43 → 0.23.45 (this bump).** 0.23.45 fixes
  [GHSA-2mjx-qc3c-rqvc](https://github.com/rustls/rustls/security/advisories/GHSA-2mjx-qc3c-rqvc)
  (medium, published 2026-09-14): TLS 1.3 handshake messages were incorrectly
  accepted across encryption-level boundaries — a peer could send handshake
  messages that should have been encrypted in plaintext. The handshake
  transcript remained authenticated, so a network-position attacker could not
  alter or complete a handshake, but the affected range is **0.23.13 through
  0.23.44 inclusive**, i.e. the previously vendored 0.23.43 *was* affected. It
  is the same bug as Go `GO-2026-4340`. Fixed by
  [rustls#3265](https://github.com/rustls/rustls/pull/3265).
  0.23.44 (2026-09-07) carried only routine changes for us: ML-DSA certificates
  enabled by default in the aws-lc-rs provider (frp-rs uses the **ring**
  provider, so not compiled in), owner-only permissions on `KeyLogFile` output,
  and an ECH-rejection certificate-name verification fix.
- **0.23.41 → 0.23.43** (the previous bump, in the same series as the SNI
  patch): aws-lc-rs ticketer debug-panic and QUIC client TLS1.2/suite-selection
  fixes. None affected the ring-provider server path used here.

## Exit condition (drop this vendor directory)

**Delete `vendor/rustls` and the `[patch.crates-io]` entry when the workspace
moves to rustls ≥ 0.24**, which adds
`ServerConfig::invalid_sni_policy = InvalidSniPolicy::IgnoreAll` natively — the
exact semantics of this patch, as a supported knob. At that point set the policy
on the XTCP QUIC `ServerConfig` and drop the vendored tree.

**As of 2026-09-17 that release does not exist:** crates.io reports
`max_stable_version = 0.23.45`, `newest_version = 0.23.45`, and the only 0.24
artifact is `0.24.0-dev.1` — a **prerelease** (published 2026-07-23,
`edition = "2024"`, `rust_version = "1.85"`). A prerelease is not an option for
the shipped TLS stack. The 0.24 migration is tracked in [`TODO.md`](../../TODO.md)
with the exact trigger (`max_stable_version` ≥ 0.24).

## Maintenance obligation until then

Because the crate is patched, `cargo update` will **not** pick up upstream
0.23.x releases automatically:

1. **Track `RUSTSEC` advisories/GitHub security advisories for rustls 0.23.x
   manually** and watch <https://github.com/rustls/rustls/releases> for security
   backports. Do this as part of every release checklist (see the Security audit
   steps in [`CLAUDE.md`](../../CLAUDE.md)).
2. When upstream publishes a 0.23.x security release, re-vendor that version and
   re-apply the one patch. The diff is small and localized (see "Site" above).
   Concretely: unpack the `.crate` from `static.crates.io`, drop `Cargo.lock`,
   `benches/` and `examples/` (the vendoring convention), keep this README, then
   re-apply the `None` arm.
3. Verify the patch survives the re-vendor by running
   `cargo test -p frp-core --test xtcp_quic_sni` (the focused local proof) and
   the XTCP QUIC compat scenarios — `bash scripts/download-go-frp.sh && bash scripts/compat-test.sh --verbose`
   plus the daily `xtcp-compat.yml` matrix.

## Diff from crates.io rustls 0.23.45

Everything outside the `Some(ServerNamePayload::Invalid)` arm of
`src/server/hs.rs` is byte-identical to crates.io rustls 0.23.45 (apart from
`Cargo.lock`, `benches/` and `examples/`, which are not vendored). The patch
carries an inline `// frp-rs vendored patch:` comment at the site so it can be
found with `grep -rn "frp-rs vendored patch" vendor/`.
