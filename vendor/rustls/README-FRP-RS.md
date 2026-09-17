# Vendored rustls 0.23.43 (frp-rs)

This directory vendors `rustls` 0.23.43 (crates.io) with **one** server-side
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

## Exit condition (drop this vendor directory)

**Delete `vendor/rustls` and the `[patch.crates-io]` entry when the workspace
moves to rustls ≥ 0.24**, which adds
`ServerConfig::invalid_sni_policy = InvalidSniPolicy::IgnoreAll` natively — the
exact semantics of this patch, as a supported knob. At that point set the policy
on the XTCP QUIC `ServerConfig` and drop the vendored tree.

## Maintenance obligation until then

Because the crate is patched, `cargo update` will **not** pick up upstream
0.23.x releases automatically:

1. **Track `RUSTSEC` advisories for rustls 0.23.x manually** and watch
   <https://github.com/rustls/rustls/releases> for security backports. Do this
   as part of every release checklist (see the Security audit steps in
   [`CLAUDE.md`](../../CLAUDE.md)).
2. When upstream publishes a 0.23.x security release, re-vendor that version and
   re-apply the one patch. The diff is small and localized (see "Site" above).
3. Verify the patch survives the re-vendor by running the XTCP QUIC compat
   scenarios — `bash scripts/download-go-frp.sh && bash scripts/compat-test.sh --verbose`
   plus the daily `xtcp-compat.yml` matrix.

## Diff from crates.io rustls 0.23.43

Everything outside the `Some(ServerNamePayload::Invalid)` arm of
`src/server/hs.rs` is byte-identical to crates.io rustls 0.23.43. The patch
carries an inline `// frp-rs vendored patch:` comment at the site so it can be
found with `grep -rn "frp-rs vendored patch" vendor/`.
