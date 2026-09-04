# Vendored russh 0.62.7 (frp-rs)

This directory vendors `russh` 0.62.7 (crates.io, warp-tech) with one
patch, wired in via `[patch.crates-io]` in the workspace root
`Cargo.toml` (`russh = { path = "vendor/russh" }`).

## License

Upstream: `Apache-2.0` (see `Cargo.toml` `license` field). The crates.io
package ships no `LICENSE` file; the vendored copy keeps the declared
license.

## Patch: drop ssh-key `encryption` + `ppk` (dead code in the frp-rs SSH gateway)

Upstream russh hardcodes its `ssh-key` dependency features as
`["ed25519","p256","p384","p521","encryption","ppk","sha1"]` in
`Cargo.toml`, and calls the APIs those features gate unconditionally:

- `keys/format/mod.rs` → `PrivateKey::from_ppk(...)` (PuTTY `.ppk`
  parsing, gated by ssh-key's `ppk` feature)
- `keys/format/openssh.rs` → `PrivateKey::decrypt(password)`
  (passphrase-protected OpenSSH key decryption, gated by ssh-key's
  `encryption` feature)

frp-rs's SSH gateway (`frp-server/src/ssh_gateway.rs`) never exercises
either path: it loads only OpenSSH-format host keys via
`russh::keys::load_secret_key(path, None)` (no passphrase, no `.ppk`),
and verifies client public keys from `authorized_keys`. So the two
call sites are dead code, and the features they drag in are pure binary
bloat plus pre-release dependency risk:

- `ppk` → `argon2 0.6.0-rc.8` + `blake2 0.11.0-rc.6` + `hex` + `hmac`
- `encryption` → `bcrypt-pbkdf` + ssh-cipher's `aes`/`chacha20poly1305`
  (the latter pulls `poly1305 0.9` + `chacha20 0.10`, a duplicate of
  the chacha20 gen frp-core already has)

### What changed

- `Cargo.toml`: ssh-key features trimmed to
  `["ed25519","p256","p384","p521","sha1"]`.
- `src/keys/format/mod.rs`: the `PuTTY-User-Key-File-` early-return
  (`PrivateKey::from_ppk`) is removed; PuTTY key files now fall through
  to PEM format detection and return `Error::CouldNotReadKey`.
- `src/keys/format/openssh.rs`: the `pk.decrypt(password)` branch is
  replaced with `Err(Error::KeyIsEncrypted)`; the parameter is renamed
  `_password`.

The `pkcs5`/`pkcs8` decryption paths are untouched: they use russh's own
direct dependencies (`aes`/`cbc`/`md5`, the `pkcs8` crate), not ssh-key's
`encryption` feature, so they still compile and still reject encrypted
keys the same way.

### What is NOT removed

The aes-gcm 0.11 / aead 0.6 / cipher 0.5 new-generation RustCrypto trait
stack stays. It is pulled independently by the SSH key-algorithm crates
(`ed25519-dalek 3.0` / `rsa 0.10-rc` / `p256`/`p384`/`p521 0.14-rc` →
`pkcs8 0.11` → `pkcs5 0.8` → `aes-gcm 0.11`) via russh's own
`pkcs8 = { features = ["encryption", ...] }` dependency, which this patch
does not touch. Dropping it would mean removing SSH key-algorithm
support, not dead decryption code.

### Behavior change

Encrypted OpenSSH host keys and PuTTY `.ppk` keys are rejected. frp-rs
never supported them (its gateway has no passphrase/key-cipher config),
so no reachable behavior changes.

### Upgrade note

When bumping russh upstream: re-apply the two source edits (the
`format/mod.rs` PuTTY branch removal and the `format/openssh.rs` decrypt
replacement) and the `Cargo.toml` ssh-key feature trim, or carry the
patch upstream (preferred: an ssh-key feature knob in russh so `ppk` and
`encryption` can be disabled from the crate root).

## Minor deviations (not patches)

- `cipher::MAXIMUM_DECOMPRESSED_PACKET_LEN` carries `#[allow(dead_code)]`
  (`src/cipher/mod.rs`). It is read only by the `flate2`-gated
  compression paths; with default-features off (frp-rs builds russh as
  `ring` + `rsa`, no `flate2`) the constant is dead. The allow keeps the
  vendored build warning-free — upstream is silent only because registry
  dependencies suppress warnings.

## Diff from crates.io russh 0.62.7

Everything else in this tree is byte-identical to crates.io russh
0.62.7 (the normalized `Cargo.toml`); the full delta is the two source
edits above, the ssh-key feature trim, and the one `#[allow(dead_code)]`.
