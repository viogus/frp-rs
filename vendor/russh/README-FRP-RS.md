# Vendored russh 0.65.0 (frp-rs)

This directory vendors `russh` 0.65.0 (crates.io, warp-tech) with two
patches, wired in via `[patch.crates-io]` in the workspace root
`Cargo.toml` (`russh = { path = "vendor/russh" }`).

## Provenance

Re-vendored from the crates.io `russh` 0.65.0 tarball
(`sha256 3bb77a4b259312b2abbc541bca1c13cb4e9b61c560a7fd894068c3b92e0c9dc3`,
matching the `cksum` of the 0.65.0 row in the crates.io sparse index).
The vendored tree is the tarball's `Cargo.toml`, `Cargo.toml.orig`,
`README.md` and `src/`; the package's `benches/`, `examples/`, `tests/`,
`Cargo.lock` and `.cargo_vcs_info.json` are not vendored, same as in the
previous (0.62.7) copy. `diff -r` against the pristine tarball reports
exactly five modified files — `Cargo.toml`, `src/cipher/mod.rs`,
`src/keys/format/mod.rs`, `src/keys/format/openssh.rs` and
`src/keys/format/pkcs8.rs` — i.e. the two patches below and the one
`#[allow(dead_code)]`; everything else is byte-identical to crates.io.

The re-vendor commit was 0.62.7 → 0.65.0 in one step. The patch hunks
re-applied to the 0.65.0 text with zero fuzz (`patch -p1 --fuzz=0`, no
offsets, no rejects), so the frp-rs edit set is unchanged across the bump.
Upstream's exit condition for these patches is still unmet at 0.65.0:
`Cargo.toml` still hardcodes ssh-key's `encryption` + `ppk` features and
pkcs8's `encryption` feature, and the crate still calls
`PrivateKey::from_ppk`, `PrivateKey::decrypt` and
`EncryptedPrivateKeyInfoRef::decrypt` unconditionally.

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

The `pkcs8` encrypted-key decryption path is covered by Patch 2 below,
which drops the encrypted-PKCS8 chain entirely (pkcs8's `encryption`
feature → the `pkcs5` crate → scrypt/salsa20/sha3).

### Behavior change

Encrypted OpenSSH host keys and PuTTY `.ppk` keys are rejected. frp-rs
never supported them (its gateway has no passphrase/key-cipher config),
so no reachable behavior changes.

### Upgrade note

This has been replayed through the 0.62.7 → 0.65.0 bump: the two patches
above applied to the pristine 0.65.0 sources with `patch -p1 --fuzz=0`
(zero fuzz, zero offsets, no rejects), and `diff -r` against the pristine
tarball shows only the five files listed at the end of this file. When
bumping russh again: re-apply the source edits from Patch 1 and Patch 2
(the `format/mod.rs` PuTTY branch removal, the `format/openssh.rs` decrypt
replacement, the `format/pkcs8.rs` encrypted-key rejection +
`encode_pkcs8_encrypted` removal, and the `format/mod.rs`
`encode_pkcs8_pem_encrypted` removal) and the two `Cargo.toml` trims
(ssh-key features; pkcs8 features + the pkcs5/salsa20/scrypt/sha3 direct
deps), or carry the patch upstream (preferred: feature knobs in russh so
`ppk`, ssh-key `encryption`, and pkcs8 `encryption` can be disabled from
the crate root).

## Patch 2: drop pkcs8 `encryption` (encrypted-PKCS8 decryption chain)

Upstream russh hardcodes `pkcs8 = { features = ["encryption", ...] }`,
which turns on pkcs8's `encryption` feature. That feature = `alloc` +
`pkcs5/alloc` + `pkcs5/pbes2` + `rand_core`, and pulls the `pkcs5`
crate, whose `pbes2` path drags in scrypt 0.12, salsa20 0.11, sha3 0.12
and (transitively) aes-gcm 0.11. Russh uses it in exactly one place:
`keys/format/pkcs8.rs` decrypts `-----BEGIN ENCRYPTED PRIVATE KEY-----`
files via `EncryptedPrivateKeyInfoRef::decrypt`.

frp-rs's SSH gateway never loads an encrypted private key: host keys are
read with `russh::keys::load_secret_key(path, None)` (no passphrase) or
generated in-memory (`PrivateKey::random`), auth is password + public
keys (`authorized_keys`), and no config path reads an encrypted PKCS#8
key. So the entire encrypted-PKCS8/PKCS5 path is dead, and its dependency
chain is pure compile-time + audit-surface cost (LTO already strips the
unused crypto from the binary, but the crates still have to build and be
security-audited).

### What changed

- `Cargo.toml`: pkcs8 features trimmed to `["std"]`; the direct
  `pkcs5`/`salsa20`/`scrypt`/`sha3` dependencies are removed.
- `src/keys/format/pkcs8.rs`: `decode_pkcs8` rejects an encrypted key up
  front (`password.is_some()` → `Error::KeyIsEncrypted`) instead of
  decrypting; `encode_pkcs8_encrypted` is removed.
- `src/keys/format/mod.rs`: `encode_pkcs8_pem_encrypted` is removed (it
  called the now-deleted `encode_pkcs8_encrypted`).

### What this drops

Five crates leave `Cargo.lock`: `pkcs5`, `salsa20`, `scrypt`, `sha3`
0.12, and `sponge-cursor`. Their transitively-shared deps (`cipher`,
`aes`, `cbc`, `keccak`, `pbkdf2`) stay because russh's own direct deps
still use them. `sha3` 0.11 also stays — it is a hard dependency of
`ml-kem` (post-quantum Kyber KEX), not of the removed PKCS5 chain.
`aes-gcm` 0.11 is no longer compiled into the russh tree after Patch 1
(`cargo tree -i aes-gcm` prints nothing, so the `ssh-cipher` path that
used it is off); its lock entry lingers as an orphan. (`ssh-cipher` 0.3
itself stays: ssh-key 0.7 depends on it independently of the
`encryption` feature.) The SSH key algorithms (rsa/ed25519/p256/p384/p521)
are unaffected: they use pkcs8's core (`alloc`), never the `encryption`
path. russh's internal `keys/format/pkcs5` module (legacy OpenSSL
`DEK-Info: AES-128-CBC` PEM, on the `aes`/`cbc`/`md5` direct deps) is
unrelated to the removed `pkcs5` crate and is still present.

The win is build-time + audit surface, not binary size: LTO already
strips the unused crypto from the shipped binary, but these crates no
longer compile or need security review.

### Behavior change

Encrypted PKCS#8 private keys (`-----BEGIN ENCRYPTED PRIVATE KEY-----`)
now return `Error::KeyIsEncrypted` instead of being decrypted. frp-rs
never had a code path that fed one in, so no reachable behavior changes.

## Minor deviations (not patches)

- `cipher::MAXIMUM_DECOMPRESSED_PACKET_LEN` carries `#[allow(dead_code)]`
  (`src/cipher/mod.rs`). It is read only by the `flate2`-gated
  compression paths; with default-features off (frp-rs builds russh as
  `ring` + `rsa`, no `flate2`) the constant is dead. The allow keeps the
  vendored build warning-free — upstream is silent only because registry
  dependencies suppress warnings.

## Diff from crates.io russh 0.65.0

0.65.0 (the normalized `Cargo.toml`) with the five-file delta below is
the whole difference: `Cargo.toml.orig`, `README.md` and every `src/`
file not listed here are byte-identical to crates.io. The full delta is:

| File | Change |
|------|--------|
| `Cargo.toml` | ssh-key features trimmed; pkcs8 features trimmed; `pkcs5`/`salsa20`/`scrypt`/`sha3` direct deps dropped |
| `src/cipher/mod.rs` | `#[allow(dead_code)]` on `MAXIMUM_DECOMPRESSED_PACKET_LEN` |
| `src/keys/format/mod.rs` | PuTTY branch removed; `encode_pkcs8_pem_encrypted` removed |
| `src/keys/format/openssh.rs` | decrypt branch replaced with `Err(Error::KeyIsEncrypted)` |
| `src/keys/format/pkcs8.rs` | encrypted-key rejection; `encode_pkcs8_encrypted` removed |

The vendored tree also omits the package's `benches/`, `examples/`,
`tests/`, `Cargo.lock` and `.cargo_vcs_info.json` (as the 0.62.7 copy
did), and carries this file.
