# Vendored russh 0.65.4 (frp-rs)

This directory vendors `russh` 0.65.4 (crates.io, warp-tech) with three
patches, wired in via `[patch.crates-io]` in the workspace root
`Cargo.toml` (`russh = { path = "vendor/russh" }`).

## Provenance

Re-vendored from the crates.io `russh` 0.65.4 tarball
(`sha256 569d8c45e20c123af2fc5ecb4803fde0a98572449ba4c24ed97741d7b02fedf7`,
matching the `cksum` of the 0.65.4 row in the crates.io sparse index).
The vendored tree is the tarball's `Cargo.toml`, `Cargo.toml.orig`,
`README.md` and `src/`; the package's `benches/`, `examples/`, `tests/`,
`Cargo.lock` and `.cargo_vcs_info.json` are not vendored, same as in the
previous (`0.65.0`) copy. `diff -r` against the pristine tarball reports
exactly six modified files — `Cargo.toml`, `src/cipher/mod.rs`,
`src/keys/format/mod.rs`, `src/keys/format/openssh.rs`,
`src/keys/format/pkcs8.rs` and `src/keys/format/pkcs5.rs` — i.e. the three
patches below and the one `#[allow(dead_code)]`; everything else is
byte-identical to crates.io.

The re-vendor history moved `0.62.7 → 0.65.0 → 0.65.4`. All five `.rs` patch
files re-applied to the `0.65.4` text with zero rejects (`--fuzz=0`), and
upstream `0.65.4` also dropped `generic-array` (`compat-0_14`), adopted `rsa ^0.10`
(resolving to stable `rsa 0.10.0` and retiring `RUSTSEC-2023-0071`),
`pkcs1 ^0.8`, and `ssh-key =0.7.0-rc.12`, plus client/channel and KEX/crypto
fixes (`GHSA-7qgr-cjxw-6vjf`; sibling `GHSA-xm3f-jwj9-3x8m` applies only to the
separate unvendored `russh-config` crate).
Upstream's exit condition for these patches is still unmet at 0.65.4:
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
bloat + unnecessary cryptographic surface:

- `ppk` → `argon2 0.6` + `blake2 0.11` + `hex` + `hmac` (pre-`0.7.0-rc.12` even pulled `-rc` releases)
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

This has been replayed through the `0.62.7 → 0.65.0 → 0.65.4` bumps: Patches 1, 2,
and 3 applied cleanly onto the pristine `0.65.4` sources (`patch -p0 --fuzz=0`,
zero rejects), and `diff -r` against pristine `0.65.4` shows only the six files
listed at the end of this file. When bumping russh again: re-apply the source
edits from Patches 1, 2, and 3 (the `format/mod.rs` PuTTY branch removal, the
`format/openssh.rs` decrypt replacement, the `format/pkcs8.rs` encrypted-key
rejection + `encode_pkcs8_encrypted` removal, the `format/mod.rs`
`encode_pkcs8_pem_encrypted` removal, and the `format/pkcs5.rs` encrypted-key
rejection) and the `Cargo.toml` trims (ssh-key features; pkcs8 features +
`pkcs5`/`salsa20`/`scrypt`/`sha3`/`ghash`/`polyval`/`pbkdf2`/`md5` direct deps),
or carry the patches upstream (preferred: feature knobs in russh so `ppk`,
ssh-key `encryption`, and pkcs8/pkcs5 encrypted keys can be disabled from the
crate root).

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

Three crates leave `Cargo.lock`: `pkcs5`, `salsa20`, and `scrypt` (`sha3` 0.12
and `sponge-cursor` 0.1 stay in `Cargo.lock` because `ml-kem` pulls them
independently for post-quantum KEX). Their transitively-shared deps (`cipher`,
`aes`, `cbc`, `keccak`) stay because russh's own cipher/KEX paths still use
them. `aes-gcm` 0.11 is no longer compiled into the russh tree after Patch 1
(`cargo tree -i aes-gcm` prints nothing, so the `ssh-cipher` path that used
it is off); its lock entry lingers as an orphan. (`ssh-cipher` 0.3 itself
stays: ssh-key 0.7 depends on it independently of the `encryption` feature.)
The SSH key algorithms (rsa/ed25519/p256/p384/p521) are unaffected: they use
pkcs8's core (`alloc`), never the `encryption` path.

### Behavior change

Encrypted PKCS#8 private keys (`-----BEGIN ENCRYPTED PRIVATE KEY-----`)
now return `Error::KeyIsEncrypted` instead of being decrypted. frp-rs
never had a code path that fed one in, so no reachable behavior changes.

## Patch 3: drop PKCS#5 encrypted PEM (`md5 0.8`) and unused direct deps

Upstream `Cargo.toml` declares three unused or dead-path direct dependency
groups for frp-rs's `ring` + `rsa` build (`generic-array` `compat-0_14` was
already dropped upstream in `0.65.4`):

- `ghash`, `polyval`, `pbkdf2` — 0 references in `vendor/russh/src/`.
- `md5 0.8` — used only in `src/keys/format/pkcs5.rs` (`decode_pkcs5`) for
  legacy OpenSSL `DEK-Info: AES-128-CBC` password-encrypted PEM keys (the same
  unreachable encrypted-key surface rejected by Patches 1 and 2), pulling a
  second MD5 crate alongside workspace `md-5 0.11`.

### What changed

- `Cargo.toml`: drop `ghash`, `polyval`, `pbkdf2`, and `md5`.
- `src/keys/format/pkcs5.rs`: reject encrypted PKCS#5 keys with
  `Err(Error::KeyIsEncrypted)` (matching `openssh.rs` and `pkcs8.rs`).

The win is build-time + audit surface, not binary size: LTO already
strips the unused crypto from the shipped binary, but these crates no
longer compile or need security review.

### Behavior change

Legacy OpenSSL `DEK-Info: AES-128-CBC` password-encrypted PKCS#5 PEM keys
now return `Error::KeyIsEncrypted` unconditionally (matching `openssh.rs` and
`pkcs8.rs`). frp-rs only calls `load_secret_key(path, None)`, which already
returned `Err(Error::KeyIsEncrypted)`, so no reachable behavior changes.

## Minor deviations (not patches)

- `cipher::MAXIMUM_DECOMPRESSED_PACKET_LEN` carries `#[allow(dead_code)]`
  (`src/cipher/mod.rs`). It is read only by the `flate2`-gated
  compression paths; with default-features off (frp-rs builds russh as
  `ring` + `rsa`, no `flate2`) the constant is dead. The allow keeps the
  vendored build warning-free — upstream is silent only because registry
  dependencies suppress warnings.

## Diff from crates.io russh 0.65.4

0.65.4 (the normalized `Cargo.toml`) with the six-file delta below is
the whole difference: `Cargo.toml.orig`, `README.md` and every `src/`
file not listed here are byte-identical to crates.io. The full delta is:

| File | Change |
|------|--------|
| `Cargo.toml` | ssh-key features trimmed; pkcs8 features trimmed; `pkcs5`/`salsa20`/`scrypt`/`sha3`/`ghash`/`polyval`/`pbkdf2`/`md5` direct deps dropped |
| `src/cipher/mod.rs` | `#[allow(dead_code)]` on `MAXIMUM_DECOMPRESSED_PACKET_LEN` |
| `src/keys/format/mod.rs` | PuTTY branch removed; `encode_pkcs8_pem_encrypted` removed |
| `src/keys/format/openssh.rs` | decrypt branch replaced with `Err(Error::KeyIsEncrypted)` |
| `src/keys/format/pkcs8.rs` | encrypted-key rejection; `encode_pkcs8_encrypted` removed |
| `src/keys/format/pkcs5.rs` | encrypted-key rejection (`Err(Error::KeyIsEncrypted)`) |

The vendored tree also omits the package's `benches/`, `examples/`,
`tests/`, `Cargo.lock` and `.cargo_vcs_info.json` (as the previous copies
did), and carries this file.
