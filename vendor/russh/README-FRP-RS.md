# Vendored russh 0.62.7 (frp-rs)

This directory vendors `russh` 0.62.7 (crates.io, warp-tech) with two
patches, wired in via `[patch.crates-io]` in the workspace root
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

The `pkcs8` encrypted-key decryption path is covered by Patch 2 below,
which drops the encrypted-PKCS8 chain entirely (pkcs8's `encryption`
feature → the `pkcs5` crate → scrypt/salsa20/sha3).

### Behavior change

Encrypted OpenSSH host keys and PuTTY `.ppk` keys are rejected. frp-rs
never supported them (its gateway has no passphrase/key-cipher config),
so no reachable behavior changes.

### Upgrade note

When bumping russh upstream: re-apply the source edits from Patch 1 and
Patch 2 (the `format/mod.rs` PuTTY branch removal, the
`format/openssh.rs` decrypt replacement, the `format/pkcs8.rs`
encrypted-key rejection + `encode_pkcs8_encrypted` removal, and the
`format/mod.rs` `encode_pkcs8_pem_encrypted` removal) and the two
`Cargo.toml` trims (ssh-key features; pkcs8 features + the
pkcs5/salsa20/scrypt/sha3 direct deps), or carry the patch upstream
(preferred: feature knobs in russh so `ppk`, ssh-key `encryption`, and
pkcs8 `encryption` can be disabled from the crate root).

## Patch 2: drop pkcs8 `encryption` (encrypted-PKCS8 decryption chain)

Upstream russh hardcodes `pkcs8 = { features = ["encryption", ...] }`,
which turns on pkcs8's `encryption` feature. That feature = `alloc` +
`pkcs5/alloc` + `pkcs5/pbes2` + `rand_core`, and pulls the `pkcs5`
crate, whose `pbes2` path drags in scrypt 0.12, salsa20 0.11, sha3 0.12
and (transitively) aes-gcm 0.11. Russh uses it in exactly one place:
`keys/format/pkcs8.rs` decrypts `-----BEGIN ENCRYPTED PRIVATE KEY-----`
files via `EncryptedPrivateKeyInfoRef::decrypt`.

frp-rs's SSH gateway never loads private-key files at all: the host key
is generated in-memory (`PrivateKey::random`), auth is password + public
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
`aes-gcm` 0.11 was already unreachable after Patch 1 (its only puller,
`ssh-cipher` via ssh-key's `encryption` feature, is gone); its lock entry
lingers as an orphan. The SSH key algorithms (rsa/ed25519/p256/p384/p521)
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

## Diff from crates.io russh 0.62.7

Everything else in this tree is byte-identical to crates.io russh
0.62.7 (the normalized `Cargo.toml`); the full delta is the source edits
from Patch 1 and Patch 2, the two `Cargo.toml` trims, and the one
`#[allow(dead_code)]`.
