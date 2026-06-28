# Dependency Consolidation & Binary Size Optimization

**Date**: 2026-06-28
**Status**: approved
**Scope**: frp-rs workspace — all crates, all features preserved

## Goal

Reduce binary size of `frps` and `frpc` by consolidating duplicate dependencies,
replacing heavy crates with lighter alternatives, and removing unused dependencies.
No features removed. No feature gates added.

## Baseline

| Binary | Size (release, stripped) |
|--------|--------------------------|
| frps   | 5.3 MB                   |
| frpc   | 3.7 MB                   |

Current compile settings already maxed: `opt-level=z`, `lto=fat`, `codegen-units=1`,
`strip=symbols`, `panic=abort`.

## Target

| Binary | Target size |
|--------|-------------|
| frps   | ~2.0–2.8 MB |
| frpc   | ~3.3 MB     |

---

## Step 1: russh → ring (largest single win)

### Problem

`russh = "0.61"` uses default features, which include `aws-lc-rs`. This pulls in
`aws-lc-sys` — a 67 MB C codebase compiled as a static library. `aws-lc-sys`
accounts for an estimated 2–3 MB of the frps binary (frpc does not depend on
russh).

`rustls` already uses `ring` as its crypto backend. `ring` is already in the
dependency tree. russh supports `ring` as an alternative crypto backend via
its own `ring` feature flag.

### Change

**Workspace `Cargo.toml`:**
```toml
# Before
russh = "0.61"

# After
russh = { version = "0.61", default-features = false, features = ["ring", "rsa", "flate2"] }
```

**`frp-server/Cargo.toml`:** No change needed (`russh = { workspace = true }`).

### Code changes

None. russh's public API is independent of crypto backend selection.

### Verification

```bash
cargo tree -p frps | grep aws-lc   # should return nothing
cargo build --release
# frps binary should be significantly smaller
bash scripts/compat-test.sh --verbose
```

---

## Step 2: Crypto consolidation → ring

### Problem

`frp-core` declares 14 cryptography-related dependencies. Many overlap with
`ring`'s built-in primitives:

| Crate | Used where | ring replacement |
|-------|-----------|-----------------|
| `aes-gcm` | `crypto.rs` — V2 AEAD stream encrypt/decrypt | `ring::aead::AES_256_GCM` |
| `chacha20poly1305` | `crypto.rs` — V2 AEAD (XChaCha20 variant) | ❌ ring has ChaCha20 only (96-bit nonce), V2 needs XChaCha20 (192-bit) |
| `sha2` | `v2_handshake.rs` — transcript hash; `crypto.rs` — HKDF input | `ring::digest::SHA256` |
| `hkdf` | `crypto.rs` — AEAD key derivation | `ring::hkdf` (HKDF-SHA256) |
| `hmac` | **Not used anywhere** — dead dependency | Remove |
| `pbkdf2` + `sha1` | `encryption.rs` — control-plane AES key derivation | ❌ ring lacks PBKDF2-SHA1 |
| `aes` + `cfb-mode` | `cipher_stream.rs` — data-plane AES-128-CFB streaming | ❌ ring lacks CFB mode |
| `md-5` | `auth.rs` — Go frp compat token hash | ❌ ring lacks MD5 |

### Changes

**Add direct ring dependency:**
- `Cargo.toml` (workspace): `ring = "0.17"` (already in dep tree at 0.17.14)
- `frp-core/Cargo.toml`: `ring = { workspace = true }`

**Remove from workspace + frp-core:**
- `sha2`, `aes-gcm`, `hkdf`, `hmac`, `base64`

**Keep (irreplaceable):**
- `chacha20poly1305`, `pbkdf2`, `sha1`, `aes`, `cfb-mode`, `md-5`

### Code changes: `frp-core/src/crypto.rs`

Replace `aes_gcm::Aes256Gcm` with `ring::aead`:

```rust
// Before
use aes_gcm::{Aes256Gcm, KeyInit, aead::{Aead, Payload}};
use hkdf::Hkdf;
use sha2::Sha256;

// After
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::hkdf;

// AeadKey::new() changes:
//   UnboundKey::new(&AES_256_GCM, key) → LessSafeKey::new(key)
// encrypt: key.seal_in_place(nonce, aad, &mut in_out, tag_len)
// decrypt: key.open_in_place(nonce, aad, &mut in_out)

// HKDF changes:
//   Salt::new(HKDF_SHA256, transcript_hash).extract(token).expand(...)
```

Detailed API mapping in `crypto.rs`:
- `AeadAlgorithm::Aes256Gcm` stays; implementation switches to ring
- `AeadAlgorithm::XChaCha20Poly1305` stays; keeps `chacha20poly1305` crate
- `AeadCipher::encrypt()`: `ring` uses `seal_in_place` — pre-allocate buffer with tag space
- `AeadCipher::decrypt()`: `ring` uses `open_in_place` — tag is at end of buffer
- Frame counter tracking unchanged

### Code changes: `frp-core/src/v2_handshake.rs`

```rust
// Before
use sha2::{Digest, Sha256};
// After
use ring::digest;

// transcript_hash computation:
//   let hash = digest::digest(&digest::SHA256, raw_json.as_bytes());
//   transcript_hash = hash.as_ref().to_vec();
```

### Code changes: `frp-core/src/msg.rs` (base64 → data_encoding)

```rust
// Before
use base64::Engine;
// After — use data_encoding::BASE64 (already imported in msg.rs)
// Replace: base64::engine::general_purpose::STANDARD.encode(b)
// With:    data_encoding::BASE64.encode(b)
```

### Verification

```bash
cargo build --release
cargo test --workspace
bash scripts/compat-test.sh --verbose
# Verify V2 handshake tests still pass
cargo test -p frp-core -- crypto v2_handshake
```

---

## Step 3: Encoding consolidation

### Problem

Three encoding crates: `hex`, `base64`, `data_encoding`. `data_encoding` already
provides both BASE64 and HEX. `hex` is tiny (single Rust file, no deps) — keep
for readability. `base64` only used in `v2_handshake.rs`.

### Changes

**`Cargo.toml` (workspace):** Remove `base64 = "0.22"`

**`frp-core/Cargo.toml`:** Remove `base64.workspace = true`

**`frp-core/src/v2_handshake.rs`:** Replace `base64::Engine` imports with `data_encoding::BASE64` calls:
```rust
// Before
use base64::Engine;
// ...
let encoded = base64::engine::general_purpose::STANDARD.encode(b);

// After
let encoded = data_encoding::BASE64.encode(b);
```

**`frp-core/src/msg.rs`:** Already uses `data_encoding::BASE64`. No change.

---

## Step 4: hickory-resolver → custom DNS client

### Problem

`hickory-resolver` (plus `hickory-proto`) is a full async DNS resolver library.
It is used in exactly one function: `resolve_host_with_dns()` in
`frp-core/src/transport.rs:950`. All other hostname resolution uses
`tokio::net::lookup_host` (system getaddrinfo).

`resolve_host_with_dns` does:
1. Parse DNS server address
2. Build a `TokioAsyncResolver` config pointing at that server
3. Call `resolver.lookup_ip(host)`
4. Return first resolved IP

### Change

Replace with a minimal DNS-over-UDP client (~50–80 lines). The DNS A-record
query wire format is trivial:

```
Header (12 bytes):
  [2-byte txid] [2-byte flags=0x0100] [1 QD] [0 AN] [0 NS] [0 AR]

Question:
  [length-prefixed labels] [0x00 terminator] [2-byte QTYPE=0x0001 (A)] [2-byte QCLASS=0x0001 (IN)]

Response parsing:
  Skip header + question, read answer section:
  [2-byte name ptr=0xC00C] [2-byte TYPE] [2-byte CLASS] [4-byte TTL] [2-byte RDLENGTH] [RDLENGTH bytes]
  If TYPE=0x0001: first 4 bytes of RDATA = IPv4 address
```

Implementation (DNS wire format is well-defined; ~80 lines total):

```rust
async fn resolve_host_with_dns(host: &str, dns_server: &str) -> Result<String, crate::Error> {
    use tokio::net::UdpSocket;

    // Build DNS query: 12-byte header + encoded hostname + QTYPE + QCLASS
    let mut query = Vec::with_capacity(64);
    let txid: u16 = rand::random();
    query.extend_from_slice(&txid.to_be_bytes());       // transaction ID
    query.extend_from_slice(&[0x01, 0x00]);              // flags: standard query, recursion desired
    query.extend_from_slice(&[0x00, 0x01]);              // QDCOUNT = 1
    query.extend_from_slice(&[0x00, 0x00]);              // ANCOUNT = 0
    query.extend_from_slice(&[0x00, 0x00]);              // NSCOUNT = 0
    query.extend_from_slice(&[0x00, 0x00]);              // ARCOUNT = 0
    for label in host.split('.') {                        // encode hostname as labels
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0x00);                                     // terminator
    query.extend_from_slice(&[0x00, 0x01]);              // QTYPE = A (1)
    query.extend_from_slice(&[0x00, 0x01]);              // QCLASS = IN (1)

    let socket = UdpSocket::bind("0.0.0.0:0").await
        .map_err(|e| crate::Error::Transport(format!("DNS: bind: {e}")))?;
    let dns_addr: std::net::SocketAddr = parse_dns_addr(dns_server)?;
    socket.connect(dns_addr).await
        .map_err(|e| crate::Error::Transport(format!("DNS: connect {dns_server}: {e}")))?;
    socket.send(&query).await
        .map_err(|e| crate::Error::Transport(format!("DNS: send to {dns_server}: {e}")))?;

    let mut buf = [0u8; 512];
    let n = tokio::time::timeout(Duration::from_secs(5), socket.recv(&mut buf)).await
        .map_err(|_| crate::Error::Transport("DNS: timeout".into()))?
        .map_err(|e| crate::Error::Transport(format!("DNS: recv: {e}")))?;

    // Parse response: skip 12-byte header + question section, read answers
    // Handle name compression pointers (0xC0xx) when skipping question
    // Extract first A record (TYPE=1, CLASS=1, RDLENGTH=4) from answer section
    let response = &buf[..n];
    // ... parse answers, return first IPv4 address ...
}
```

Edge cases handled:
- Name compression pointers (`0xC0`) in question and answer sections
- Multiple answers in response (iterate until A record found)
- Timeout on no response (5 seconds)
- Already-an-IP early return (preserved from original)

**Remove from workspace + frp-core:**
- `hickory-resolver`

### Verification

```bash
# Test with a known DNS server
cargo test -p frp-core -- transport::tests
# Integration: frpc connects to frps with custom dns_server in config
```

---

## Step 5: reqwest feature trim

### Problem

`reqwest` is configured with features `["rustls-tls", "json", "socks"]`.
- `json`: used for `.json()` convenience method on responses
- `socks`: SOCKS5 proxy support — not used (OIDC proxy uses HTTP_PROXY env var)

### Changes

**Workspace `Cargo.toml`:**
```toml
# Before
reqwest = { version = "0.12", default-features = false, features = ["rustls-tls", "json", "socks"] }

# After
reqwest = { version = "0.12", default-features = false, features = ["rustls-tls"] }
```

**Code changes:**

`frp-core/src/auth.rs` — replace `.json::<T>()` with manual deserialization:
```rust
// Before
let config: serde_json::Value = resp.json().await...;

// After
let body = resp.text().await...;
let config: serde_json::Value = serde_json::from_str(&body)...;
```

`frp-server/src/plugin/http.rs` — same pattern for POST responses:
```rust
// Before
let resp: PluginResponse = client.post(&url).json(&req).send().await?.json().await?;

// After
let resp_body = client.post(&url).json(&req).send().await?.text().await?;
let resp: PluginResponse = serde_json::from_str(&resp_body)?;
```

### Verification

```bash
cargo build --release
# OIDC tests
cargo test -p frp-core -- auth::oidc
# Plugin tests
cargo test -p frp-server -- plugin
```

---

## Files modified

| File | Change type |
|------|-------------|
| `Cargo.toml` (workspace) | Add `ring`, change `russh` features, remove `sha2/aes-gcm/hkdf/hmac/base64/hickory-resolver`, trim `reqwest` features |
| `frp-core/Cargo.toml` | Add `ring`, remove `sha2/aes-gcm/hkdf/hmac/base64/hickory-resolver` |
| `frp-core/src/crypto.rs` | Replace aes_gcm + hkdf + sha2 with ring APIs |
| `frp-core/src/v2_handshake.rs` | Replace sha2 with ring, replace base64 with data_encoding |
| `frp-core/src/auth.rs` | Replace reqwest `.json()` with manual deserialization |
| `frp-core/src/transport.rs` | Replace hickory-resolver with custom DNS client |
| `frp-server/src/plugin/http.rs` | Replace reqwest `.json()` with manual deserialization |

---

## Risk assessment

| Risk | Mitigation |
|------|-----------|
| ring's AEAD API differs from aes-gcm (in-place vs alloc) | Careful buffer management in crypto.rs; existing tests cover encrypt/decrypt roundtrip |
| ring's ChaCha20 ≠ XChaCha20 | Keep chacha20poly1305 crate for XChaCha20 variant; V2 protocol negotiation still offers both |
| Custom DNS client lacks edge case handling (truncation, CNAME, IPv6) | Implement only A-records with standard 512-byte UDP; fall through to error (same as current behavior on resolution failure) |
| russh ring backend may behave differently | russh supports ring as first-class backend; SSH gateway path covered by compat test |
| PBKDF2-SHA1 and AES-CFB remain as separate deps | Unavoidable for Go frp compat; ring deliberately excludes weak primitives |

---

## Out of scope (TODO: Approach C)

These items are noted for future work:

- `toml` → `toml_edit` — lighter TOML parser (already in dep tree via other crates)
- String/Vec optimization — `compact_str`, `smallvec`, `Cow` for hot paths
- Reduce `.clone()` calls — 686 sites, many convertible to references or moves
- Buffer preallocation — known-size read buffers instead of dynamic `Vec`
- Trait object elimination — `Box<dyn AsyncRead>` → generic or enum dispatch
- `snap` → `lz4_flex` — evaluate if pure-Rust lz4 is smaller/faster

---

## Rollback plan

Each step is independent and can be reverted separately:
1. Revert `russh` feature change → restores aws-lc-rs
2. Revert ring crypto changes → restores aes-gcm/sha2/hkdf
3. Revert base64 → restore base64 crate
4. Revert DNS client → restore hickory-resolver
5. Revert reqwest features → restore json/socks features

All changes are in a single git worktree branch. Full compat test run before merge.
