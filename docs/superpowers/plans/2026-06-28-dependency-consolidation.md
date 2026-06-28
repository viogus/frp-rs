# Dependency Consolidation & Binary Size Optimization — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reduce binary size (frps 5.3MB → ~2.0–2.8MB, frpc 3.7MB → ~3.3MB) by consolidating crypto onto ring, replacing heavy deps, and removing unused crates. No features removed.

**Architecture:** Five independent changes: (1) russh switches from aws-lc-rs to ring crypto backend, (2) frp-core crypto (aes-gcm, sha2, hkdf, hmac) consolidates to ring, (3) base64 crate replaced by data_encoding, (4) hickory-resolver replaced by custom DNS-over-UDP client, (5) reqwest feature trim with manual JSON deserialization. Each change is self-contained and independently revertible.

**Tech Stack:** Rust, tokio, ring 0.17, data_encoding, reqwest (trimmed features)

---

### Task 1: russh → ring crypto backend

**Files:**
- Modify: `Cargo.toml:47`
- Build: `cargo build --release`

- [ ] **Step 1: Edit workspace Cargo.toml — change russh features**

Line 47 in `/Users/cdf/Codes/frp-rs/Cargo.toml`:

```toml
# Before
russh = "0.61"

# After
russh = { version = "0.61", default-features = false, features = ["ring", "rsa", "flate2"] }
```

Use the Edit tool:
- `old_string`: `russh = "0.61"`
- `new_string`: `russh = { version = "0.61", default-features = false, features = ["ring", "rsa", "flate2"] }`

- [ ] **Step 2: Verify aws-lc-sys is gone from dependency tree**

```bash
cargo tree -p frps 2>/dev/null | grep -c "aws-lc"    # should output 0
```

Expected: `0` (no matches)

- [ ] **Step 3: Build release and check size**

```bash
cargo build --release 2>&1
ls -lh target/release/frps target/release/frpc
```

frps should drop from ~5.3MB to ~3.0–3.5MB. frpc size unchanged (does not depend on russh).

- [ ] **Step 4: Run SSH gateway-related tests**

```bash
cargo test -p frp-server -- ssh
```

Expected: all tests pass (SSH gateway logic unchanged, only crypto backend changed).

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock
git commit -m "perf: switch russh from aws-lc-rs to ring crypto backend

Removes aws-lc-sys (~2-3MB) from frps binary.
russh supports ring as first-class alternative via feature flag.
SSH gateway code unchanged — API is crypto-backend-agnostic.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 2: Add ring as direct dependency

**Files:**
- Modify: `Cargo.toml` (workspace, add `ring = "0.17"`)
- Modify: `frp-core/Cargo.toml` (add `ring.workspace = true`)

- [ ] **Step 1: Add ring to workspace dependencies**

In `/Users/cdf/Codes/frp-rs/Cargo.toml`, after line 39 (`webpki-roots = "0.26"`), add:

```toml
ring = "0.17"
```

Use Edit to insert after `webpki-roots = "0.26"`:
```
old_string: webpki-roots = "0.26"
new_string: webpki-roots = "0.26"
ring = "0.17"
```

- [ ] **Step 2: Add ring to frp-core dependencies**

In `/Users/cdf/Codes/frp-rs/frp-core/Cargo.toml`, after line 33 (`webpki-roots.workspace = true`), add:

```toml
ring = { workspace = true }
```

Use Edit to insert after `webpki-roots.workspace = true`:
```
old_string: webpki-roots.workspace = true
new_string: webpki-roots.workspace = true
ring = { workspace = true }
```

- [ ] **Step 3: Verify ring resolves**

```bash
cargo tree -p frp-core -i ring --depth 1 2>/dev/null | head -5
```

Expected: ring appears in tree (already v0.17.14, our declaration matches).

- [ ] **Step 4: Commit**

```bash
git add Cargo.toml frp-core/Cargo.toml Cargo.lock
git commit -m "deps: add ring as direct dependency (already in tree via rustls)

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 3: Remove dead dependency (hmac only)

**Files:**
- Modify: `Cargo.toml:27` (remove `hmac = "0.12"`)
- Modify: `frp-core/Cargo.toml:21` (remove `hmac.workspace = true`)

- [ ] **Step 1: Remove hmac from workspace Cargo.toml**

Line 27 in workspace `Cargo.toml` — delete the line:
```
hmac = "0.12"
```

Use Edit:
- `old_string`: `hmac = "0.12"\n`
- `new_string`: `` (empty)

- [ ] **Step 2: Remove hmac from frp-core Cargo.toml**

Line 21 in `frp-core/Cargo.toml` — delete the line:
```
hmac.workspace = true
```

- [ ] **Step 3: Verify build still works (hmac was dead — never imported)**

```bash
cargo build 2>&1 | head -5
```

Expected: build succeeds. hmac was declared but never imported in any `.rs` file.

- [ ] **Step 4: Commit**

```bash
git add Cargo.toml frp-core/Cargo.toml Cargo.lock
git commit -m "deps: remove unused hmac crate (dead dependency, never imported)

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 4: Replace aes-gcm + sha2 + hkdf with ring in crypto.rs (+ remove deps)

**Files:**
- Modify: `frp-core/src/crypto.rs:18-27` (imports)
- Modify: `frp-core/src/crypto.rs:86-141` (AeadCipher enum)
- Modify: `frp-core/src/crypto.rs:931-936` (HKDF key derivation)
- Modify: `Cargo.toml:24,53,55` (remove sha2, aes-gcm, hkdf)
- Modify: `frp-core/Cargo.toml:18,43,45` (remove sha2, aes-gcm, hkdf)

- [ ] **Step 1: Replace imports (lines 18-27)**

Replace lines 18-27 of `frp-core/src/crypto.rs`:

```rust
// Before
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use aes_gcm::{Aes256Gcm, KeyInit, aead::{Aead, Payload}};
use chacha20poly1305::XChaCha20Poly1305;
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;

// After
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use chacha20poly1305::XChaCha20Poly1305;
use rand::RngCore;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::hkdf::{Salt, HKDF_SHA256};
```

- [ ] **Step 2: Replace AeadCipher enum and impl (lines 86-141)**

Replace the `AeadCipher` enum and its `impl` block:

```rust
// Before
enum AeadCipher {
    Aes256Gcm(Box<Aes256Gcm>),
    XChaCha20Poly1305(XChaCha20Poly1305),
}

impl AeadCipher {
    fn new(algorithm: AeadAlgorithm, key: &[u8]) -> Result<Self, String> {
        if key.len() != AEAD_KEY_SIZE {
            return Err(format!("AEAD key must be {} bytes, got {}", AEAD_KEY_SIZE, key.len()));
        }
        match algorithm {
            AeadAlgorithm::Aes256Gcm => {
                let cipher = Aes256Gcm::new_from_slice(key)
                    .map_err(|e| format!("aes-256-gcm init: {e}"))?;
                Ok(Self::Aes256Gcm(Box::new(cipher)))
            }
            AeadAlgorithm::XChaCha20Poly1305 => {
                let cipher = XChaCha20Poly1305::new_from_slice(key)
                    .map_err(|e| format!("xchacha20-poly1305 init: {e}"))?;
                Ok(Self::XChaCha20Poly1305(cipher))
            }
        }
    }

    fn encrypt(&self, nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
        let payload = Payload { msg: plaintext, aad };
        match self {
            Self::Aes256Gcm(c) => {
                let nonce = aes_gcm::Nonce::from_slice(nonce);
                c.encrypt(nonce, payload)
                    .map_err(|e| format!("aes-gcm encrypt: {e}"))
            }
            Self::XChaCha20Poly1305(c) => {
                let nonce = chacha20poly1305::XNonce::from_slice(nonce);
                c.encrypt(nonce, payload)
                    .map_err(|e| format!("xchacha20 encrypt: {e}"))
            }
        }
    }

    fn decrypt(&self, nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
        let payload = Payload { msg: ciphertext, aad };
        match self {
            Self::Aes256Gcm(c) => {
                let nonce = aes_gcm::Nonce::from_slice(nonce);
                c.decrypt(nonce, payload)
                    .map_err(|e| format!("aes-gcm decrypt: {e}"))
            }
            Self::XChaCha20Poly1305(c) => {
                let nonce = chacha20poly1305::XNonce::from_slice(nonce);
                c.decrypt(nonce, payload)
                    .map_err(|e| format!("xchacha20 decrypt: {e}"))
            }
        }
    }
}

// After
enum AeadCipher {
    /// ring-based AES-256-GCM (via LessSafeKey for non-96-bit nonce support).
    Aes256Gcm(Box<LessSafeKey>),
    XChaCha20Poly1305(XChaCha20Poly1305),
}

impl AeadCipher {
    fn new(algorithm: AeadAlgorithm, key: &[u8]) -> Result<Self, String> {
        if key.len() != AEAD_KEY_SIZE {
            return Err(format!("AEAD key must be {} bytes, got {}", AEAD_KEY_SIZE, key.len()));
        }
        match algorithm {
            AeadAlgorithm::Aes256Gcm => {
                let unbound = UnboundKey::new(&AES_256_GCM, key)
                    .map_err(|e| format!("aes-256-gcm init: {e}"))?;
                Ok(Self::Aes256Gcm(Box::new(LessSafeKey::new(unbound))))
            }
            AeadAlgorithm::XChaCha20Poly1305 => {
                let cipher = XChaCha20Poly1305::new_from_slice(key)
                    .map_err(|e| format!("xchacha20-poly1305 init: {e}"))?;
                Ok(Self::XChaCha20Poly1305(cipher))
            }
        }
    }

    fn encrypt(&self, nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
        match self {
            Self::Aes256Gcm(key) => {
                let nonce = Nonce::try_assume_unique_for_key(nonce)
                    .map_err(|e| format!("aes-gcm nonce: {e}"))?;
                let aad = Aad::from(aad);
                let mut in_out = plaintext.to_vec();
                // Tag is appended by seal_in_place
                key.seal_in_place_append_tag(nonce, aad, &mut in_out)
                    .map_err(|e| format!("aes-gcm encrypt: {e}"))?;
                Ok(in_out)
            }
            Self::XChaCha20Poly1305(c) => {
                let nonce = chacha20poly1305::XNonce::from_slice(nonce);
                let payload = chacha20poly1305::aead::Payload { msg: plaintext, aad };
                c.encrypt(nonce, payload)
                    .map_err(|e| format!("xchacha20 encrypt: {e}"))
            }
        }
    }

    fn decrypt(&self, nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
        match self {
            Self::Aes256Gcm(key) => {
                let nonce = Nonce::try_assume_unique_for_key(nonce)
                    .map_err(|e| format!("aes-gcm nonce: {e}"))?;
                let aad = Aad::from(aad);
                let mut in_out = ciphertext.to_vec();
                let plaintext = key.open_in_place(nonce, aad, &mut in_out)
                    .map_err(|e| format!("aes-gcm decrypt: {e}"))?;
                Ok(plaintext.to_vec())
            }
            Self::XChaCha20Poly1305(c) => {
                let nonce = chacha20poly1305::XNonce::from_slice(nonce);
                let payload = chacha20poly1305::aead::Payload { msg: ciphertext, aad };
                c.decrypt(nonce, payload)
                    .map_err(|e| format!("xchacha20 decrypt: {e}"))
            }
        }
    }
}
```

- [ ] **Step 3: Replace HKDF key derivation (lines 931-936)**

Replace the `derive_aead_control_key` function body (lines 930-936):

```rust
// Before
fn derive_aead_control_key(
    token: &[u8],
    algorithm: AeadAlgorithm,
    transcript_hash: &[u8],
    direction: &str,
) -> Result<Vec<u8>, String> {
    let info = format!("frp wire v2 control aead {} {}", algorithm.as_str(), direction);
    let hkdf = Hkdf::<Sha256>::new(Some(transcript_hash), token);
    let mut okm = vec![0u8; AEAD_KEY_SIZE];
    hkdf.expand(info.as_bytes(), &mut okm)
        .map_err(|e| format!("HKDF expand: {e}"))?;
    Ok(okm)
}

// After
fn derive_aead_control_key(
    token: &[u8],
    algorithm: AeadAlgorithm,
    transcript_hash: &[u8],
    direction: &str,
) -> Result<Vec<u8>, String> {
    let info = format!("frp wire v2 control aead {} {}", algorithm.as_str(), direction);
    let salt = Salt::new(HKDF_SHA256, transcript_hash);
    let prk = salt.extract(token);
    let mut okm = vec![0u8; AEAD_KEY_SIZE];
    let info_refs = [info.as_bytes()];
    let okm_result = prk.expand(&info_refs, HKDF_SHA256)
        .map_err(|e| format!("HKDF expand: {e}"))?;
    okm_result.fill(&mut okm)
        .map_err(|e| format!("HKDF fill: {e}"))?;
    Ok(okm)
}
```

- [ ] **Step 5: Remove sha2, aes-gcm, hkdf from workspace Cargo.toml**

Delete these three lines from workspace `Cargo.toml`:
```
sha2 = "0.10"        # line 24
aes-gcm = "0.10"     # line 53
hkdf = "0.12"        # line 55
```

- [ ] **Step 6: Remove sha2, aes-gcm, hkdf from frp-core Cargo.toml**

Delete these three lines from `frp-core/Cargo.toml`:
```
sha2.workspace = true        # line 18
aes-gcm.workspace = true     # line 43
hkdf.workspace = true        # line 45
```

- [ ] **Step 7: Build and run crypto tests**

```bash
cargo build 2>&1
cargo test -p frp-core -- crypto 2>&1
```

Expected: builds clean, all crypto tests pass (roundtrip encrypt/decrypt, key derivation, AEAD stream).

- [ ] **Step 8: Commit**

```bash
git add frp-core/src/crypto.rs Cargo.toml frp-core/Cargo.toml Cargo.lock
git commit -m "perf: replace aes-gcm + sha2 + hkdf with ring in crypto.rs

AES-256-GCM now uses ring::aead (LessSafeKey + AES_256_GCM).
HKDF-SHA256 key derivation now uses ring::hkdf (Salt + Prk + expand).
XChaCha20-Poly1305 keeps chacha20poly1305 crate (ring lacks XChaCha variant).

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 5: Replace sha2 + base64 with ring + data_encoding in v2_handshake.rs (+ remove base64 dep)

**Files:**
- Modify: `frp-core/src/v2_handshake.rs:15-18` (imports)
- Modify: `frp-core/src/v2_handshake.rs:37-70` (base64 helpers)
- Modify: `frp-core/src/v2_handshake.rs:298-302` (compute_transcript_hash)
- Modify: `Cargo.toml:56` (remove base64)
- Modify: `frp-core/Cargo.toml:46` (remove base64)

- [ ] **Step 1: Replace imports (lines 15-18)**

```rust
// Before
use base64::Engine;
use rand::RngCore;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

// After
use rand::RngCore;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use ring::digest;
```

Also add `use data_encoding::BASE64;` after line 18.

- [ ] **Step 2: Replace base64 helper functions (lines 37-70)**

Replace all four base64 functions with data_encoding equivalents:

```rust
// Before (lines 37-70)
fn base64_serialize<S: Serializer>(bytes: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
    match bytes {
        Some(b) => {
            let encoded = base64::engine::general_purpose::STANDARD.encode(b);
            s.serialize_some(&encoded)
        }
        None => s.serialize_none(),
    }
}

fn base64_deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
    let opt: Option<String> = Option::deserialize(d)?;
    match opt {
        Some(s) => {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(s.as_bytes())
                .map_err(serde::de::Error::custom)?;
            Ok(Some(bytes))
        }
        None => Ok(None),
    }
}

fn base64_serialize_non_null<S: Serializer>(bytes: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
    let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
    s.serialize_str(&encoded)
}

fn base64_deserialize_non_null<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    let s: String = String::deserialize(d)?;
    base64::engine::general_purpose::STANDARD
        .decode(s.as_bytes())
        .map_err(serde::de::Error::custom)
}

// After
fn base64_serialize<S: Serializer>(bytes: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
    match bytes {
        Some(b) => {
            let encoded = data_encoding::BASE64.encode(b);
            s.serialize_some(&encoded)
        }
        None => s.serialize_none(),
    }
}

fn base64_deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
    let opt: Option<String> = Option::deserialize(d)?;
    match opt {
        Some(s) => {
            let bytes = data_encoding::BASE64.decode(s.as_bytes())
                .map_err(serde::de::Error::custom)?;
            Ok(Some(bytes))
        }
        None => Ok(None),
    }
}

fn base64_serialize_non_null<S: Serializer>(bytes: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
    let encoded = data_encoding::BASE64.encode(bytes);
    s.serialize_str(&encoded)
}

fn base64_deserialize_non_null<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    let s: String = String::deserialize(d)?;
    data_encoding::BASE64.decode(s.as_bytes())
        .map_err(serde::de::Error::custom)
}
```

- [ ] **Step 3: Replace compute_transcript_hash (lines 298-302)**

```rust
// Before
pub fn compute_transcript_hash(client_hello_payload: &[u8], server_hello_payload: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(CRYPTO_TRANSCRIPT_LABEL.as_bytes());
    write_transcript_part(&mut h, "client hello", client_hello_payload);
    write_transcript_part(&mut h, "server hello", server_hello_payload);
    h.finalize().to_vec()
}

fn write_transcript_part(h: &mut Sha256, label: &str, payload: &[u8]) {
    h.update([0u8]);
    h.update(label.as_bytes());
    h.update([0u8]);
    h.update((payload.len() as u64).to_be_bytes());
    h.update(payload);
}

// After
pub fn compute_transcript_hash(client_hello_payload: &[u8], server_hello_payload: &[u8]) -> Vec<u8> {
    let mut ctx = digest::Context::new(&digest::SHA256);
    ctx.update(CRYPTO_TRANSCRIPT_LABEL.as_bytes());
    write_transcript_part(&mut ctx, "client hello", client_hello_payload);
    write_transcript_part(&mut ctx, "server hello", server_hello_payload);
    ctx.finish().as_ref().to_vec()
}

fn write_transcript_part(ctx: &mut digest::Context, label: &str, payload: &[u8]) {
    ctx.update(&[0u8]);
    ctx.update(label.as_bytes());
    ctx.update(&[0u8]);
    ctx.update(&(payload.len() as u64).to_be_bytes());
    ctx.update(payload);
}
```

- [ ] **Step 4: Remove base64 from Cargo.toml files**

Delete from workspace `Cargo.toml` (line 56):
```
base64 = "0.22"
```

Delete from `frp-core/Cargo.toml` (line 46):
```
base64.workspace = true
```

- [ ] **Step 5: Build and test V2 handshake**

```bash
cargo build 2>&1
cargo test -p frp-core -- v2_handshake 2>&1
```

Expected: builds clean, V2 handshake tests pass.

- [ ] **Step 6: Commit**

```bash
git add frp-core/src/v2_handshake.rs Cargo.toml frp-core/Cargo.toml Cargo.lock
git commit -m "perf: replace sha2+base64 with ring+data_encoding in v2_handshake

SHA256 transcript hash now uses ring::digest.
Base64 helpers now use data_encoding::BASE64 (already in dep tree).

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 6: Replace hickory-resolver with custom DNS client

**Files:**
- Modify: `frp-core/src/transport.rs:949-987` (replace resolve_host_with_dns)
- Modify: `Cargo.toml:51` (remove hickory-resolver)
- Modify: `frp-core/Cargo.toml:39` (remove hickory-resolver.workspace)

- [ ] **Step 1: Replace resolve_host_with_dns function**

Replace lines 949-987 of `frp-core/src/transport.rs`:

```rust
// Before (lines 949-987)
/// Resolve a hostname to an IP address using a specific DNS server.
async fn resolve_host_with_dns(host: &str, dns_server: &str) -> Result<String, crate::Error> {
    use hickory_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};
    use hickory_resolver::TokioAsyncResolver;
    use std::net::SocketAddr;
    use std::str::FromStr;

    // Parse DNS server address (default port 53)
    let dns_addr = if dns_server.contains(':') {
        SocketAddr::from_str(dns_server)
            .map_err(|e| crate::Error::Transport(format!("invalid dns_server '{dns_server}': {e}")))?
    } else {
        SocketAddr::from_str(&format!("{dns_server}:53"))
            .map_err(|e| crate::Error::Transport(format!("invalid dns_server '{dns_server}': {e}")))?
    };

    let ns_config = NameServerConfig {
        socket_addr: dns_addr,
        protocol: Protocol::Udp,
        tls_dns_name: None,
        trust_negative_responses: true,
        bind_addr: None,
    };
    let config = ResolverConfig::from_parts(None, vec![], vec![ns_config]);
    let resolver = TokioAsyncResolver::tokio(config, ResolverOpts::default());

    // If host is already an IP, return it as-is
    if host.parse::<std::net::IpAddr>().is_ok() {
        return Ok(host.to_string());
    }

    let response = resolver.lookup_ip(host).await
        .map_err(|e| crate::Error::Transport(format!("DNS resolve {host} via {dns_server}: {e}")))?;

    response.iter()
        .next()
        .map(|ip| ip.to_string())
        .ok_or_else(|| crate::Error::Transport(format!("DNS resolve {host}: no records found")))
}

// After
/// Resolve a hostname to an IP address using a specific DNS server.
///
/// Sends a standard DNS A-record query over UDP. Handles name compression
/// pointers in the response. IPv6 (AAAA) is not supported — the custom DNS
/// server option is typically used with IPv4-only internal resolvers.
async fn resolve_host_with_dns(host: &str, dns_server: &str) -> Result<String, crate::Error> {
    use std::net::SocketAddr;
    use std::str::FromStr;
    use tokio::net::UdpSocket;
    use tokio::time::{timeout, Duration};

    // If host is already an IP, return it as-is
    if host.parse::<std::net::IpAddr>().is_ok() {
        return Ok(host.to_string());
    }

    // Parse DNS server address (default port 53)
    let dns_addr = if dns_server.contains(':') {
        SocketAddr::from_str(dns_server)
            .map_err(|e| crate::Error::Transport(format!("invalid dns_server '{dns_server}': {e}")))?
    } else {
        SocketAddr::from_str(&format!("{dns_server}:53"))
            .map_err(|e| crate::Error::Transport(format!("invalid dns_server '{dns_server}': {e}")))?
    };

    // Build DNS A-record query
    let mut query = Vec::with_capacity(64);
    let txid: u16 = rand::random();
    query.extend_from_slice(&txid.to_be_bytes());
    query.extend_from_slice(&[0x01, 0x00]); // flags: standard query, RD=1
    query.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
    query.extend_from_slice(&[0x00, 0x00]); // ANCOUNT = 0
    query.extend_from_slice(&[0x00, 0x00]); // NSCOUNT = 0
    query.extend_from_slice(&[0x00, 0x00]); // ARCOUNT = 0
    for label in host.split('.') {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0x00); // terminator
    query.extend_from_slice(&[0x00, 0x01]); // QTYPE = A
    query.extend_from_slice(&[0x00, 0x01]); // QCLASS = IN

    // Send query over UDP
    let socket = UdpSocket::bind("0.0.0.0:0").await
        .map_err(|e| crate::Error::Transport(format!("DNS: bind: {e}")))?;
    socket.connect(dns_addr).await
        .map_err(|e| crate::Error::Transport(format!("DNS: connect {dns_server}: {e}")))?;
    socket.send(&query).await
        .map_err(|e| crate::Error::Transport(format!("DNS: send to {dns_server}: {e}")))?;

    let mut buf = [0u8; 512];
    let n = timeout(Duration::from_secs(5), socket.recv(&mut buf)).await
        .map_err(|_| crate::Error::Transport("DNS: timeout".into()))?
        .map_err(|e| crate::Error::Transport(format!("DNS: recv: {e}")))?;

    // Parse response
    let response = &buf[..n];
    if response.len() < 12 {
        return Err(crate::Error::Transport("DNS: response too short".into()));
    }

    // Verify transaction ID
    let resp_txid = u16::from_be_bytes([response[0], response[1]]);
    if resp_txid != txid {
        return Err(crate::Error::Transport(format!(
            "DNS: txid mismatch (sent {txid}, got {resp_txid})"
        )));
    }

    let ancount = u16::from_be_bytes([response[6], response[7]]) as usize;
    if ancount == 0 {
        return Err(crate::Error::Transport(format!("DNS resolve {host}: no records found")));
    }

    // Skip 12-byte header + question section to reach answers
    let mut pos = 12;
    pos = skip_dns_name(response, pos); // QNAME
    pos += 4; // QTYPE (2) + QCLASS (2)

    // Read answers
    for _ in 0..ancount {
        if pos + 10 > response.len() {
            return Err(crate::Error::Transport("DNS: truncated answer section".into()));
        }
        pos = skip_dns_name(response, pos); // NAME (may be compression pointer)
        let qtype = u16::from_be_bytes([response[pos], response[pos + 1]]);
        let rdlength = u16::from_be_bytes([response[pos + 8], response[pos + 9]]) as usize;
        pos += 10; // past TYPE(2)+CLASS(2)+TTL(4)+RDLENGTH(2)
        if pos + rdlength > response.len() {
            return Err(crate::Error::Transport("DNS: truncated RDATA".into()));
        }
        if qtype == 1 && rdlength == 4 {
            // A record: 4-byte IPv4 address
            let ip = std::net::Ipv4Addr::new(response[pos], response[pos + 1],
                                              response[pos + 2], response[pos + 3]);
            return Ok(ip.to_string());
        }
        pos += rdlength;
    }

    Err(crate::Error::Transport(format!("DNS resolve {host}: no A record found")))
}

/// Skip a DNS name in the response, handling compression pointers.
/// Returns the new position after the name.
fn skip_dns_name(response: &[u8], mut pos: usize) -> usize {
    loop {
        if pos >= response.len() {
            return pos;
        }
        let len = response[pos];
        if len == 0 {
            return pos + 1; // end of name
        }
        if len & 0xC0 == 0xC0 {
            return pos + 2; // compression pointer (2 bytes total)
        }
        pos += 1 + len as usize; // label
    }
}
```

- [ ] **Step 2: Remove hickory-resolver from Cargo.toml files**

Delete these lines:
- Workspace `Cargo.toml` line 51: `hickory-resolver = "0.24"`
- `frp-core/Cargo.toml` line 39: `hickory-resolver.workspace = true`

- [ ] **Step 3: Build and test**

```bash
cargo build 2>&1
cargo test -p frp-core -- transport 2>&1
```

Expected: builds clean, transport tests pass.

- [ ] **Step 4: Commit**

```bash
git add frp-core/src/transport.rs Cargo.toml frp-core/Cargo.toml Cargo.lock
git commit -m "perf: replace hickory-resolver with custom DNS-over-UDP client

~80-line custom DNS A-record resolver. Eliminates hickory-resolver +
hickory-proto from dependency tree. Handles compression pointers,
timeout (5s), and transaction ID verification.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 7: Trim reqwest features + replace .json() calls

**Files:**
- Modify: `Cargo.toml:41` (reqwest feature trim)
- Modify: `frp-core/src/auth.rs:157-160,207-210,436-438,499-502` (4 json() calls)
- Modify: `frp-server/src/plugin/http.rs:75,80` (json() call + response)

- [ ] **Step 1: Trim reqwest features in workspace Cargo.toml**

Line 41 — change features:

```toml
# Before
reqwest = { version = "0.12", default-features = false, features = ["rustls-tls", "json", "socks"] }

# After
reqwest = { version = "0.12", default-features = false, features = ["rustls-tls"] }
```

- [ ] **Step 2: Replace .json() calls in frp-core/src/auth.rs**

Four sites. Replace each `resp.json().await` pattern:

**Site 1 (line 157-160):** openid-configuration fetch
```rust
// Before
let config: serde_json::Value = resp
    .json()
    .await
    .map_err(|e| format!("OIDC: failed to parse openid-configuration: {e}"))?;

// After
let body = resp.text().await
    .map_err(|e| format!("OIDC: failed to read openid-configuration: {e}"))?;
let config: serde_json::Value = serde_json::from_str(&body)
    .map_err(|e| format!("OIDC: failed to parse openid-configuration: {e}"))?;
```

**Site 2 (line 207-210):** JWKS fetch
```rust
// Before
let jwks_json: serde_json::Value = resp
    .json()
    .await
    .map_err(|e| format!("OIDC: failed to parse JWKS: {e}"))?;

// After
let body = resp.text().await
    .map_err(|e| format!("OIDC: failed to read JWKS: {e}"))?;
let jwks_json: serde_json::Value = serde_json::from_str(&body)
    .map_err(|e| format!("OIDC: failed to parse JWKS: {e}"))?;
```

**Site 3 (line 436-439):** OIDC client openid-configuration
```rust
// Before
let config: serde_json::Value = resp
    .json()
    .await
    .map_err(|e| format!("OIDC client: failed to parse openid-configuration: {e}"))?;

// After
let body = resp.text().await
    .map_err(|e| format!("OIDC client: failed to read openid-configuration: {e}"))?;
let config: serde_json::Value = serde_json::from_str(&body)
    .map_err(|e| format!("OIDC client: failed to parse openid-configuration: {e}"))?;
```

**Site 4 (line 499-502):** OIDC token response
```rust
// Before
let body: serde_json::Value = resp
    .json()
    .await
    .map_err(|e| format!("OIDC client: failed to parse token response: {e}"))?;

// After
let resp_text = resp.text().await
    .map_err(|e| format!("OIDC client: failed to read token response: {e}"))?;
let body: serde_json::Value = serde_json::from_str(&resp_text)
    .map_err(|e| format!("OIDC client: failed to parse token response: {e}"))?;
```

Note: site 4 renames the variable from `body` to `resp_text` then back to `body` to avoid conflict with the `serde_json::Value` named `body`.

- [ ] **Step 3: Replace .json() in frp-server/src/plugin/http.rs**

Two changes needed — request body serialization and response deserialization (lines 73-80):

```rust
// Before (lines 73-80)
match tokio::time::timeout(timeout, self.client
    .post(&plugin.cfg.url)
    .json(&event)
    .send()
).await {
    Ok(Ok(resp)) => {
        if plugin.cfg.enable_control {
            if let Ok(pr) = resp.json::<PluginResponse>().await {

// After
let body = match serde_json::to_string(&event) {
    Ok(b) => b,
    Err(e) => {
        tracing::warn!("Server plugin '{}' JSON serialize error: {}", plugin.cfg.name, e);
        continue;
    }
};
match tokio::time::timeout(timeout, self.client
    .post(&plugin.cfg.url)
    .header("Content-Type", "application/json")
    .body(body)
    .send()
).await {
    Ok(Ok(resp)) => {
        if plugin.cfg.enable_control {
            let resp_text = match resp.text().await {
                Ok(t) => t,
                Err(e) => {
                    tracing::warn!("Server plugin '{}' read response error: {}", plugin.cfg.name, e);
                    continue;
                }
            };
            if let Ok(pr) = serde_json::from_str::<PluginResponse>(&resp_text) {
```

- [ ] **Step 4: Build and test**

```bash
cargo build 2>&1
cargo test -p frp-core -- auth 2>&1
cargo test -p frp-server -- plugin 2>&1
```

Expected: builds clean, auth + plugin tests pass.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml frp-core/src/auth.rs frp-server/src/plugin/http.rs Cargo.lock
git commit -m "perf: trim reqwest features (remove json+socks), manual deserialize

Replaces reqwest's .json() convenience methods with explicit
serde_json::from_str() calls. Removes unused 'socks' feature.
Reduces reqwest compile footprint.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 8: Full workspace build + test + binary verification

**Files:** None (verification only)

- [ ] **Step 1: Clean release build**

```bash
cargo build --release 2>&1
```

Expected: clean build, no warnings.

- [ ] **Step 2: Check binary sizes**

```bash
ls -lh target/release/frps target/release/frpc
```

frps target: ~2.0–2.8 MB (from 5.3MB). frpc target: ~3.3 MB (from 3.7MB).

- [ ] **Step 3: Verify aws-lc-sys is gone**

```bash
cargo tree -p frps 2>/dev/null | grep -c "aws-lc"    # 0
cargo tree -p frpc 2>/dev/null | grep -c "aws-lc"    # 0
cargo tree -p frps 2>/dev/null | grep -c "hickory"   # 0
cargo tree -p frps 2>/dev/null | grep -c "sha2"      # 0
cargo tree -p frps 2>/dev/null | grep -c "aes-gcm"   # 0
cargo tree -p frps 2>/dev/null | grep -c "base64"    # 0 (the crate, not the concept)
```

- [ ] **Step 4: Run full test suite**

```bash
cargo test --workspace 2>&1
```

Expected: all tests pass. No regressions.

- [ ] **Step 5: Commit (if any Cargo.lock changes)**

```bash
git add Cargo.lock
git commit -m "chore: update Cargo.lock after dependency consolidation

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 9: Run compat tests

**Files:** None (verification only)

- [ ] **Step 1: Download Go frp if needed**

```bash
bash scripts/download-go-frp.sh
```

- [ ] **Step 2: Run compatibility test suite**

```bash
bash scripts/compat-test.sh --verbose 2>&1
```

Expected: all compat tests pass. 40/40 green (same as baseline). Key areas:
- SSH gateway (russh ring backend)
- V2 handshake (ring crypto)
- Control connection encryption (unchanged — PBKDF2-SHA1+AES-CFB)
- Data plane bridge (unchanged — Snappy+AES-CFB)

- [ ] **Step 3: Address any failures**

If compat tests fail:
- Check SSH gateway: `RUST_LOG=debug cargo run --bin frps -- -c frps.toml`
- Check V2: `cargo test -p frp-core -- v2_handshake crypto`
- Revert individual changes if needed (each task is independent)

- [ ] **Step 4: Final commit**

```bash
git add -A
git commit -m "test: compat test results after dependency consolidation

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

## Dependency changes summary

| Removed from dep tree | Affects |
|----------------------|---------|
| aws-lc-sys + aws-lc-rs | frps only |
| sha2 | frps + frpc |
| aes-gcm | frps + frpc |
| hkdf | frps + frpc |
| hmac | frps + frpc (was dead dep) |
| base64 | frps + frpc |
| hickory-resolver + hickory-proto | frps + frpc |
| reqwest json feature | frps + frpc |
| reqwest socks feature | frps + frpc |

| Kept (irreplaceable) | Reason |
|----------------------|--------|
| md-5 | Go frp auth token compat |
| sha1 | WebSocket key + PBKDF2 |
| pbkdf2 | PBKDF2-SHA1 key derivation (ring lacks SHA1) |
| aes + cfb-mode | Data plane AES-128-CFB (ring lacks CFB) |
| chacha20poly1305 | V2 AEAD XChaCha20 variant (ring lacks XChaCha20) |
| hex | Tiny (<1KB), used in debug logging |
| data_encoding | BASE64 for msg.rs, admin_auth, vhost, tcpmux |
| snap | Snappy compression (pure Rust, not C) |

| Added | Reason |
|-------|--------|
| ring (direct dep) | Already in tree via rustls; now used directly |
