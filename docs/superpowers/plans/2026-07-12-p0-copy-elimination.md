# P0 Copy Elimination — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Eliminate per-chunk copies on the encrypted data path: CipherWriter in-place encrypt (32KB save per bridge chunk) and AEAD owned-buffer encrypt/decrypt (1-2 copies saved per V2 frame).

**Architecture:** Two independent changes in frp-core. P0-1 adds `write_encrypted(&mut self, data: &mut [u8])` to CipherWriter and restructures the encrypted bridge `user_to_work` loop to pass mutable buffers directly. P0-2 changes AeadAlgorithm::encrypt/decrypt signatures from `&[u8]` to `Vec<u8>` (ownership transfer), updating 3 call sites in AeadStream.

**Tech Stack:** Rust, tokio, ring, aes+cfb-mode, chacha20poly1305

## Global Constraints

- Zero new crate dependencies
- Wire-identical output (same key+IV+plaintext → same ciphertext)
- All existing tests pass: 14 cipher_stream tests, 409 workspace tests
- Compat tests: `bash scripts/compat-test.sh --ci` → 57 passed, 0 failed
- `poll_write` scratch path unchanged for generic AsyncWrite users

---

### Task 1: Add `write_encrypted` and `send_iv` to CipherWriter

**Files:**
- Modify: `frp-core/src/cipher_stream.rs:238-253` (CipherWriter impl)

**Interfaces:**
- Produces: `CipherWriter::send_iv(&mut self) -> io::Result<()>`, `CipherWriter::write_encrypted(&mut self, data: &mut [u8]) -> io::Result<usize>`

- [ ] **Step 1: Add `send_iv` helper method**

Read `frp-core/src/cipher_stream.rs` lines 225-253 to see the CipherWriter struct fields. Add this method after `new()`:

```rust
impl<W: AsyncWrite + Unpin> CipherWriter<W> {
    // ... existing new() stays

    /// Send the random IV to the peer. Must be called once before write_encrypted.
    /// Idempotent — subsequent calls are no-ops.
    async fn send_iv(&mut self) -> io::Result<()> {
        if self.iv_sent {
            return Ok(());
        }
        self.iv_sent = true;
        let mut iv = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut iv);
        self.cfb = Some(CfbState::new(&self.key, &iv));
        self.inner.write_all(&iv).await
    }
}
```

- [ ] **Step 2: Add `write_encrypted` method**

Add after `send_iv`:

```rust
    /// Encrypt `data` in-place (CFB) and write to the underlying transport.
    /// `data` is overwritten with ciphertext — caller must not read it after.
    /// IV must already be sent (via poll_write first write, poll_flush, or send_iv).
    pub async fn write_encrypted(&mut self, data: &mut [u8]) -> io::Result<usize> {
        self.send_iv().await?;
        let cfb = self.cfb.as_mut().expect("IV must be set after send_iv");
        cfb.encrypt(data);
        self.inner.write_all(data).await?;
        Ok(data.len())
    }
```

`CfbState::encrypt` already takes `&mut [u8]` (line ~50 of cipher_stream.rs) — no change needed.

- [ ] **Step 3: Write roundtrip test**

Add to the `mod tests` block at the bottom of `cipher_stream.rs`:

```rust
    #[tokio::test]
    async fn cipher_writer_write_encrypted_roundtrip() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (client, server) = tokio::io::duplex(4096);
        let key = [0xABu8; 16];
        let mut writer = CipherWriter::new(client, key);
        let mut reader = CipherReader::new(server, key);

        let mut plaintext = b"hello world encrypted in-place".to_vec();
        let expected = plaintext.clone();

        // write_encrypted sends IV then encrypts in-place
        writer.write_encrypted(&mut plaintext).await.unwrap();
        // plaintext is now ciphertext — verify it changed
        assert_ne!(&plaintext, &expected, "plaintext should be encrypted in-place");
        writer.inner.shutdown().await.unwrap();

        let mut decrypted = vec![0u8; expected.len()];
        reader.read_exact(&mut decrypted).await.unwrap();
        assert_eq!(&decrypted, &expected, "roundtrip should recover original");
    }
```

- [ ] **Step 4: Run tests**

```bash
cargo test -p frp-core -- cipher_stream 2>&1 | tail -20
```

Expected: 15 tests pass (14 existing + 1 new). If CipherWriter is behind feature gates, also run:
```bash
cargo test -p frp-core 2>&1 | grep -E 'test result|FAILED'
```

- [ ] **Step 5: Commit**

```bash
git add frp-core/src/cipher_stream.rs
git commit -m "feat(cipher): add write_encrypted for in-place CFB encrypt to CipherWriter"
```

---

### Task 2: Integrate `write_encrypted` into encrypted bridge

**Files:**
- Modify: `frp-core/src/bridge.rs:119-151` (bridge_encrypted user_to_work loop)

**Interfaces:**
- Consumes: `CipherWriter::write_encrypted(&mut self, data: &mut [u8]) -> io::Result<usize>` (from Task 1)
- Produces: bridge_encrypted user_to_work path skips one copy per chunk

- [ ] **Step 1: Restructure user_to_work loop in bridge_encrypted**

Current code at `bridge.rs` lines 119-152:
```rust
let user_to_work = async {
    if !pre_read.is_empty()
        && enc_work_w.write_all(&pre_read).await.is_err()
    {
        return;
    }
    let mut buf = PoolGuard::acquire();
    loop {
        let n = match user_r.read(buf.as_mut_slice()).await {
            Ok(0) => break,
            Ok(n) => { ... n }
            Err(_) => break,
        };
        let payload = &buf.data()[..n];
        let processed = match compress_chunk(payload, use_compression) {
            Some(p) => p,
            None => break,
        };
        if let Some(ref mut lim) = write_limiter {
            lim.consume(processed.len()).await;
        }
        if enc_work_w.write_all(processed.as_ref()).await.is_err() { break; }
        if enc_work_w.flush().await.is_err() { break; }
    }
    ...
};
```

Replace with:
```rust
let user_to_work = async {
    // Pre-read bytes (VHost HTTP parsing): encrypt via normal write path.
    if !pre_read.is_empty()
        && enc_work_w.write_all(&pre_read).await.is_err()
    {
        return;
    }
    let mut buf = PoolGuard::acquire();
    loop {
        let n = match user_r.read(buf.as_mut_slice()).await {
            Ok(0) => break,
            Ok(n) => {
                if let Some(ref m) = metrics {
                    m.bytes_in.fetch_add(n as u64, Ordering::Relaxed);
                }
                n
            }
            Err(_) => break,
        };

        if use_compression {
            // Compress into owned Vec, then encrypt in-place before write.
            let compressed = match compress_chunk(&buf.data()[..n], true) {
                Some(p) => p.into_owned(),
                None => break,
            };
            if let Some(ref mut lim) = write_limiter {
                lim.consume(compressed.len()).await;
            }
            let mut compressed = compressed; // ensure mutable
            if enc_work_w.write_encrypted(&mut compressed).await.is_err() { break; }
        } else {
            // No compression: encrypt pool buffer slice in-place.
            let slice = &mut buf.as_mut_slice()[..n];
            if let Some(ref mut lim) = write_limiter {
                lim.consume(slice.len()).await;
            }
            if enc_work_w.write_encrypted(slice).await.is_err() { break; }
        }
        if enc_work_w.flush().await.is_err() { break; }
    }
    ...
};
```

The `compress_chunk` import and the `compress_chunk` function stay — `work_to_user` path still uses `decompress_chunk`.

- [ ] **Step 2: Build and run tests**

```bash
cargo build -p frp-core 2>&1 | tail -5
cargo test -p frp-core 2>&1 | grep -E 'test result|FAILED'
```

Expected: build clean, tests pass.

- [ ] **Step 3: Run compat tests**

```bash
cargo build --release -p frps -p frpc 2>&1 | tail -3
bash scripts/compat-test.sh --ci 2>&1 | grep -E 'RESULTS|passed|failed'
```

Expected: 57 passed, 0 failed. Wire-identical — CFB in-place produces same ciphertext.

- [ ] **Step 4: Commit**

```bash
git add frp-core/src/bridge.rs
git commit -m "perf(bridge): use write_encrypted in encrypted user_to_work path — skip 32KB copy"
```

---

### Task 3: Change AEAD encrypt/decrypt to accept owned Vec

**Files:**
- Modify: `frp-core/src/crypto.rs:120-161` (AeadAlgorithm impl encrypt/decrypt methods)
- Modify: `frp-core/src/crypto.rs:381,510,541` (call sites in AeadStream)

**Interfaces:**
- Consumes: nothing from earlier tasks (independent of P0-1)
- Produces: `AeadAlgorithm::encrypt(&self, nonce: &[u8], in_out: Vec<u8>, aad: &[u8]) -> Result<Vec<u8>, String>`, `AeadAlgorithm::decrypt(&self, nonce: &[u8], in_out: Vec<u8>, aad: &[u8]) -> Result<Vec<u8>, String>`

- [ ] **Step 1: Change encrypt/decrypt signatures and implementations**

Read `frp-core/src/crypto.rs` lines 101-162. Replace the `encrypt` and `decrypt` methods:

```rust
    fn encrypt(&self, nonce: &[u8], mut in_out: Vec<u8>, aad: &[u8]) -> Result<Vec<u8>, String> {
        match self {
            Self::Aes256Gcm(key) => {
                let nonce = Nonce::try_assume_unique_for_key(nonce)
                    .map_err(|e| format!("aes-gcm nonce: {e}"))?;
                let aad = Aad::from(aad);
                key.seal_in_place_append_tag(nonce, aad, &mut in_out)
                    .map_err(|e| format!("aes-gcm encrypt: {e}"))?;
                Ok(in_out)
            }
            #[cfg(feature = "chacha20")]
            Self::XChaCha20Poly1305(c) => {
                let nonce = chacha20poly1305::XNonce::from_slice(nonce);
                let tag = c.encrypt(nonce, chacha20poly1305::aead::Payload {
                    msg: &in_out,
                    aad,
                }).map_err(|e| format!("xchacha20 encrypt: {e}"))?;
                in_out.extend_from_slice(&tag);
                Ok(in_out)
            }
        }
    }

    fn decrypt(&self, nonce: &[u8], mut in_out: Vec<u8>, aad: &[u8]) -> Result<Vec<u8>, String> {
        match self {
            Self::Aes256Gcm(key) => {
                let nonce = Nonce::try_assume_unique_for_key(nonce)
                    .map_err(|e| format!("aes-gcm nonce: {e}"))?;
                let aad = Aad::from(aad);
                let plaintext_len = key.open_in_place(nonce, aad, &mut in_out)
                    .map_err(|e| format!("aes-gcm decrypt: {e}"))?
                    .len();
                in_out.truncate(plaintext_len);
                Ok(in_out)
            }
            #[cfg(feature = "chacha20")]
            Self::XChaCha20Poly1305(c) => {
                let nonce = chacha20poly1305::XNonce::from_slice(nonce);
                c.decrypt(nonce, chacha20poly1305::aead::Payload {
                    msg: &in_out,
                    aad,
                }).map_err(|e| format!("xchacha20 decrypt: {e}"))
            }
        }
    }
```

Key changes:
- Parameter `plaintext: &[u8]` → `in_out: Vec<u8>` (encrypt), `ciphertext: &[u8]` → `in_out: Vec<u8>` (decrypt)
- Aes256Gcm encrypt: `seal_in_place_append_tag` appends tag to `in_out` in-place
- Aes256Gcm decrypt: `open_in_place` decrypts in-place, `truncate` strips tag
- XChaCha20Poly1305 encrypt: encrypt in-place, append tag via `extend_from_slice`
- XChaCha20Poly1305 decrypt: pass `&in_out` as msg, crate returns owned Vec

- [ ] **Step 2: Update AeadStream call sites**

Call site 1 — `AeadStream::read_frame` at line 381:
```rust
// Before:
let plaintext = match self.read_cipher.decrypt(&self.read_nonce, &ciphertext, &aad) {
// After (ciphertext is already a Vec<u8> from read_exact):
let plaintext = match self.read_cipher.decrypt(&self.read_nonce, ciphertext, &aad) {
```

Call sites 2 & 3 — `AeadStream::poll_write` at lines 510 and 541:
```rust
// Before:
let sealed = match this.write_cipher.encrypt(&this.write_nonce, plaintext, &aad) {
// After (plaintext is &[u8] from caller's buffer):
let sealed = match this.write_cipher.encrypt(&this.write_nonce, plaintext.to_vec(), &aad) {
```

Note: the write path still does `to_vec()` at the call site because `poll_write` receives `&[u8]` from the AsyncWrite contract. This is acceptable — the decrypt path saves two copies, which is the hotter path (every V2 read frame). A future optimization could buffer writes into a reusable Vec.

- [ ] **Step 3: Update test call sites**

Find test call sites in `crypto.rs` that call `encrypt`/`decrypt`:
```bash
grep -n '\.encrypt(\|\.decrypt(' frp-core/src/crypto.rs | grep -v 'c\.encrypt\|c\.decrypt\|read_cipher\|write_cipher\|seal_in_place\|open_in_place'
```

Update each test call from `alg.encrypt(&nonce, &plaintext, &aad)` to `alg.encrypt(&nonce, plaintext, &aad)` (remove `&`, pass owned Vec).

- [ ] **Step 4: Build and test**

```bash
cargo build -p frp-core 2>&1 | tail -5
cargo test -p frp-core -- crypto 2>&1 | grep -E 'test result|FAILED'
```

- [ ] **Step 5: Commit**

```bash
git add frp-core/src/crypto.rs
git commit -m "perf(crypto): AEAD encrypt/decrypt accept owned Vec — skip 1-2 copies per V2 frame"
```

---

### Task 4: Integration verification

- [ ] **Step 1: Full workspace build and test**

```bash
cargo build --workspace 2>&1 | tail -5
cargo test --workspace 2>&1 | tail -5
cargo clippy --workspace 2>&1 | tail -5
```

Expected: build clean, tests pass, no new clippy warnings.

- [ ] **Step 2: Compat test suite**

```bash
cargo build --release -p frps -p frpc 2>&1 | tail -3
bash scripts/compat-test.sh --ci 2>&1 | grep -E 'RESULTS|passed|failed'
```

Expected: 57 passed, 0 failed.

- [ ] **Step 3: Throughput baseline (encrypted path)**

```bash
bash scripts/throughput-baseline.sh 2>&1 | grep -E 'encrypt|enc_compress|MB/s'
```

Expected: throughput unchanged or improved (copy elimination helps CPU-bound encrypted path).

- [ ] **Step 4: Commit**

```bash
git commit --allow-empty -m "test: verify P0 copy elimination — compat + throughput baseline"
```

---

## Review Gates

1. Workspace build clean
2. `cargo test --workspace` — all pass
3. `cargo clippy --workspace` — no new warnings
4. `bash scripts/compat-test.sh --ci` — 57 passed, 0 failed (wire-identical)
5. Throughput baseline: encrypted path no regression

