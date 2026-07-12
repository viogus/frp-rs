# P0 Copy Elimination — Design Spec

**Date:** 2026-07-12
**Status:** approved
**Scope:** Two independent copy-elimination optimizations in frp-core, zero behavioral change.

---

## P0-1: CipherWriter In-Place Encrypt

### Problem

`CipherWriter::poll_write` (`frp-core/src/cipher_stream.rs:347-349`) copies caller
data into `self.scratch` via `extend_from_slice`, then encrypts scratch. The
encrypted bridge loop in `bridge.rs` already owns plaintext in a `PoolGuard`
buffer — the copy is pure waste (32 KiB per chunk on hot data-plane path).

### Design

Add `CipherWriter::write_encrypted(&mut self, data: &mut [u8])` — encrypts `data`
in-place via CFB then writes to the inner transport. Caller passes a mutable
slice; caller's buffer becomes ciphertext.

```rust
impl<W: AsyncWrite + Unpin> CipherWriter<W> {
    /// Encrypt `data` in-place and write to underlying transport.
    /// `data` is modified — caller must not read it after this call.
    /// IV must already have been sent (first write via poll_write or send_iv).
    pub async fn write_encrypted(&mut self, data: &mut [u8]) -> Result<usize, io::Error> {
        if !self.iv_sent {
            // Send IV if not yet sent (first write in session)
            self.send_iv().await?;
        }
        let cfb = self.cfb.as_mut().expect("IV must be set");
        cfb.encrypt(data);
        self.inner.write_all(data).await?;
        Ok(data.len())
    }

    async fn send_iv(&mut self) -> Result<(), io::Error> {
        self.iv_sent = true;
        let mut iv = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut iv);
        self.cfb = Some(CfbState::new(&self.key, &iv));
        self.inner.write_all(&iv).await
    }
}
```

### Bridge Integration

In `bridge_encrypted` (`bridge.rs`), replace `enc_work_w.write_all()` with
`enc_work_w.write_encrypted()` on the `user_to_work` path where plaintext is
available as `&mut [u8]`:

```rust
// Before (line 150):
if enc_work_w.write_all(processed.as_ref()).await.is_err() { break; }

// After:
if enc_work_w.write_encrypted(&mut processed_bytes).await.is_err() { break; }
```

The `processed` value from `compress_chunk` returns `Cow<[u8]>` — if it's a
`Cow::Owned(Vec)`, we pass `&mut vec[..]`; if `Cow::Borrowed`, we must copy to a
scratch Vec first (compression disabled case — plaintext from pool buffer).
Alternative: pass the pool buffer directly to `write_encrypted` when compression
is off, skipping the `compress_chunk` intermediary. This is the common case
(compression is opt-in; most connections are plain-encrypted).

### Constraints

- CFB encryption is deterministic: same key+IV+plaintext → same ciphertext. In-place
  produces identical output to the old `scratch.extend_from_slice` path.
- `poll_write` keeps its `scratch` path unchanged for generic `AsyncWrite` users.
- The `write_encrypted` method is for callers who own mutable plaintext and don't
  need it after encryption.

---

## P0-2: AEAD Copy Elimination

### Problem

`AeadAlgorithm::encrypt` and `decrypt` (`frp-core/src/crypto.rs:120-161`) take
`&[u8]` plaintext/ciphertext, forcing internal `to_vec()` copies. Decrypt makes
two copies: `ciphertext.to_vec()` then `plaintext.to_vec()`.

`ring`'s `seal_in_place_append_tag` and `open_in_place` already operate on mutable
buffers in-place. The copies are in the wrapper, not the crypto primitive.

### Design

Change signatures to accept owned `Vec<u8>` — caller transfers ownership, callee
encrypts/decrypts in-place, returns the (possibly resized) Vec:

```rust
// Before:
fn encrypt(&self, nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, String>
fn decrypt(&self, nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, String>

// After:
fn encrypt(&self, nonce: &[u8], mut in_out: Vec<u8>, aad: &[u8]) -> Result<Vec<u8>, String>
fn decrypt(&self, nonce: &[u8], mut in_out: Vec<u8>, aad: &[u8]) -> Result<Vec<u8>, String>
```

Encrypt implementation (Aes256Gcm):
```rust
key.seal_in_place_append_tag(nonce, Aad::from(aad), &mut in_out)
    .map_err(|e| format!("aes-gcm encrypt: {e}"))?;
Ok(in_out) // tag appended, no copy
```

Decrypt implementation (Aes256Gcm):
```rust
let plaintext_len = key.open_in_place(nonce, Aad::from(aad), &mut in_out)
    .map_err(|e| format!("aes-gcm decrypt: {e}"))?;
in_out.truncate(plaintext_len); // strip auth tag, 0 copy
Ok(in_out)
```

XChaCha20Poly1305 path:
```rust
// encrypt — chacha20poly1305 crate already takes Payload{msg, aad}
// and returns Vec<u8>. Pass plaintext as owned Vec.
let payload = chacha20poly1305::aead::Payload { msg: &in_out, aad };
let tag = c.encrypt(nonce, payload)?;
// Append tag
in_out.extend_from_slice(&tag);
Ok(in_out)

// decrypt — split tag from ciphertext, decrypt in-place
let tag_start = in_out.len().saturating_sub(16); // Poly1305 tag = 16 bytes
let (msg, tag) = in_out.split_at(tag_start);
let payload = chacha20poly1305::aead::Payload { msg, aad };
let plaintext = c.decrypt(nonce, payload)?;
Ok(plaintext) // chacha20poly1305 returns owned Vec
```

### Caller Impact

All `encrypt`/`decrypt` call sites (V2 handshake, V2 frame read/write) already
own the data. They pass `&data` today; changing to pass `data` (move) eliminates
the internal copy. No caller logic changes needed beyond removing `&`.

### Constraints

- Wire-identical output (same crypto, same order of operations).
- No allocation change in caller — data already on heap; we just avoid
  re-allocating inside the function.
- XChaCha20Poly1305 has slightly different API than ring — handled per variant.

---

## Testing Strategy

1. **Existing cipher_stream tests** (14 tests in `cipher_stream.rs`) — must pass
   unchanged. `poll_write` path untouched.
2. **New test:** `cipher_writer_write_encrypted_roundtrip` — write_encrypted →
   CipherReader decrypt → assert original plaintext.
3. **Existing crypto tests** — update for new signatures, verify roundtrip.
4. **Compat tests:** `bash scripts/compat-test.sh --ci` — 57/0, wire-identical.
5. **Throughput baseline:** `bash scripts/throughput-baseline.sh` — expect
   encrypted path improvement proportional to avoided copy.
