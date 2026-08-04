//! Encryption primitives for the frp control connection and data plane.
//!
//! # Security Note: V1 CFB is confidentiality-only
//!
//! AES-128-CFB (V1 protocol) provides **confidentiality only** — it has no
//! integrity protection. An attacker who can modify ciphertext can predictably
//! flip bits in the decrypted plaintext (CFB malleability). This is acceptable
//! for the frp V1 control channel because:
//! - The channel carries structured JSON messages — bit flips produce invalid
//!   JSON, which is caught by serde deserialization.
//! - The attacker must be on-path (MITM between client and server).
//! - TLS wraps the transport when available, providing AEAD at the transport
//!   layer.
//!
//! **Prefer V2 protocol** which uses AEAD (AES-256-GCM or XChaCha20-Poly1305)
//! with HKDF-SHA256 key derivation. V2 provides authenticated encryption
//! (confidentiality + integrity) and is the recommended protocol for new
//! deployments. See `frp_core::crypto` and `frp_core::v2_handshake`.
//!
//! PBKDF2-SHA1 with 64 iterations and salt "frp" matches the Go frp v0.69.1
//! binary for wire compatibility. Do not increase iterations — it would break
//! interop with Go frp.

use cfb_mode::cipher::KeyIvInit;
use rand::RngCore;

type Aes128CfbEnc = cfb_mode::Encryptor<aes::Aes128>;
type Aes128CfbDec = cfb_mode::Decryptor<aes::Aes128>;

/// Derive an AES-128 key from a token using PBKDF2-SHA1.
/// Matches Go frp v0.69.1 binary: pbkdf2.Key(token, "frp", 64, 16, sha1.New)
///
/// SECURITY NOTE: V1 uses PBKDF2-SHA1 with 64 iterations and salt="frp" for
/// Go frp wire compatibility. This provides minimal brute-force protection.
/// Prefer V2 protocol (AEAD with HKDF-SHA256) for stronger key derivation.
/// Do not increase iterations: it breaks Go frp interop.
pub fn derive_key(token: &str) -> [u8; 16] {
    let mut key = [0u8; 16];
    pbkdf2::pbkdf2_hmac::<sha1::Sha1>(token.as_bytes(), b"frp", 64, &mut key);
    key
}

/// Encrypt data using AES-128-CFB with a random 16-byte IV.
/// Returns: [16-byte IV][ciphertext]
pub fn encrypt(data: &[u8], key: &[u8; 16]) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(data.len() + 16);
    encrypt_into(data, key, &mut out)?;
    Ok(out)
}

/// Encrypt into an existing buffer, reusing its allocation.
/// Output layout identical to [`encrypt`]: [16-byte IV][ciphertext].
pub fn encrypt_into(data: &[u8], key: &[u8; 16], out: &mut Vec<u8>) -> Result<(), String> {
    let mut iv = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut iv);
    out.clear();
    out.extend_from_slice(&iv);
    out.extend_from_slice(data);
    let cipher = Aes128CfbEnc::new(key.into(), &iv.into());
    cipher.encrypt(&mut out[16..]);
    Ok(())
}

/// Decrypt data using AES-128-CFB.
/// Input: [16-byte IV][ciphertext]
pub fn decrypt(data: &[u8], key: &[u8; 16]) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(data.len().saturating_sub(16));
    decrypt_into(data, key, &mut out)?;
    Ok(out)
}

/// Decrypt into an existing buffer, reusing its allocation.
/// Output identical to [`decrypt`].
pub fn decrypt_into(data: &[u8], key: &[u8; 16], out: &mut Vec<u8>) -> Result<(), String> {
    if data.len() < 16 {
        return Err("data too short for AES-CFB (need at least 16-byte IV)".into());
    }
    let iv: &[u8; 16] = data[..16]
        .try_into()
        .expect("IV is exactly 16 bytes: length checked above");
    let ciphertext = &data[16..];
    out.clear();
    out.extend_from_slice(ciphertext);
    let cipher = Aes128CfbDec::new(key.into(), iv.into());
    cipher.decrypt(out);
    Ok(())
}

/// Compress data using Snappy (matching Go frp v0.69.1).
#[cfg(feature = "compression")]
pub fn compress(data: &[u8]) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    compress_into(data, &mut buf)?;
    Ok(buf)
}

/// Compress data into an existing buffer, reusing its allocation.
/// The buffer is cleared before writing; its capacity grows to accommodate
/// the maximum compressed size and stabilizes after the first few chunks.
#[cfg(feature = "compression")]
pub fn compress_into(data: &[u8], buf: &mut Vec<u8>) -> Result<(), String> {
    use snap::write::FrameEncoder;
    use std::io::Write;
    buf.clear();
    let mut encoder = FrameEncoder::new(&mut *buf);
    encoder
        .write_all(data)
        .map_err(|e| format!("snappy compress: {e}"))?;
    encoder
        .into_inner()
        .map_err(|e| format!("snappy finalize: {e}"))?;
    Ok(())
}

/// Reusable Snappy stream compressor for high-throughput data-plane paths.
///
/// The wrapped [`snap::write::FrameEncoder`] is created once for the
/// connection lifetime and reused across chunks, eliminating the ~128 KiB
/// allocation (64 KiB source buffer + 64 KiB destination scratch) the encoder
/// pays on every construction.
///
/// Wire format: the 10-byte `sNaPpY` stream identifier is emitted only by the
/// first compressed chunk; subsequent chunks are plain Snappy data frames.
/// This is valid Snappy stream framing — the identifier may legally appear
/// once, at stream start — and is byte-compatible with both the per-chunk
/// [`compress_into`] output (which repeats the identifier on every chunk) and
/// Go frp's `snappy.Writer` output. Streaming decoders such as
/// [`SnappyDecompressor`] and Go's `snappy.Reader` accept either form.
#[cfg(feature = "compression")]
pub struct SnappyCompressor {
    encoder: snap::write::FrameEncoder<Vec<u8>>,
}

#[cfg(feature = "compression")]
impl Default for SnappyCompressor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "compression")]
impl SnappyCompressor {
    pub fn new() -> Self {
        Self {
            encoder: snap::write::FrameEncoder::new(Vec::new()),
        }
    }

    /// Compress `data`, replacing the contents of `out` with the framed
    /// output.
    ///
    /// The encoder's internal sink is swapped with the caller's `out`
    /// allocation, so both buffers keep their capacity and steady-state
    /// compression performs no heap allocation per chunk.
    pub fn compress(&mut self, data: &[u8], out: &mut Vec<u8>) -> Result<(), String> {
        use std::io::Write;
        self.encoder.get_mut().clear();
        self.encoder
            .write_all(data)
            .map_err(|e| format!("snappy compress: {e}"))?;
        self.encoder
            .flush()
            .map_err(|e| format!("snappy flush: {e}"))?;
        std::mem::swap(out, self.encoder.get_mut());
        Ok(())
    }
}

#[cfg(not(feature = "compression"))]
pub fn compress(_data: &[u8]) -> Result<Vec<u8>, String> {
    Err("compression not compiled".into())
}

#[cfg(not(feature = "compression"))]
pub fn compress_into(_data: &[u8], _buf: &mut Vec<u8>) -> Result<(), String> {
    Err("compression not compiled".into())
}

#[cfg(not(feature = "compression"))]
pub struct SnappyCompressor;

#[cfg(not(feature = "compression"))]
impl SnappyCompressor {
    pub fn new() -> Self {
        Self
    }
    pub fn compress(&mut self, _data: &[u8], _out: &mut Vec<u8>) -> Result<(), String> {
        Err("compression not compiled".into())
    }
}

/// Decompress Snappy-compressed data.
#[cfg(feature = "compression")]
pub fn decompress(data: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    decompress_into(data, &mut out)?;
    Ok(out)
}

/// Decompress into an existing buffer, reusing its allocation.
/// Output identical to [`decompress`].
#[cfg(feature = "compression")]
pub fn decompress_into(data: &[u8], out: &mut Vec<u8>) -> Result<(), String> {
    use snap::read::FrameDecoder;
    use std::io::Read;
    let mut decoder = FrameDecoder::new(data);
    out.clear();
    decoder
        .read_to_end(out)
        .map_err(|e| format!("snappy decompress: {e}"))?;
    Ok(())
}

#[cfg(not(feature = "compression"))]
pub fn decompress_into(_data: &[u8], _out: &mut Vec<u8>) -> Result<(), String> {
    Err("compression not compiled".into())
}

/// Streaming Snappy decompressor for use in bridges.
///
/// Unlike [`decompress`], this handles data arriving in arbitrary TCP chunks:
/// partial snappy frames are buffered internally until a complete frame is
/// available, then decompressed.  This avoids "unexpected EOF" errors when a
/// `read()` boundary does not align with a snappy frame boundary.
#[cfg(feature = "compression")]
pub struct SnappyDecompressor {
    buf: Vec<u8>,
    offset: usize,
    /// Reusable decompressed-output scratch. Kept at the largest frame size
    /// seen so far so `decompress` overwrites it in place instead of paying
    /// a per-frame zero-fill or allocation.
    scratch: Vec<u8>,
}

/// State returned by [`SnappyDecompressor::feed_into_progress`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnappyFeedStatus {
    /// Another complete frame can be processed without supplying more input.
    pub has_more_complete: bool,
    /// Buffered bytes remain, but they do not yet form a complete frame.
    pub has_pending_partial: bool,
}

#[cfg(feature = "compression")]
impl Default for SnappyDecompressor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "compression")]
impl SnappyDecompressor {
    pub fn new() -> Self {
        Self {
            buf: Vec::new(),
            offset: 0,
            scratch: Vec::new(),
        }
    }

    /// Feed compressed bytes into the decompressor.
    ///
    /// Returns at most one decompressed data chunk. Complete later frames and
    /// an incomplete tail are retained; call `feed(&[])` to drain them before
    /// reading more compressed input. This supplies bounded backpressure.
    ///
    /// Returns an error only for truly corrupt input (bad magic, bad CRC);
    /// partial frames are silently buffered, not treated as errors.
    pub fn feed(&mut self, data: &[u8]) -> Result<Vec<u8>, String> {
        let mut out = Vec::new();
        self.feed_into(data, &mut out)?;
        Ok(out)
    }

    /// Like [`feed`], but writes at most one chunk into an existing buffer,
    /// reusing its allocation. This compatibility API skips metadata internally
    /// until it produces data or needs more input. Use [`feed_into_progress`]
    /// when each call must have a fixed metadata-work budget.
    pub fn feed_into(&mut self, data: &[u8], out: &mut Vec<u8>) -> Result<(), String> {
        let mut status = self.feed_into_progress(data, out)?;
        let mut metadata_batches = 1usize;
        while out.is_empty() && status.has_more_complete {
            if metadata_batches >= 16 {
                return Err(
                    "snappy: legacy metadata work limit exceeded; use feed_into_progress".into(),
                );
            }
            status = self.feed_into_progress(&[], out)?;
            metadata_batches += 1;
        }
        Ok(())
    }

    /// Process at most 1024 metadata frames and at most one data frame.
    ///
    /// The returned status explicitly tells callers whether to drain again or
    /// wait for more input, so an empty output is never ambiguous.
    pub fn feed_into_progress(
        &mut self,
        data: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<SnappyFeedStatus, String> {
        out.clear();
        self.feed_into_step_core(data, out)
    }

    /// Append variant of [`feed_into_progress`]: decoded output is appended to
    /// `out` instead of replacing its contents. Callers that batch many frames
    /// into one buffer (e.g. the work→user bridge) can feed repeatedly into
    /// the same `out` without a per-frame memcpy through a scratch buffer.
    pub fn feed_into_append_progress(
        &mut self,
        data: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<SnappyFeedStatus, String> {
        self.feed_into_step_core(data, out)
    }

    fn feed_into_step_core(
        &mut self,
        data: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<SnappyFeedStatus, String> {
        self.feed_into_step(data, out)?;
        let has_more_complete = self.has_complete_frame();
        Ok(SnappyFeedStatus {
            has_more_complete,
            has_pending_partial: self.has_pending() && !has_more_complete,
        })
    }

    fn feed_into_step(&mut self, data: &[u8], out: &mut Vec<u8>) -> Result<(), String> {
        const MAX_SNAPPY_CHUNK: usize = 128 * 1024;
        const MAX_SNAPPY_PENDING: usize = 16 * 1024 * 1024;
        const MAX_FRAMES_PER_CALL: usize = 1024;

        // Note: `out` is *not* cleared here. Callers decide replace vs append
        // semantics: feed_into_progress clears before calling, while
        // feed_into_append_progress appends into the caller's buffer.
        if self.offset > 0 && !data.is_empty() {
            self.buf.drain(..self.offset);
            self.offset = 0;
        }
        let mut remaining = data;
        let stream_body = b"sNaPpY";

        // Complete and validate the first pending header before copying a
        // co-delivered payload. Remaining bytes share one contiguous buffer.
        if self.buf.len() < 4 {
            let take = (4 - self.buf.len()).min(remaining.len());
            self.buf.extend_from_slice(&remaining[..take]);
            remaining = &remaining[take..];
        }
        if self.buf.len() >= 4 {
            let chunk_len = u32::from_le_bytes([self.buf[1], self.buf[2], self.buf[3], 0]) as usize;
            if chunk_len > MAX_SNAPPY_CHUNK {
                return Err(format!(
                    "snappy: chunk length {chunk_len} exceeds {MAX_SNAPPY_CHUNK} byte limit"
                ));
            }
        }
        let new_len = self
            .buf
            .len()
            .checked_add(remaining.len())
            .ok_or_else(|| "snappy pending buffer length overflow".to_string())?;
        if new_len > MAX_SNAPPY_PENDING {
            return Err("snappy decompression buffer exhausted".into());
        }
        self.buf.extend_from_slice(remaining);

        // Drain bounded metadata work and at most one plaintext-producing frame.
        for _ in 0..MAX_FRAMES_PER_CALL {
            if self.offset + 4 > self.buf.len() {
                break;
            }
            let start = self.offset;
            let chunk_type = self.buf[start];
            let chunk_len = u32::from_le_bytes([
                self.buf[start + 1],
                self.buf[start + 2],
                self.buf[start + 3],
                0,
            ]) as usize;
            if chunk_len > MAX_SNAPPY_CHUNK {
                return Err(format!(
                    "snappy: chunk length {chunk_len} exceeds {MAX_SNAPPY_CHUNK} byte limit"
                ));
            }
            let total = 4 + chunk_len;
            if start + total > self.buf.len() {
                break;
            }
            match chunk_type {
                0x00 => {
                    // Compressed data: length field includes 4-byte CRC.
                    if chunk_len < 4 {
                        return Err("snappy: compressed chunk length too small".into());
                    }
                    // Skip 4-byte header (already read) + 4-byte CRC
                    let compressed = &self.buf[start + 8..start + total];
                    let decompressed_len = snap::raw::decompress_len(compressed)
                        .map_err(|e| format!("snappy decompress: {e}"))?;
                    if decompressed_len > MAX_SNAPPY_CHUNK {
                        return Err(format!(
                            "snappy: decompressed output {decompressed_len} exceeds per-chunk {MAX_SNAPPY_CHUNK} byte limit"
                        ));
                    }
                    if self.scratch.len() < decompressed_len {
                        self.scratch.resize(decompressed_len, 0);
                    }
                    let mut decoder = snap::raw::Decoder::new();
                    let written = decoder
                        .decompress(compressed, &mut self.scratch[..decompressed_len])
                        .map_err(|e| format!("snappy decompress: {e}"))?;
                    if written != decompressed_len {
                        return Err("snappy: decompressed output length changed".into());
                    }
                    out.extend_from_slice(&self.scratch[..written]);
                    self.offset += total;
                    return Ok(());
                }
                0x01 => {
                    // Uncompressed data: length field includes 4-byte CRC.
                    if chunk_len < 4 {
                        return Err("snappy: uncompressed chunk length too small".into());
                    }
                    let chunk_data = &self.buf[start + 8..start + total];
                    out.extend_from_slice(chunk_data);
                    self.offset += total;
                    return Ok(());
                }
                0xFF => {
                    // Stream identifier: 4-byte header + body, NO CRC.
                    let body = &self.buf[start + 4..start + total];
                    if body != stream_body {
                        return Err(format!("snappy: bad stream identifier: {:?}", body));
                    }
                }
                t if (0x02..=0x7F).contains(&t) => {
                    // Reserved unskippable chunk — spec says return error.
                    return Err(format!("snappy: reserved unskippable chunk type 0x{t:02x}"));
                }
                _ => {
                    // Padding (0xFE) and reserved skippable (0x80-0xFD).
                    // No CRC for these types.
                }
            }
            self.offset += total;
        }

        if self.offset == self.buf.len() {
            self.buf.clear();
            self.offset = 0;
        }

        Ok(())
    }

    #[cfg(test)]
    fn buffered_capacity(&self) -> usize {
        self.buf.capacity()
    }

    #[cfg(test)]
    fn buffered_segments(&self) -> usize {
        usize::from(!self.buf.is_empty())
    }

    pub(crate) fn has_pending(&self) -> bool {
        self.offset < self.buf.len()
    }

    pub(crate) fn has_complete_frame(&self) -> bool {
        if self.offset + 4 > self.buf.len() {
            return false;
        }
        let chunk_len = u32::from_le_bytes([
            self.buf[self.offset + 1],
            self.buf[self.offset + 2],
            self.buf[self.offset + 3],
            0,
        ]) as usize;
        self.offset + 4 + chunk_len <= self.buf.len()
    }

    /// Validate that EOF did not leave a partial frame. Complete frames must be
    /// drained through [`feed_into_progress`] before calling this method.
    pub fn validate_partial_eof(&mut self) -> Result<(), String> {
        if self.has_complete_frame() {
            return Err("snappy: complete frame remains at EOF; drain progress first".into());
        }
        if self.has_pending() {
            self.buf.clear();
            self.offset = 0;
            Err("snappy: incomplete frame at end of stream".into())
        } else {
            Ok(())
        }
    }

    /// Flush any remaining buffered data, returning decompressed output.
    /// Call this when the compressed stream has ended (work_r EOF).
    pub fn flush(&mut self) -> Result<Vec<u8>, String> {
        let offset_before = self.offset;
        let output = self.feed(&[])?;
        if !output.is_empty() {
            return Ok(output);
        }
        if !self.has_pending() {
            Ok(Vec::new())
        } else if self.offset > offset_before {
            // Bounded metadata work was consumed; the caller should drain again.
            Ok(Vec::new())
        } else {
            self.buf.clear();
            self.offset = 0;
            Err("snappy: incomplete frame at end of stream".into())
        }
    }
}

// Stub SnappyDecompressor when compression feature is disabled.
#[cfg(not(feature = "compression"))]
pub struct SnappyDecompressor;

#[cfg(not(feature = "compression"))]
impl Default for SnappyDecompressor {
    fn default() -> Self {
        Self
    }
}

#[cfg(not(feature = "compression"))]
impl SnappyDecompressor {
    pub fn new() -> Self {
        Self
    }
    pub fn feed(&mut self, _data: &[u8]) -> Result<Vec<u8>, String> {
        Err("compression not compiled".into())
    }
    pub fn feed_into(&mut self, _data: &[u8], _out: &mut Vec<u8>) -> Result<(), String> {
        Err("compression not compiled".into())
    }
    pub fn feed_into_progress(
        &mut self,
        _data: &[u8],
        _out: &mut Vec<u8>,
    ) -> Result<SnappyFeedStatus, String> {
        Err("compression not compiled".into())
    }
    pub fn feed_into_append_progress(
        &mut self,
        _data: &[u8],
        _out: &mut Vec<u8>,
    ) -> Result<SnappyFeedStatus, String> {
        Err("compression not compiled".into())
    }
    #[allow(dead_code)] // stub: only called when the compression feature is on
    pub(crate) fn has_pending(&self) -> bool {
        false
    }
    pub(crate) fn has_complete_frame(&self) -> bool {
        false
    }
    pub fn validate_partial_eof(&mut self) -> Result<(), String> {
        Ok(())
    }
    pub fn flush(&mut self) -> Result<Vec<u8>, String> {
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let key = derive_key("my-secret-token");
        let data = b"Hello, frp-rs!";
        let encrypted = encrypt(data, &key).unwrap();
        assert_ne!(encrypted, data);
        assert_eq!(encrypted.len(), 16 + data.len());
        let decrypted = decrypt(&encrypted, &key).unwrap();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_encrypt_empty() {
        let key = derive_key("token");
        let encrypted = encrypt(b"", &key).unwrap();
        assert_eq!(encrypted.len(), 16);
        let decrypted = decrypt(&encrypted, &key).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    #[cfg(feature = "compression")]
    fn test_compression() {
        let data = b"Hello, frp-rs! Hello, frp-rs! Hello, frp-rs!";
        let compressed = compress(data).unwrap();
        let decompressed = decompress(&compressed).unwrap();
        assert_eq!(decompressed, data);
        assert!(compressed.len() < data.len());
    }

    #[test]
    #[cfg(feature = "compression")]
    fn snappy_compressor_reuses_encoder_and_roundtrips_across_chunks() {
        let mut comp = SnappyCompressor::new();
        let mut out = Vec::new();
        let mut stream = Vec::new();

        comp.compress(b"first-chunk-data", &mut out).unwrap();
        assert!(
            out.starts_with(&[0xff, 0x06, 0x00, 0x00, b's', b'N', b'a', b'P', b'p', b'Y']),
            "first chunk must carry the stream identifier"
        );
        stream.extend_from_slice(&out);

        comp.compress(b"second-chunk-data", &mut out).unwrap();
        assert!(
            !out.starts_with(&[0xff, 0x06, 0x00, 0x00, b's', b'N', b'a', b'P', b'p', b'Y']),
            "later chunks must not repeat the stream identifier"
        );
        stream.extend_from_slice(&out);

        comp.compress(b"third-chunk-data", &mut out).unwrap();
        stream.extend_from_slice(&out);

        // The concatenated stream must decompress across chunk boundaries.
        let mut dec = SnappyDecompressor::new();
        let mut reconstructed = Vec::new();
        for fragment in stream.chunks(7) {
            reconstructed.extend_from_slice(&dec.feed(fragment).unwrap());
        }
        loop {
            let chunk = dec.feed(&[]).unwrap();
            if chunk.is_empty() {
                break;
            }
            reconstructed.extend_from_slice(&chunk);
        }
        assert_eq!(
            reconstructed,
            b"first-chunk-datasecond-chunk-datathird-chunk-data"
        );
    }

    #[test]
    #[cfg(feature = "compression")]
    fn mixed_legacy_and_reused_encoder_stream_decompresses() {
        // Legacy per-chunk compress_into repeats the stream identifier on
        // every chunk; the reused SnappyCompressor emits it only once. Both
        // output styles must be decodable as one continuous stream. Note
        // compress_into/compress replace their output buffer, so each chunk
        // is compressed into its own buffer and accumulated into the stream.
        let mut legacy = Vec::new();
        for data in [&b"legacy-chunk"[..], &b"legacy-chunk-2"[..]] {
            let mut chunk_buf = Vec::new();
            compress_into(data, &mut chunk_buf).unwrap();
            legacy.extend_from_slice(&chunk_buf);
        }

        let mut comp = SnappyCompressor::new();
        let mut reused = Vec::new();
        for data in [&b"reused-chunk"[..], &b"reused-chunk-2"[..]] {
            let mut chunk_buf = Vec::new();
            comp.compress(data, &mut chunk_buf).unwrap();
            reused.extend_from_slice(&chunk_buf);
        }

        let mut stream = legacy;
        stream.extend_from_slice(&reused);

        let mut dec = SnappyDecompressor::new();
        let mut reconstructed = Vec::new();
        for fragment in stream.chunks(11) {
            reconstructed.extend_from_slice(&dec.feed(fragment).unwrap());
        }
        loop {
            let chunk = dec.feed(&[]).unwrap();
            if chunk.is_empty() {
                break;
            }
            reconstructed.extend_from_slice(&chunk);
        }
        assert_eq!(
            reconstructed,
            b"legacy-chunklegacy-chunk-2reused-chunkreused-chunk-2"
        );
    }

    #[test]
    #[cfg(feature = "compression")]
    fn feed_into_append_progress_batches_frames_into_one_buffer() {
        let mut dec = SnappyDecompressor::new();
        let mut out = Vec::new();

        let c1 = compress(b"frame-one").unwrap();
        let c2 = compress(b"frame-two").unwrap();
        let c3 = compress(b"frame-three").unwrap();

        // Each chunk is an independent framed stream; the append variant must
        // accumulate all decoded frames in a single buffer without clearing.
        dec.feed_into_append_progress(&c1, &mut out).unwrap();
        dec.feed_into_append_progress(&c2, &mut out).unwrap();
        dec.feed_into_append_progress(&c3, &mut out).unwrap();

        assert_eq!(out, b"frame-oneframe-twoframe-three");
    }

    #[test]
    #[cfg(feature = "compression")]
    fn test_snappy_decompressor_streaming() {
        // Simulate data arriving in chunks: split mid-stream-identifier
        // to exercise the partial-frame and multi-chunk paths.
        let plaintext = b"test-data-for-streaming-decompression";
        let compressed = compress(plaintext).unwrap();

        // Snappy frame: stream identifier (10 bytes) + compressed data chunk.
        // Split mid-stream-identifier to test partial delivery.
        let split_at = 6;
        let part1 = &compressed[..split_at];
        let part2 = &compressed[split_at..];

        let mut dec = SnappyDecompressor::new();
        let out1 = dec.feed(part1).unwrap();
        assert!(
            out1.is_empty(),
            "partial stream ID should produce no output"
        );

        let out2 = dec.feed(part2).unwrap();
        assert_eq!(out2, plaintext, "second feed should produce full output");

        // Third feed — new compressed chunk.
        let out3 = dec.feed(&compress(b"second-chunk").unwrap()).unwrap();
        assert_eq!(out3, b"second-chunk");
    }

    #[test]
    #[cfg(feature = "compression")]
    fn test_snappy_decompressor_all_at_once() {
        let plaintext = b"all-at-once-compression-test-data";
        let compressed = compress(plaintext).unwrap();

        let mut dec = SnappyDecompressor::new();
        let output = dec.feed(&compressed).unwrap();
        assert_eq!(output, plaintext);
    }

    #[test]
    #[cfg(feature = "compression")]
    fn test_snappy_decompressor_empty() {
        let mut dec = SnappyDecompressor::new();
        assert!(dec.feed(b"").unwrap().is_empty());
    }

    #[test]
    #[cfg(feature = "compression")]
    fn snappy_rejects_oversized_declared_chunk_before_payload_allocation() {
        let mut dec = SnappyDecompressor::new();
        let declared = 256 * 1024_u32;
        let header = [
            0x00,
            declared as u8,
            (declared >> 8) as u8,
            (declared >> 16) as u8,
        ];

        let error = dec.feed(&header).unwrap_err();
        assert!(error.contains("chunk length"), "unexpected error: {error}");
        assert!(dec.buffered_capacity() <= 256 * 1024);
    }

    #[test]
    #[cfg(feature = "compression")]
    fn snappy_rejects_expansion_bomb_before_output_allocation() {
        // A complete, small framed chunk whose raw Snappy header declares
        // 128 KiB + 1 of output. The limit must fire before decompression or
        // any output reservation; the payload itself may remain invalid.
        let frame = [0x00, 0x07, 0x00, 0x00, 0, 0, 0, 0, 0x81, 0x80, 0x08];
        let mut dec = SnappyDecompressor::new();
        let mut output = Vec::new();

        let error = dec.feed_into(&frame, &mut output).unwrap_err();
        assert!(
            error.contains("decompressed output"),
            "unexpected error: {error}"
        );
        assert_eq!(output.capacity(), 0);
    }

    #[test]
    #[cfg(feature = "compression")]
    fn snappy_fragmented_valid_frame_stays_bounded_and_roundtrips() {
        let plaintext = vec![0x5a; 64 * 1024];
        let compressed = compress(&plaintext).unwrap();
        let mut dec = SnappyDecompressor::new();
        let mut output = Vec::new();

        for fragment in compressed.chunks(7) {
            output.extend_from_slice(&dec.feed(fragment).unwrap());
            assert!(dec.buffered_capacity() <= 256 * 1024);
        }
        loop {
            let chunk = dec.feed(&[]).unwrap();
            if chunk.is_empty() {
                break;
            }
            output.extend_from_slice(&chunk);
        }

        assert_eq!(output, plaintext);
    }

    #[test]
    #[cfg(feature = "compression")]
    fn snappy_accepts_one_megabyte_multi_chunk_feed() {
        let plaintext = vec![0x42; 1024 * 1024];
        let compressed = compress(&plaintext).unwrap();
        let mut dec = SnappyDecompressor::new();

        let mut output = dec.feed(&compressed).unwrap();
        loop {
            let chunk = dec.feed(&[]).unwrap();
            if chunk.is_empty() {
                break;
            }
            output.extend_from_slice(&chunk);
        }
        assert_eq!(output, plaintext);
    }

    #[test]
    #[cfg(feature = "compression")]
    fn snappy_drains_highly_compressed_three_megabytes_one_bounded_chunk_at_a_time() {
        let plaintext = vec![0x42; 3 * 1024 * 1024];
        let compressed = compress(&plaintext).unwrap();
        let mut dec = SnappyDecompressor::new();
        let mut reconstructed = Vec::new();

        let mut chunk = dec.feed(&compressed).unwrap();
        loop {
            assert!(chunk.len() <= 128 * 1024);
            if chunk.is_empty() {
                break;
            }
            reconstructed.extend_from_slice(&chunk);
            chunk = dec.feed(&[]).unwrap();
        }

        assert_eq!(reconstructed, plaintext);
        assert!(dec.buffered_capacity() <= 2 * 1024 * 1024);
    }

    #[test]
    #[cfg(feature = "compression")]
    fn snappy_accepts_three_megabytes_of_incompressible_framed_input() {
        let plaintext: Vec<u8> = (0usize..3 * 1024 * 1024)
            .map(|i| (i.wrapping_mul(131) >> 7) as u8)
            .collect();
        let compressed = compress(&plaintext).unwrap();
        let mut dec = SnappyDecompressor::new();
        let mut reconstructed = Vec::new();
        let mut chunk = dec.feed(&compressed).unwrap();
        while !chunk.is_empty() {
            reconstructed.extend_from_slice(&chunk);
            chunk = dec.feed(&[]).unwrap();
        }
        assert_eq!(reconstructed, plaintext);
    }

    #[test]
    #[cfg(feature = "compression")]
    fn snappy_skippable_frame_storm_uses_one_contiguous_pending_buffer() {
        let mut storm = Vec::with_capacity(400_000);
        for _ in 0..100_000 {
            storm.extend_from_slice(&[0xfe, 0, 0, 0]);
        }
        let mut dec = SnappyDecompressor::new();
        let mut output = Vec::new();

        let status = dec.feed_into_progress(&storm, &mut output).unwrap();
        assert!(output.is_empty());
        assert!(status.has_more_complete);
        assert_eq!(dec.buffered_segments(), 1);
        assert!(dec.buffered_capacity() <= 16 * 1024 * 1024);
    }

    #[test]
    #[cfg(feature = "compression")]
    fn public_progress_api_unambiguously_drains_metadata_storm_then_data() {
        let mut input = Vec::with_capacity(400_128);
        for _ in 0..100_000 {
            input.extend_from_slice(&[0xfe, 0, 0, 0]);
        }
        input.extend_from_slice(&compress(b"after-storm").unwrap());
        let mut dec = SnappyDecompressor::new();
        let mut output = Vec::new();
        let mut calls = 0usize;
        let mut status = dec.feed_into_progress(&input, &mut output).unwrap();

        loop {
            calls += 1;
            if !output.is_empty() {
                assert_eq!(output, b"after-storm");
            }
            if !status.has_more_complete {
                break;
            }
            status = dec.feed_into_progress(&[], &mut output).unwrap();
        }

        assert!(calls > 1, "work budget must split the metadata storm");
        assert!(calls < 200, "each call must make bounded forward progress");
        assert!(!status.has_pending_partial);
    }

    #[test]
    #[cfg(feature = "compression")]
    fn legacy_feed_rejects_excessive_metadata_work_with_progress_guidance() {
        let mut storm = Vec::with_capacity(16 * 1024 * 1024);
        for _ in 0..(16 * 1024 * 1024 / 4) {
            storm.extend_from_slice(&[0xfe, 0, 0, 0]);
        }
        let mut dec = SnappyDecompressor::new();

        let error = dec.feed(&storm).unwrap_err();
        assert!(error.contains("feed_into_progress"), "unexpected: {error}");
    }

    #[test]
    #[cfg(feature = "compression")]
    fn snappy_rejects_oversized_header_before_copying_same_feed_payload() {
        let declared = 256 * 1024_u32;
        let mut input = vec![0u8; 300 * 1024];
        input[..4].copy_from_slice(&[
            0x00,
            declared as u8,
            (declared >> 8) as u8,
            (declared >> 16) as u8,
        ]);
        let mut dec = SnappyDecompressor::new();

        let error = dec.feed(&input).unwrap_err();
        assert!(error.contains("chunk length"), "unexpected error: {error}");
        assert!(dec.buffered_capacity() < input.len());
    }

    #[test]
    fn test_key_derivation_deterministic() {
        let k1 = derive_key("secret");
        let k2 = derive_key("secret");
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_key_derivation_different() {
        let k1 = derive_key("secret1");
        let k2 = derive_key("secret2");
        assert_ne!(k1, k2);
    }

    #[test]
    fn test_encrypt_decrypt_into_roundtrip_and_wire_equiv() {
        let key: [u8; 16] = *b"0123456789abcdef";
        let data = b"udp payload payload payload";
        let mut key_buf = [0u8; 16];
        key_buf.copy_from_slice(&key);

        // encrypt → decrypt roundtrip through the _into variants (the random
        // IV differs per call, so compare decrypted plaintext, not ciphertext).
        let mut enc = Vec::new();
        encrypt_into(data, &key_buf, &mut enc).unwrap();
        assert_eq!(enc.len(), data.len() + 16);
        let mut dec = Vec::new();
        decrypt_into(&enc, &key_buf, &mut dec).unwrap();
        assert_eq!(dec, data);

        // _into must reuse the buffer (capacity retained), not reallocate.
        let cap_before = enc.capacity();
        encrypt_into(data, &key_buf, &mut enc).unwrap();
        assert!(enc.capacity() >= cap_before, "capacity must be retained");

        // decrypt_into output identical to decrypt.
        let dec_plain = decrypt(&enc, &key_buf).unwrap();
        let mut dec_into = Vec::new();
        decrypt_into(&enc, &key_buf, &mut dec_into).unwrap();
        assert_eq!(dec_plain, dec_into);
    }

    #[test]
    fn test_compress_decompress_into_wire_equiv() {
        let data = b"compressible compressible compressible compressible data";
        // compress is deterministic → _into output must be byte-identical.
        let plain = compress(data).unwrap();
        let mut into = Vec::new();
        compress_into(data, &mut into).unwrap();
        assert_eq!(
            plain, into,
            "compress_into must match compress byte-for-byte"
        );

        // decompress_into output identical to decompress, and roundtrips.
        let mut out = Vec::new();
        decompress_into(&plain, &mut out).unwrap();
        assert_eq!(out, data);
        let out_plain = decompress(&plain).unwrap();
        assert_eq!(out_plain, out);
    }
}
