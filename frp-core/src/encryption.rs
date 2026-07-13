use cfb_mode::cipher::KeyIvInit;
use rand::RngCore;

type Aes128CfbEnc = cfb_mode::Encryptor<aes::Aes128>;
type Aes128CfbDec = cfb_mode::Decryptor<aes::Aes128>;

/// Derive an AES-128 key from a token using PBKDF2-SHA1.
/// Matches Go frp v0.69.1 binary: pbkdf2.Key(token, "frp", 64, 16, sha1.New)
///
/// V1 only. Uses PBKDF2-SHA1 with 64 iterations and salt "frp" — deliberately
/// weak, for Go frp binary compatibility. For stronger key derivation, use the
/// V2 AEAD path (HKDF-SHA256 with transcript hashing). Do not increase
/// iterations: it breaks Go frp interop.
pub fn derive_key(token: &str) -> [u8; 16] {
    let mut key = [0u8; 16];
    pbkdf2::pbkdf2_hmac::<sha1::Sha1>(token.as_bytes(), b"frp", 64, &mut key);
    key
}

/// Encrypt data using AES-128-CFB with a random 16-byte IV.
/// Returns: [16-byte IV][ciphertext]
pub fn encrypt(data: &[u8], key: &[u8; 16]) -> Result<Vec<u8>, String> {
    let mut iv = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut iv);
    let mut result = iv.to_vec();
    result.extend_from_slice(data);
    let cipher = Aes128CfbEnc::new(key.into(), &iv.into());
    cipher.encrypt(&mut result[16..]);
    Ok(result)
}

/// Decrypt data using AES-128-CFB.
/// Input: [16-byte IV][ciphertext]
pub fn decrypt(data: &[u8], key: &[u8; 16]) -> Result<Vec<u8>, String> {
    if data.len() < 16 {
        return Err("data too short for AES-CFB (need at least 16-byte IV)".into());
    }
    let iv: &[u8; 16] = data[..16]
        .try_into()
        .expect("IV is exactly 16 bytes: length checked above");
    let ciphertext = &data[16..];
    let mut result = ciphertext.to_vec();
    let cipher = Aes128CfbDec::new(key.into(), iv.into());
    cipher.decrypt(&mut result);
    Ok(result)
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

#[cfg(not(feature = "compression"))]
pub fn compress(_data: &[u8]) -> Result<Vec<u8>, String> {
    Err("compression not compiled".into())
}

#[cfg(not(feature = "compression"))]
pub fn compress_into(_data: &[u8], _buf: &mut Vec<u8>) -> Result<(), String> {
    Err("compression not compiled".into())
}

/// Decompress Snappy-compressed data.
#[cfg(feature = "compression")]
pub fn decompress(data: &[u8]) -> Result<Vec<u8>, String> {
    use snap::read::FrameDecoder;
    use std::io::Read;
    let mut decoder = FrameDecoder::new(data);
    let mut result = Vec::new();
    decoder
        .read_to_end(&mut result)
        .map_err(|e| format!("snappy decompress: {e}"))?;
    Ok(result)
}

#[cfg(not(feature = "compression"))]
pub fn decompress(_data: &[u8]) -> Result<Vec<u8>, String> {
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
        Self { buf: Vec::new() }
    }

    /// Feed compressed bytes into the decompressor.
    ///
    /// Returns all decompressed plaintext that can be produced from complete
    /// frames currently in the buffer.  Bytes that belong to an incomplete
    /// frame are retained and will be processed on the next `feed()` call.
    ///
    /// Returns an error only for truly corrupt input (bad magic, bad CRC);
    /// partial frames are silently buffered, not treated as errors.
    pub fn feed(&mut self, data: &[u8]) -> Result<Vec<u8>, String> {
        let mut out = Vec::new();
        self.feed_into(data, &mut out)?;
        Ok(out)
    }

    /// Like [`feed`], but writes decompressed output into an existing buffer,
    /// reusing its allocation.
    pub fn feed_into(&mut self, data: &[u8], out: &mut Vec<u8>) -> Result<(), String> {
        const MAX_SNAPPY_BUFFER: usize = 16 * 1024 * 1024; // 16 MB
        if self.buf.len() + data.len() > MAX_SNAPPY_BUFFER {
            return Err("snappy decompression buffer exhausted".into());
        }
        self.buf.extend_from_slice(data);

        out.clear();
        let mut pos = 0;
        let stream_body = b"sNaPpY";

        while pos + 4 <= self.buf.len() {
            let chunk_type = self.buf[pos];
            let chunk_len = u32::from_le_bytes([
                self.buf[pos + 1],
                self.buf[pos + 2],
                self.buf[pos + 3],
                0,
            ]) as usize;

            match chunk_type {
                0x00 => {
                    // Compressed data: length field includes 4-byte CRC.
                    if chunk_len < 4 {
                        return Err("snappy: compressed chunk length too small".into());
                    }
                    let total = 4 + chunk_len;
                    if pos + total > self.buf.len() {
                        break; // incomplete chunk
                    }
                    // Skip 4-byte header (already read) + 4-byte CRC
                    let data_start = pos + 8;
                    let compressed = &self.buf[data_start..pos + total];
                    let mut decoder = snap::raw::Decoder::new();
                    let decompressed = decoder
                        .decompress_vec(compressed)
                        .map_err(|e| format!("snappy decompress: {e}"))?;
                    out.extend_from_slice(&decompressed);
                    pos += total;
                }
                0x01 => {
                    // Uncompressed data: length field includes 4-byte CRC.
                    if chunk_len < 4 {
                        return Err("snappy: uncompressed chunk length too small".into());
                    }
                    let total = 4 + chunk_len;
                    if pos + total > self.buf.len() {
                        break; // incomplete chunk
                    }
                    let data_start = pos + 8; // skip header + CRC
                    let data = &self.buf[data_start..pos + total];
                    out.extend_from_slice(data);
                    pos += total;
                }
                0xFF => {
                    // Stream identifier: 4-byte header + body, NO CRC.
                    let total = 4 + chunk_len;
                    if pos + total > self.buf.len() {
                        break; // incomplete
                    }
                    let body = &self.buf[pos + 4..pos + total];
                    if body != stream_body {
                        return Err(format!(
                            "snappy: bad stream identifier: {:?}",
                            body
                        ));
                    }
                    pos += total;
                }
                t if (0x02..=0x7F).contains(&t) => {
                    // Reserved unskippable chunk — spec says return error.
                    return Err(format!(
                        "snappy: reserved unskippable chunk type 0x{t:02x}"
                    ));
                }
                _ => {
                    // Padding (0xFE) and reserved skippable (0x80-0xFD).
                    // No CRC for these types.
                    let total = 4 + chunk_len;
                    if pos + total > self.buf.len() {
                        break; // incomplete chunk
                    }
                    pos += total;
                }
            }
        }

        self.buf.drain(..pos);
        Ok(())
    }

    /// Flush any remaining buffered data, returning decompressed output.
    /// Call this when the compressed stream has ended (work_r EOF).
    pub fn flush(&mut self) -> Result<Vec<u8>, String> {
        if self.buf.is_empty() {
            return Ok(Vec::new());
        }
        let remaining = std::mem::take(&mut self.buf);
        decompress(&remaining)
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
        assert!(out1.is_empty(), "partial stream ID should produce no output");

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
}
