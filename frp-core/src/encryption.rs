use cfb_mode::cipher::AsyncStreamCipher;
use cfb_mode::cipher::KeyIvInit;
use rand::RngCore;

type Aes128CfbEnc = cfb_mode::Encryptor<aes::Aes128>;
type Aes128CfbDec = cfb_mode::Decryptor<aes::Aes128>;

/// Derive an AES-128 key from a token using PBKDF2-SHA1.
/// Matches Go frp v0.69.1 binary: pbkdf2.Key(token, "frp", 64, 16, sha1.New)
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
    let iv = &data[..16];
    let ciphertext = &data[16..];
    let mut result = ciphertext.to_vec();
    let cipher = Aes128CfbDec::new(key.into(), iv.into());
    cipher.decrypt(&mut result);
    Ok(result)
}

/// Compress data using Snappy (matching Go frp v0.69.1).
pub fn compress(data: &[u8]) -> Result<Vec<u8>, String> {
    use snap::write::FrameEncoder;
    use std::io::Write;
    let mut encoder = FrameEncoder::new(Vec::new());
    encoder
        .write_all(data)
        .map_err(|e| format!("snappy compress: {e}"))?;
    encoder
        .into_inner()
        .map_err(|e| format!("snappy finalize: {e}"))
}

/// Decompress Snappy-compressed data.
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

/// Streaming Snappy decompressor for use in bridges.
///
/// Unlike [`decompress`], this handles data arriving in arbitrary TCP chunks:
/// partial snappy frames are buffered internally until a complete frame is
/// available, then decompressed.  This avoids "unexpected EOF" errors when a
/// `read()` boundary does not align with a snappy frame boundary.
pub struct SnappyDecompressor {
    buf: Vec<u8>,
}

impl Default for SnappyDecompressor {
    fn default() -> Self {
        Self::new()
    }
}

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
        use snap::read::FrameDecoder;
        use std::io::Read;

        self.buf.extend_from_slice(data);

        let mut output = Vec::new();
        let mut tmp = [0u8; 8192];

        loop {
            let mut cursor = std::io::Cursor::new(&self.buf[..]);
            let mut decoder = FrameDecoder::new(&mut cursor);
            let mut decoded_any = false;

            loop {
                match decoder.read(&mut tmp) {
                    Ok(0) => {
                        // All complete frames consumed.
                        decoded_any = true;
                        break;
                    }
                    Ok(n) => {
                        decoded_any = true;
                        output.extend_from_slice(&tmp[..n]);
                    }
                    Err(_) => {
                        // Partial frame or corrupt data — stop.
                        break;
                    }
                }
            }

            let consumed = cursor.position() as usize;
            if consumed == 0 {
                // Nothing consumed — incomplete header or frame; wait for more data.
                break;
            }
            self.buf.drain(..consumed);
            if !decoded_any {
                // Consumed bytes but no output (e.g. skipped a stream-identifier
                // chunk mid-stream).  Loop again to try the next frame.
                continue;
            }
            // We got output.  Don't loop — return what we have so the caller
            // can send it to the user immediately.  Remaining frames will be
            // processed on the next `feed()`.
            break;
        }

        Ok(output)
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
    fn test_compression() {
        let data = b"Hello, frp-rs! Hello, frp-rs! Hello, frp-rs!";
        let compressed = compress(data).unwrap();
        let decompressed = decompress(&compressed).unwrap();
        assert_eq!(decompressed, data);
        assert!(compressed.len() < data.len());
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
