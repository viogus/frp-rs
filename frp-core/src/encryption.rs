use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng};

/// Derive an AES-256 key from a token using SHA-256.
pub fn derive_key(token: &str) -> [u8; 32] {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

/// Encrypt data using AES-256-GCM.
/// Returns: 12-byte nonce || ciphertext || 16-byte tag
pub fn encrypt(data: &[u8], key_bytes: &[u8; 32]) -> Result<Vec<u8>, String> {
    let key = Key::<Aes256Gcm>::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, data)
        .map_err(|e| format!("encryption failed: {e}"))?;
    let mut result = nonce.to_vec();
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Decrypt data using AES-256-GCM.
/// Input: 12-byte nonce || ciphertext || 16-byte tag
pub fn decrypt(data: &[u8], key_bytes: &[u8; 32]) -> Result<Vec<u8>, String> {
    if data.len() < 28 {
        return Err("data too short for AES-GCM (need at least 12-byte nonce + 16-byte tag)".into());
    }
    let key = Key::<Aes256Gcm>::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&data[..12]);
    let ciphertext = &data[12..];
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| format!("decryption failed: {e}"))
}

use flate2::read::{ZlibDecoder, ZlibEncoder};
use flate2::Compression;
use std::io::Read;

/// Compress data using zlib.
pub fn compress(data: &[u8]) -> Result<Vec<u8>, String> {
    let mut encoder = ZlibEncoder::new(data, Compression::default());
    let mut result = Vec::new();
    encoder.read_to_end(&mut result)
        .map_err(|e| format!("compression failed: {e}"))?;
    Ok(result)
}

/// Decompress zlib-compressed data.
pub fn decompress(data: &[u8]) -> Result<Vec<u8>, String> {
    let mut decoder = ZlibDecoder::new(data);
    let mut result = Vec::new();
    decoder.read_to_end(&mut result)
        .map_err(|e| format!("decompression failed: {e}"))?;
    Ok(result)
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
        let decrypted = decrypt(&encrypted, &key).unwrap();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_compression() {
        let data = b"Hello, frp-rs!";    
        let compressed = compress(data).unwrap();
        let decompressed = decompress(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }
}
