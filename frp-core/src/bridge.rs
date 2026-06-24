use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::encryption;

/// Bridge data between user and work connections with optional encryption/compression.
/// Uses length-prefixed framing for encrypted data.
///
/// Protocol frame:
///   [4-byte big-endian length][encrypted payload]
/// The encrypted payload contains: [nonce(12)][ciphertext][tag(16)]
pub async fn bridge_encrypted(
    mut user_r: impl AsyncReadExt + Unpin,
    mut user_w: impl AsyncWriteExt + Unpin,
    mut work_r: impl AsyncReadExt + Unpin,
    mut work_w: impl AsyncWriteExt + Unpin,
    key: &[u8; 32],
) {
    // User → Server: read from user, compress+encrypt, write to work
    let user_to_work = async {
        let mut buf = vec![0u8; 65536];
        loop {
            let n = match user_r.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            };
            let payload = &buf[..n];
            match encryption::encrypt(payload, key) {
                Ok(encrypted) => {
                    let len = u32::try_from(encrypted.len()).unwrap_or(u32::MAX).to_be_bytes();
                    if work_w.write_all(&len).await.is_err() { break; }
                    if work_w.write_all(&encrypted).await.is_err() { break; }
                    if work_w.flush().await.is_err() { break; }
                }
                Err(_) => break,
            }
        }
    };

    // Server → User: read from work, decrypt, write to user
    let work_to_user = async {
        let mut len_buf = [0u8; 4];
        loop {
            let len = match read_frame_length(&mut work_r, &mut len_buf).await {
                Some(l) => l,
                None => break,
            };
            let mut enc_buf = vec![0u8; len];
            if work_r.read_exact(&mut enc_buf).await.is_err() { break; }
            match encryption::decrypt(&enc_buf, key) {
                Ok(plaintext) => {
                    if user_w.write_all(&plaintext).await.is_err() { break; }
                    if user_w.flush().await.is_err() { break; }
                }
                Err(_) => break,
            }
        }
    };

    tokio::select! {
        _ = user_to_work => {},
        _ = work_to_user => {},
    }
}

/// Read a 4-byte big-endian length prefix from the reader.
async fn read_frame_length(
    reader: &mut (impl AsyncReadExt + Unpin),
    buf: &mut [u8; 4],
) -> Option<usize> {
    reader.read_exact(buf).await.ok()?;
    let len = u32::from_be_bytes(*buf) as usize;
    if len == 0 || len > 1024 * 1024 {
        return None; // reject zero-length frames and frames > 1MB
    }
    Some(len)
}
