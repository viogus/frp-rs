use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::encryption;

/// Bridge data between user and work connections with encryption and compression.
/// Matches Go frp v0.69.1: compress (Snappy) → encrypt (AES-128-CFB) → frame (4-byte BE length).
///
/// Protocol frame:
///   [4-byte big-endian length][encrypted payload]
/// Encrypted payload: [16-byte IV][CFB-encrypted(compressed plaintext)]
pub async fn bridge_encrypted(
    mut user_r: impl AsyncReadExt + Unpin,
    mut user_w: impl AsyncWriteExt + Unpin,
    mut work_r: impl AsyncReadExt + Unpin,
    mut work_w: impl AsyncWriteExt + Unpin,
    key: &[u8; 16],
    use_compression: bool,
) {
    // User → Work: read from user, compress, encrypt, write to work
    let user_to_work = async {
        let mut buf = vec![0u8; 65536];
        loop {
            let n = match user_r.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            };
            let payload = &buf[..n];

            let processed = if use_compression {
                match encryption::compress(payload) {
                    Ok(c) => c,
                    Err(_) => break,
                }
            } else {
                payload.to_vec()
            };

            match encryption::encrypt(&processed, key) {
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

    // Work → User: read from work, decrypt, decompress, write to user
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
                Ok(processed) => {
                    let plaintext = if use_compression {
                        match encryption::decompress(&processed) {
                            Ok(p) => p,
                            Err(_) => break,
                        }
                    } else {
                        processed
                    };
                    if user_w.write_all(&plaintext).await.is_err() { break; }
                    if user_w.flush().await.is_err() { break; }
                }
                Err(_) => break,
            }
        }
    };

    // Use join! (not select!): both directions must complete, matching Go frp's WaitGroup
    let _ = tokio::join!(user_to_work, work_to_user);
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
