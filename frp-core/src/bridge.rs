use std::sync::Arc;
use std::sync::atomic::Ordering;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::bandwidth::BandwidthLimiter;
use crate::cipher_stream::{CipherReader, CipherWriter};
use crate::encryption;
use crate::transport::IoStream;

/// Bridge encrypted data between two IoStreams, splitting them internally.
pub async fn bridge_encrypted_io(
    user: IoStream,
    work: IoStream,
    key: &[u8; 16],
    use_compression: bool,
    pre_read: Vec<u8>,
    read_limiter: Option<&mut BandwidthLimiter>,
    write_limiter: Option<&mut BandwidthLimiter>,
    metrics: Option<Arc<crate::metrics::ProxyMetrics>>,
) {
    let (u_r, u_w) = user.into_split();
    let (w_r, w_w) = work.into_split();
    bridge_encrypted(u_r, u_w, w_r, w_w, key, use_compression, pre_read, read_limiter, write_limiter, metrics).await;
}

/// Bridge data between user and work connections over an encrypted+compressed channel.
/// Matches Go frp v0.69.1: compress (Snappy) → encrypt (AES-128-CFB streaming).
///
/// Encryption uses streaming CFB: work_r / work_w are wrapped in
/// `CipherReader` / `CipherWriter` internally. A single random IV is sent
/// per direction on the first write/read, then all subsequent data is
/// encrypted/decrypted with continuous cipher state.
///
/// `pre_read` bytes (e.g., VHost HTTP body) are written through the encrypting
/// writer before the main bridge loop, ensuring they share the same IV and
/// CFB state.
///
/// `read_limiter` limits work→user (download). `write_limiter` limits user→work (upload).
pub async fn bridge_encrypted(
    mut user_r: impl AsyncReadExt + Unpin,
    mut user_w: impl AsyncWriteExt + Unpin,
    work_r: impl AsyncReadExt + Unpin,
    work_w: impl AsyncWriteExt + Unpin,
    key: &[u8; 16],
    use_compression: bool,
    pre_read: Vec<u8>,
    mut read_limiter: Option<&mut BandwidthLimiter>,
    mut write_limiter: Option<&mut BandwidthLimiter>,
    metrics: Option<Arc<crate::metrics::ProxyMetrics>>,
) {
    let mut enc_work_r = CipherReader::new(work_r, *key);
    let mut enc_work_w = CipherWriter::new(work_w, *key);

    // User → Work: write pre_read first (through CipherWriter), then bridge
    let user_to_work = async {
        if !pre_read.is_empty()
            && enc_work_w.write_all(&pre_read).await.is_err()
        {
            return;
        }
        let mut buf = vec![0u8; 65536];
        loop {
            let n = match user_r.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if let Some(ref m) = metrics {
                        m.bytes_in.fetch_add(n as u64, Ordering::Relaxed);
                    }
                    n
                }
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

            // Apply write bandwidth limit before send
            if let Some(ref mut lim) = write_limiter {
                lim.consume(processed.len()).await;
            }

            if enc_work_w.write_all(&processed).await.is_err() { break; }
            if enc_work_w.flush().await.is_err() { break; }
        }
    };

    // Work → User: read from work (decrypted), decompress, write to user
    let work_to_user = async {
        let mut buf = vec![0u8; 65536];
        let mut decompressor = if use_compression {
            Some(encryption::SnappyDecompressor::new())
        } else {
            None
        };
        loop {
            let n = match enc_work_r.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            };
            let decrypted = &buf[..n];

            let plaintext = if let Some(ref mut dec) = decompressor {
                match dec.feed(decrypted) {
                    Ok(p) => p,
                    Err(e) => {
                        tracing::warn!("snappy decompress error in encrypted bridge: {}", e);
                        break;
                    }
                }
            } else {
                decrypted.to_vec()
            };

            if !plaintext.is_empty() {
                // Apply read bandwidth limit before writing to user
                if let Some(ref mut lim) = read_limiter {
                    lim.consume(plaintext.len()).await;
                }

                if user_w.write_all(&plaintext).await.is_err() { break; }
                // Count bytes written to user (download)
                if let Some(ref m) = metrics {
                    m.bytes_out.fetch_add(plaintext.len() as u64, Ordering::Relaxed);
                }
                if user_w.flush().await.is_err() { break; }
            }
        }
        // Flush remaining buffered compressed data
        if let Some(ref mut dec) = decompressor {
            match dec.flush() {
                Ok(plaintext) if !plaintext.is_empty() => {
                    let _ = user_w.write_all(&plaintext).await;
                    if let Some(ref m) = metrics {
                        m.bytes_out.fetch_add(plaintext.len() as u64, Ordering::Relaxed);
                    }
                    let _ = user_w.flush().await;
                }
                Err(e) => {
                    tracing::warn!("snappy flush error in encrypted bridge: {}", e);
                }
                _ => {}
            }
        }
    };

    // Use join! (not select!): both directions must complete, matching Go frp's WaitGroup
    let _ = tokio::join!(user_to_work, work_to_user);
}

/// Plain (unencrypted) bidirectional bridge with optional compression.
pub async fn bridge_plain(
    mut user_r: impl AsyncReadExt + Unpin,
    mut user_w: impl AsyncWriteExt + Unpin,
    mut work_r: impl AsyncReadExt + Unpin,
    mut work_w: impl AsyncWriteExt + Unpin,
    use_compression: bool,
    pre_read: Vec<u8>,
    metrics: Option<Arc<crate::metrics::ProxyMetrics>>,
) {
    let user_to_work = async {
        if !pre_read.is_empty()
            && work_w.write_all(&pre_read).await.is_err() {
                return;
            }
        let mut buf = vec![0u8; 65536];
        loop {
            let n = match user_r.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if let Some(ref m) = metrics {
                        m.bytes_in.fetch_add(n as u64, Ordering::Relaxed);
                    }
                    n
                }
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
            if work_w.write_all(&processed).await.is_err() { break; }
            if work_w.flush().await.is_err() { break; }
        }
        let _ = work_w.shutdown().await;
    };
    let work_to_user = async {
        let mut buf = vec![0u8; 65536];
        let mut decompressor = if use_compression {
            Some(encryption::SnappyDecompressor::new())
        } else {
            None
        };
        loop {
            let n = match work_r.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            };
            let plaintext = if let Some(ref mut dec) = decompressor {
                match dec.feed(&buf[..n]) {
                    Ok(p) => p,
                    Err(e) => {
                        tracing::warn!("snappy decompress error in bridge: {}", e);
                        break;
                    }
                }
            } else {
                buf[..n].to_vec()
            };
            if !plaintext.is_empty() {
                if user_w.write_all(&plaintext).await.is_err() { break; }
                if let Some(ref m) = metrics {
                    m.bytes_out.fetch_add(plaintext.len() as u64, Ordering::Relaxed);
                }
                if user_w.flush().await.is_err() { break; }
            }
        }
        // Flush remaining buffered compressed data
        if let Some(ref mut dec) = decompressor {
            match dec.flush() {
                Ok(plaintext) if !plaintext.is_empty() => {
                    let _ = user_w.write_all(&plaintext).await;
                    if let Some(ref m) = metrics {
                        m.bytes_out.fetch_add(plaintext.len() as u64, Ordering::Relaxed);
                    }
                    let _ = user_w.flush().await;
                }
                Err(e) => {
                    tracing::warn!("snappy flush error in bridge: {}", e);
                }
                _ => {}
            }
        }
        let _ = user_w.shutdown().await;
    };
    let _ = tokio::join!(user_to_work, work_to_user);
}

/// Plain (unencrypted) bidirectional bridge with optional bandwidth limiting.
///
/// Uses the same `join!`-of-two-halves pattern as `bridge_encrypted` so that
/// both directions run to completion independently. When neither limiter is
/// active this is equivalent to `tokio::io::copy_bidirectional`.
///
/// `read_limiter` throttles work→user (download).
/// `write_limiter` throttles user→work (upload).
pub async fn bridge_plain_rate_limited(
    mut user_r: impl AsyncReadExt + Unpin,
    mut user_w: impl AsyncWriteExt + Unpin,
    mut work_r: impl AsyncReadExt + Unpin,
    mut work_w: impl AsyncWriteExt + Unpin,
    mut read_limiter: Option<&mut BandwidthLimiter>,
    mut write_limiter: Option<&mut BandwidthLimiter>,
    metrics: Option<Arc<crate::metrics::ProxyMetrics>>,
) {
    // User → Work
    let user_to_work = async {
        let mut buf = vec![0u8; 65536];
        loop {
            let n = match user_r.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if let Some(ref m) = metrics {
                        m.bytes_in.fetch_add(n as u64, Ordering::Relaxed);
                    }
                    n
                }
                Err(_) => break,
            };
            if let Some(ref mut lim) = write_limiter {
                lim.consume(n).await;
            }
            if work_w.write_all(&buf[..n]).await.is_err() { break; }
            if work_w.flush().await.is_err() { break; }
        }
        // Signal EOF to work side so the peer knows we're done writing
        let _ = work_w.shutdown().await;
    };

    // Work → User
    let work_to_user = async {
        let mut buf = vec![0u8; 65536];
        loop {
            let n = match work_r.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            };
            if let Some(ref mut lim) = read_limiter {
                lim.consume(n).await;
            }
            if user_w.write_all(&buf[..n]).await.is_err() { break; }
            if let Some(ref m) = metrics {
                m.bytes_out.fetch_add(n as u64, Ordering::Relaxed);
            }
            if user_w.flush().await.is_err() { break; }
        }
        let _ = user_w.shutdown().await;
    };

    let _ = tokio::join!(user_to_work, work_to_user);
}
