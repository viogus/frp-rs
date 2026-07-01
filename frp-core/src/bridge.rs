use std::sync::Arc;
use std::sync::atomic::Ordering;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::bandwidth::BandwidthLimiter;
use crate::cipher_stream::{CipherReader, CipherWriter};
use crate::encryption;
use crate::transport::IoStream;
use tracing::instrument;

/// Bridge encrypted data between two IoStreams, splitting them internally.
#[allow(clippy::too_many_arguments)]
#[instrument(skip(user, work, key, pre_read, read_limiter, write_limiter, metrics), fields(use_compression))]
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
#[allow(clippy::too_many_arguments)]
#[instrument(skip(user_r, user_w, work_r, work_w, key, pre_read, read_limiter, write_limiter, metrics), fields(use_compression))]
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

    // Eagerly flush the IV to unblock the peer's CipherReader.
    // Without this, when both sides use CipherWriter/CipherReader pairs,
    // each side's work_to_user task blocks on CipherReader::read() waiting
    // for the other side's IV, while the other side's user_to_work task
    // blocks waiting for user data — deadlock. Flushing here sends our
    // random IV immediately so the peer's CipherReader can make progress.
    if enc_work_w.flush().await.is_err() {
        return;
    }

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
        #[cfg(feature = "compression")]
        let mut decompressor = if use_compression {
            Some(encryption::SnappyDecompressor::new())
        } else {
            None
        };
        #[cfg(not(feature = "compression"))]
        let mut decompressor: Option<encryption::SnappyDecompressor> = None;
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
                    #[cfg(feature = "compression")]
                    Err(e) => {
                        tracing::warn!(error = %e, "snappy decompress error in encrypted bridge: {}", e);
                        break;
                    }
                    #[cfg(not(feature = "compression"))]
                    Err(_) => break,
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
                    if let Err(e) = user_w.write_all(&plaintext).await {
                        tracing::debug!(error = %e, "bridge_encrypted flush: user_w.write_all failed");
                    }
                    if let Some(ref m) = metrics {
                        m.bytes_out.fetch_add(plaintext.len() as u64, Ordering::Relaxed);
                    }
                    if let Err(e) = user_w.flush().await {
                        tracing::debug!(error = %e, "bridge_encrypted flush: user_w.flush failed");
                    }
                }
                #[cfg(feature = "compression")]
                Err(e) => {
                    tracing::warn!(error = %e, "snappy flush error in encrypted bridge: {}", e);
                }
                _ => {}
            }
        }
    };

    // Use join! (not select!): both directions must complete, matching Go frp's WaitGroup
    let _ = tokio::join!(user_to_work, work_to_user);
}

/// Plain (unencrypted) bidirectional bridge with optional compression.
#[instrument(skip(user_r, user_w, work_r, work_w, pre_read, metrics), fields(use_compression))]
pub async fn bridge_plain(
    mut user_r: impl AsyncReadExt + Unpin,
    mut user_w: impl AsyncWriteExt + Unpin,
    mut work_r: impl AsyncReadExt + Unpin,
    mut work_w: impl AsyncWriteExt + Unpin,
    use_compression: bool,
    pre_read: Vec<u8>,
    metrics: Option<Arc<crate::metrics::ProxyMetrics>>,
) {
    let had_pre_read = !pre_read.is_empty();
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
        // When pre_read bytes were forwarded (e.g. VHost HTTP handler consumed
        // the user's request), leave work_w open so work_to_user can receive
        // the backend response. The frpc side will see EOF from user_w.shutdown()
        // in work_to_user after the response is complete.
        if !had_pre_read {
            if let Err(e) = work_w.shutdown().await {
                tracing::debug!(error = %e, "bridge_encrypted shutdown: work_w.shutdown failed");
            }
        }
    };
    let work_to_user = async {
        let mut buf = vec![0u8; 65536];
        #[cfg(feature = "compression")]
        let mut decompressor = if use_compression {
            Some(encryption::SnappyDecompressor::new())
        } else {
            None
        };
        #[cfg(not(feature = "compression"))]
        let mut decompressor: Option<encryption::SnappyDecompressor> = None;
        loop {
            let n = match work_r.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            };
            let plaintext = if let Some(ref mut dec) = decompressor {
                match dec.feed(&buf[..n]) {
                    Ok(p) => p,
                    #[cfg(feature = "compression")]
                    Err(e) => {
                        tracing::warn!(error = %e, "snappy decompress error in bridge: {}", e);
                        break;
                    }
                    #[cfg(not(feature = "compression"))]
                    Err(_) => break,
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
                    if let Err(e) = user_w.write_all(&plaintext).await {
                        tracing::debug!(error = %e, "bridge_plain flush: user_w.write_all failed");
                    }
                    if let Some(ref m) = metrics {
                        m.bytes_out.fetch_add(plaintext.len() as u64, Ordering::Relaxed);
                    }
                    if let Err(e) = user_w.flush().await {
                        tracing::debug!(error = %e, "bridge_plain flush: user_w.flush failed");
                    }
                }
                #[cfg(feature = "compression")]
                Err(e) => {
                    tracing::warn!(error = %e, "snappy flush error in bridge: {}", e);
                }
                _ => {}
            }
        }
        if let Err(e) = user_w.shutdown().await {
            tracing::debug!(error = %e, "bridge_plain shutdown: user_w.shutdown failed");
        }
    };
    let _ = tokio::join!(user_to_work, work_to_user);
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Plain bridge: basic bidirectional data flow.
    #[tokio::test]
    async fn test_bridge_plain_bidirectional() {
        let (mut u_w_test, u_r_bridge) = tokio::io::duplex(65536);
        let (w_w_bridge, mut w_r_test) = tokio::io::duplex(65536);
        let (mut w_w_test, w_r_bridge) = tokio::io::duplex(65536);
        let (u_w_bridge, mut u_r_test) = tokio::io::duplex(65536);

        tokio::spawn(async move {
            bridge_plain(
                u_r_bridge, u_w_bridge, w_r_bridge, w_w_bridge,
                false, vec![], None,
            ).await;
        });

        // User → Work
        u_w_test.write_all(b"user->work").await.unwrap();
        u_w_test.flush().await.unwrap();
        let mut buf = vec![0u8; 1024];
        let n = w_r_test.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"user->work");

        // Work → User
        w_w_test.write_all(b"work->user").await.unwrap();
        w_w_test.flush().await.unwrap();
        let n2 = u_r_test.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n2], b"work->user");
    }

    /// Plain bridge with pre_read: bytes forwarded before main loop.
    #[tokio::test]
    async fn test_bridge_plain_pre_read() {
        let (mut u_w_test, u_r_bridge) = tokio::io::duplex(65536);
        let (w_w_bridge, mut w_r_test) = tokio::io::duplex(65536);
        let (_w_w_test, w_r_bridge) = tokio::io::duplex(65536);
        let (u_w_bridge, _u_r_test) = tokio::io::duplex(65536);

        let pre_read = b"pre-read body".to_vec();

        tokio::spawn(async move {
            bridge_plain(
                u_r_bridge, u_w_bridge, w_r_bridge, w_w_bridge,
                false, pre_read, None,
            ).await;
        });

        let mut buf = vec![0u8; 1024];
        let n = w_r_test.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"pre-read body");

        u_w_test.write_all(b"after").await.unwrap();
        u_w_test.flush().await.unwrap();
        let n2 = w_r_test.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n2], b"after");
    }

    /// Encrypted bridge: smoke test — starts, processes data, completes without panic.
    /// Content verification is done in cipher_stream tests.
    /// Note: bridge uses tokio::join! — both directions must complete. We drop
    /// both write sides to signal EOF on both read sides.
    #[tokio::test]
    async fn test_encrypted_bridge_smoke() {
        let key = crate::encryption::derive_key("smoke_test_key_42");

        let (mut u_w_test, u_r_bridge) = tokio::io::duplex(65536);
        let (w_w_bridge, _w_r_test) = tokio::io::duplex(65536);
        let (w_w_test, w_r_bridge) = tokio::io::duplex(65536);
        let (u_w_bridge, _u_r_test) = tokio::io::duplex(65536);

        let handle = tokio::spawn(async move {
            bridge_encrypted(
                u_r_bridge, u_w_bridge, w_r_bridge, w_w_bridge,
                &key, false, vec![], None, None, None,
            ).await;
        });

        u_w_test.write_all(b"hello encrypted world").await.unwrap();
        u_w_test.flush().await.unwrap();
        drop(u_w_test); // EOF on user_r
        drop(w_w_test); // EOF on work_r (so enc_work_r.read() returns 0)

        handle.await.unwrap();
    }

    /// Encrypted bridge with compression: smoke test.
    #[tokio::test]
    async fn test_encrypted_bridge_compression_smoke() {
        let key = crate::encryption::derive_key("comp_smoke_key_99");

        let (mut u_w_test, u_r_bridge) = tokio::io::duplex(65536);
        let (w_w_bridge, _w_r_test) = tokio::io::duplex(65536);
        let (w_w_test, w_r_bridge) = tokio::io::duplex(65536);
        let (u_w_bridge, _u_r_test) = tokio::io::duplex(65536);

        let handle = tokio::spawn(async move {
            bridge_encrypted(
                u_r_bridge, u_w_bridge, w_r_bridge, w_w_bridge,
                &key, true, vec![], None, None, None,
            ).await;
        });

        let msg = b"AAAA".repeat(256);
        u_w_test.write_all(&msg).await.unwrap();
        u_w_test.flush().await.unwrap();
        drop(u_w_test);
        drop(w_w_test);

        handle.await.unwrap();
    }

    /// Encrypted bridge: large data smoke test.
    #[tokio::test]
    async fn test_encrypted_bridge_large_smoke() {
        let key = crate::encryption::derive_key("large_smoke_12345");

        let (mut u_w_test, u_r_bridge) = tokio::io::duplex(256 * 1024);
        let (w_w_bridge, _w_r_test) = tokio::io::duplex(256 * 1024);
        let (w_w_test, w_r_bridge) = tokio::io::duplex(256 * 1024);
        let (u_w_bridge, _u_r_test) = tokio::io::duplex(256 * 1024);

        let handle = tokio::spawn(async move {
            bridge_encrypted(
                u_r_bridge, u_w_bridge, w_r_bridge, w_w_bridge,
                &key, false, vec![], None, None, None,
            ).await;
        });

        let large_msg = vec![0x42u8; 100_000];
        u_w_test.write_all(&large_msg).await.unwrap();
        u_w_test.flush().await.unwrap();
        drop(u_w_test);
        drop(w_w_test);

        handle.await.unwrap();
    }
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
