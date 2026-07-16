//! AEAD stream encryption for V2 control channel.
//!
//! Matches Go frp `libcrypto.NewAEADStreamReader` / `libcrypto.NewAEADStreamWriter`.
//!
//! Wire format:
//!   [stream_nonce] [frame]*  (stream_nonce sent once, then repeated frames)
//!
//! Each frame:
//!   uint32 ciphertext_len (big-endian, includes AEAD overhead)
//!   AEAD ciphertext (authenticated + tag)
//!
//! AAD (authenticated additional data): stream_nonce || frame_header (4 bytes)
//! Nonce: starts as stream_nonce, increments by 1 per frame (big-endian)
//!
//! AES-256-GCM limit: 2^32 frames per stream
//! XChaCha20-Poly1305: no explicit limit (XChaCha internal limit is 2^64 blocks)

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[cfg(feature = "chacha20")]
use chacha20poly1305::aead::{Aead, AeadInPlace};
#[cfg(feature = "chacha20")]
use chacha20poly1305::{KeyInit, XChaCha20Poly1305};
use rand::RngCore;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::hkdf::{Salt, HKDF_SHA256};

const AEAD_KEY_SIZE: usize = 32;
const AEAD_FRAME_HEADER_SIZE: usize = 4;
const DEFAULT_MAX_PAYLOAD_SIZE: usize = 64 * 1024;
const MAX_AES_GCM_FRAME_COUNT: u64 = 1u64 << 32;

// ---------------------------------------------------------------------------
// Algorithm enum
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadAlgorithm {
    Aes256Gcm,
    #[cfg(feature = "chacha20")]
    XChaCha20Poly1305,
}

impl std::str::FromStr for AeadAlgorithm {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "aes-256-gcm" => Ok(Self::Aes256Gcm),
            #[cfg(feature = "chacha20")]
            "xchacha20-poly1305" => Ok(Self::XChaCha20Poly1305),
            _ => Err(()),
        }
    }
}

impl AeadAlgorithm {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Aes256Gcm => "aes-256-gcm",
            #[cfg(feature = "chacha20")]
            Self::XChaCha20Poly1305 => "xchacha20-poly1305",
        }
    }

    fn nonce_size(&self) -> usize {
        match self {
            Self::Aes256Gcm => 12, // AES-256-GCM standard nonce
            #[cfg(feature = "chacha20")]
            Self::XChaCha20Poly1305 => 24, // XChaCha20-Poly1305 extended nonce
        }
    }

    fn overhead(&self) -> usize {
        16 // Both algorithms use 16-byte authentication tag
    }

    fn max_frame_count(&self) -> Option<u64> {
        match self {
            Self::Aes256Gcm => Some(MAX_AES_GCM_FRAME_COUNT),
            #[cfg(feature = "chacha20")]
            Self::XChaCha20Poly1305 => None,
        }
    }
}

// ---------------------------------------------------------------------------
// AEAD trait for encrypt/decrypt
// ---------------------------------------------------------------------------

enum AeadCipher {
    /// ring-based AES-256-GCM (via LessSafeKey for non-96-bit nonce support).
    Aes256Gcm(Box<LessSafeKey>),
    #[cfg(feature = "chacha20")]
    XChaCha20Poly1305(XChaCha20Poly1305),
}

impl AeadCipher {
    fn new(algorithm: AeadAlgorithm, key: &[u8]) -> Result<Self, String> {
        if key.len() != AEAD_KEY_SIZE {
            return Err(format!(
                "AEAD key must be {} bytes, got {}",
                AEAD_KEY_SIZE,
                key.len()
            ));
        }
        match algorithm {
            AeadAlgorithm::Aes256Gcm => {
                let unbound = UnboundKey::new(&AES_256_GCM, key)
                    .map_err(|e| format!("aes-256-gcm init: {e}"))?;
                Ok(Self::Aes256Gcm(Box::new(LessSafeKey::new(unbound))))
            }
            #[cfg(feature = "chacha20")]
            AeadAlgorithm::XChaCha20Poly1305 => {
                let cipher = XChaCha20Poly1305::new_from_slice(key)
                    .map_err(|e| format!("xchacha20-poly1305 init: {e}"))?;
                Ok(Self::XChaCha20Poly1305(cipher))
            }
        }
    }

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
                let tag = c
                    .encrypt_in_place_detached(nonce, aad, &mut in_out)
                    .map_err(|e| format!("xchacha20 encrypt: {e}"))?;
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
                let plaintext_len = key
                    .open_in_place(nonce, aad, &mut in_out)
                    .map_err(|e| format!("aes-gcm decrypt: {e}"))?
                    .len();
                in_out.truncate(plaintext_len);
                Ok(in_out)
            }
            #[cfg(feature = "chacha20")]
            Self::XChaCha20Poly1305(c) => {
                let nonce = chacha20poly1305::XNonce::from_slice(nonce);
                let payload = chacha20poly1305::aead::Payload { msg: &in_out, aad };
                c.decrypt(nonce, payload)
                    .map_err(|e| format!("xchacha20 decrypt: {e}"))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Combined AeadStream (AsyncRead + AsyncWrite) — wraps Box<dyn AsyncReadWriteUnpin>
// ---------------------------------------------------------------------------

use crate::cipher_stream::AsyncReadWriteUnpin;

/// Read-half state for an AEAD stream.
struct AeadReadState {
    cipher: AeadCipher,
    nonce: Vec<u8>,
    stream_nonce: Option<Vec<u8>>,
    header_read: bool,
    frame_count: u64,
    max_frame_count: Option<u64>,
    buf: Vec<u8>,
    buf_pos: usize,
    err: Option<io::Error>,
    scratch: Vec<u8>,
    scratch_filled: usize,
    /// Per-frame header persisted across polls so a mid-ciphertext `Pending`
    /// does not re-read (and re-consume) the 4-byte length header.
    header_buf: [u8; AEAD_FRAME_HEADER_SIZE],
    header_have: bool,
    /// Reusable AAD buffer: stream_nonce || frame_header (4 bytes).
    /// Allocated once when stream_nonce is set, reused per frame.
    aad_buf: Vec<u8>,
}

/// Write-half state for an AEAD stream.
struct AeadWriteState {
    cipher: AeadCipher,
    nonce: Vec<u8>,
    stream_nonce: Vec<u8>,
    header_sent: bool,
    frame_count: u64,
    max_frame_count: Option<u64>,
    pending: Vec<u8>,
    pending_pos: usize,
    err: Option<io::Error>,
    /// Reusable AAD buffer: stream_nonce || frame_header (4 bytes).
    /// Allocated once, reused per frame.
    aad_buf: Vec<u8>,
}

/// Combined AEAD stream wrapping a bidirectional byte transport.
///
/// Internally manages independent read and write states, each with their own
/// nonce, cipher, and buffering. Matches Go frp's pattern of wrapping an
/// `io.ReadWriter` with separate AEAD reader/writer halves.
pub struct AeadStream {
    inner: Box<dyn AsyncReadWriteUnpin>,
    algorithm: AeadAlgorithm,
    read: AeadReadState,
    write: AeadWriteState,
}

impl AeadStream {
    /// Create a new AEAD stream wrapping `inner`.
    ///
    /// `read_key` and `write_key` are the derived directional AEAD keys
    /// (32 bytes each). `algorithm` selects AES-256-GCM or XChaCha20-Poly1305.
    ///
    /// SAFETY CONTRACT: This type uses `ring::aead::LessSafeKey` which bypasses
    /// nonce uniqueness checks. The caller MUST ensure nonces are never reused
    /// with the same key. This stream implementation guarantees uniqueness by
    /// incrementing a counter — any refactoring of nonce management must
    /// preserve this invariant.
    pub fn new(
        inner: Box<dyn AsyncReadWriteUnpin>,
        algorithm: AeadAlgorithm,
        read_key: &[u8],
        write_key: &[u8],
    ) -> Result<Self, String> {
        let read_cipher = AeadCipher::new(algorithm, read_key)?;
        let write_cipher = AeadCipher::new(algorithm, write_key)?;
        let nonce_size = algorithm.nonce_size();
        let write_nonce = generate_random(nonce_size)?;

        // Pre-allocate read scratch to max frame size so per-frame read_exact
        // calls reuse the same allocation (split_off preserves capacity).
        let max_ciphertext = DEFAULT_MAX_PAYLOAD_SIZE + algorithm.overhead();

        Ok(Self {
            inner,
            algorithm,
            read: AeadReadState {
                cipher: read_cipher,
                nonce: vec![0u8; nonce_size],
                stream_nonce: None,
                header_read: false,
                frame_count: 0,
                max_frame_count: algorithm.max_frame_count(),
                buf: Vec::new(),
                buf_pos: 0,
                err: None,
                scratch: Vec::with_capacity(max_ciphertext),
                scratch_filled: 0,
                header_buf: [0u8; AEAD_FRAME_HEADER_SIZE],
                header_have: false,
                aad_buf: Vec::with_capacity(nonce_size + AEAD_FRAME_HEADER_SIZE),
            },
            write: AeadWriteState {
                cipher: write_cipher,
                nonce: write_nonce.clone(),
                stream_nonce: write_nonce.clone(),
                header_sent: false,
                frame_count: 0,
                max_frame_count: algorithm.max_frame_count(),
                pending: Vec::new(),
                pending_pos: 0,
                err: None,
                aad_buf: Vec::with_capacity(nonce_size + AEAD_FRAME_HEADER_SIZE),
            },
        })
    }
}

// --- AsyncRead impl ---

impl AsyncRead for AeadStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.read.err.is_some() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "previous read error",
            )));
        }
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        // Serve from buffered plaintext
        if self.read.buf_pos < self.read.buf.len() {
            let available = self.read.buf.len() - self.read.buf_pos;
            let to_copy = available.min(buf.remaining());
            buf.put_slice(&self.read.buf[self.read.buf_pos..self.read.buf_pos + to_copy]);
            self.read.buf_pos += to_copy;
            if self.read.buf_pos >= self.read.buf.len() {
                self.read.buf.clear();
                self.read.buf_pos = 0;
            }
            return Poll::Ready(Ok(()));
        }

        // Read next frame
        let this = &mut *self;
        match this.poll_read_frame(cx) {
            Poll::Ready(Ok(true)) => {
                // Serve from new buffer
                let available = this.read.buf.len() - this.read.buf_pos;
                let to_copy = available.min(buf.remaining());
                buf.put_slice(&this.read.buf[this.read.buf_pos..this.read.buf_pos + to_copy]);
                this.read.buf_pos += to_copy;
                if this.read.buf_pos >= this.read.buf.len() {
                    this.read.buf.clear();
                    this.read.buf_pos = 0;
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Ok(false)) => {
                // Clean EOF at frame boundary
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => {
                this.read.err = Some(io::Error::new(e.kind(), e.to_string()));
                Poll::Ready(Err(e))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AeadStream {
    /// Read one AEAD frame. Returns `Ok(true)` when a frame was decoded,
    /// `Ok(false)` on clean EOF at frame boundary.
    fn poll_read_frame(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        tracing::debug!(read_header_read = %self.read.header_read, read_frame_count = %self.read.frame_count, "[AEAD-READ] poll_read_frame called, read_header_read={}, read_frame_count={}",
            self.read.header_read, self.read.frame_count);
        // Read stream nonce on first frame
        if !self.read.header_read {
            match self.read_exact(self.read.nonce.len(), cx) {
                Poll::Ready(Ok(data)) => {
                    self.read.nonce.copy_from_slice(&data);
                    self.read.stream_nonce = Some(data.to_vec());
                    self.read.header_read = true;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        // Read 4-byte header. EOF here = clean end of stream. Persisted across
        // polls: once obtained, a mid-ciphertext `Pending` re-enters this fn but
        // must not re-read the header (those bytes are already consumed).
        if !self.read.header_have {
            match self.read_exact(AEAD_FRAME_HEADER_SIZE, cx) {
                Poll::Ready(Ok(data)) => {
                    self.read.header_buf.copy_from_slice(&data);
                    self.read.header_have = true;
                }
                // Clean EOF only when the header read consumed ZERO bytes (we are
                // exactly at a frame boundary). A partial header followed by EOF is
                // a truncated stream and must surface as an error, not a clean end.
                Poll::Ready(Err(ref e))
                    if e.kind() == io::ErrorKind::UnexpectedEof
                        && self.read.scratch_filled == 0 =>
                {
                    return Poll::Ready(Ok(false)); // clean EOF at frame boundary
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        let header = self.read.header_buf;

        if let Some(ref max) = self.read.max_frame_count {
            if self.read.frame_count >= *max {
                return Poll::Ready(Err(io::Error::other(
                    "AEAD read frame count limit exceeded",
                )));
            }
        }

        let ciphertext_len = u32::from_be_bytes(header) as usize;
        let overhead = self.algorithm.overhead();
        if ciphertext_len < overhead {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("AEAD ciphertext length {ciphertext_len} < overhead {overhead}"),
            )));
        }
        let max_ciphertext = DEFAULT_MAX_PAYLOAD_SIZE + overhead;
        if ciphertext_len > max_ciphertext {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("AEAD ciphertext length {ciphertext_len} exceeds limit {max_ciphertext}"),
            )));
        }

        let ciphertext = match self.read_exact(ciphertext_len, cx) {
            Poll::Ready(Ok(data)) => data,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        };

        let stream_nonce = self
            .read
            .stream_nonce
            .as_ref()
            .expect("stream_nonce must be set");
        self.read.aad_buf.clear();
        self.read.aad_buf.extend_from_slice(stream_nonce);
        self.read.aad_buf.extend_from_slice(&header);

        let plaintext = match self.read.cipher.decrypt(
            &self.read.nonce,
            ciphertext,
            &self.read.aad_buf,
        ) {
            Ok(p) => {
                tracing::debug!(frame = %self.read.frame_count, plaintext_len = %p.len(), "[AEAD-READ] frame={} decrypt OK, plaintext_len={}", self.read.frame_count, p.len());
                p
            }
            Err(e) => {
                #[cfg(debug_assertions)]
                tracing::warn!(frame = %self.read.frame_count, error = %e, nonce = %crate::hex_encode(&self.read.nonce), stream_nonce = %crate::hex_encode(stream_nonce), "[AEAD-READ] frame={} decrypt FAILED: {} (nonce={}, stream_nonce={})",
                    self.read.frame_count, e,
                    crate::hex_encode(&self.read.nonce),
                    crate::hex_encode(stream_nonce));
                #[cfg(not(debug_assertions))]
                tracing::warn!(frame = %self.read.frame_count, error = %e, "[AEAD-READ] frame={} decrypt FAILED: {}", self.read.frame_count, e);
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("AEAD decrypt: {e}"),
                )));
            }
        };

        if !increment_nonce(&mut self.read.nonce) {
            return Poll::Ready(Err(io::Error::other("AEAD read nonce exhausted")));
        }
        self.read.frame_count += 1;

        // Frame consumed: allow the next frame to read its own header.
        self.read.header_have = false;
        self.read.buf = plaintext;
        self.read.buf_pos = 0;
        Poll::Ready(Ok(true))
    }

    fn read_exact(&mut self, len: usize, cx: &mut Context<'_>) -> Poll<io::Result<Vec<u8>>> {
        // Resume an in-progress read of this exact length, or start a fresh one.
        // On completion the scratch is emptied (len 0), so any new read re-sizes.
        // Invariant: between reads the scratch is empty (`filled == 0`); a resumed
        // read has `scratch.len() == len`. If this trips, some exit path failed to
        // reset state and the resize guard below would treat stale bytes as freshly
        // read (silent frame corruption).
        debug_assert!(
            self.read.scratch_filled == 0 || self.read.scratch.len() == len,
            "read_exact state leak: filled={} scratch_len={} len={}",
            self.read.scratch_filled,
            self.read.scratch.len(),
            len,
        );
        if self.read.scratch.len() != len {
            self.read.scratch.clear();
            // Always zero-initialize: passing &mut [u8] of uninitialized
            // memory to ReadBuf::new() is UB per Rust reference validity
            // rules, even when guarded by a fill counter.
            self.read.scratch.resize(len, 0);
            self.read.scratch_filled = 0;
        }
        while self.read.scratch_filled < len {
            let mut rb = ReadBuf::new(&mut self.read.scratch[self.read.scratch_filled..]);
            let pin = Pin::new(&mut *self.inner);
            match pin.poll_read(cx, &mut rb) {
                Poll::Ready(Ok(())) => {
                    let n = rb.filled().len();
                    if n == 0 {
                        // No progress on a Ready poll => inner reached EOF before `len` bytes.
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            format!(
                                "AEAD stream: unexpected EOF (need {len}, got {})",
                                self.read.scratch_filled
                            ),
                        )));
                    }
                    self.read.scratch_filled += n;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending, // progress saved in read_scratch_filled
            }
        }
        // split_off(0) returns the data while preserving self.read.scratch's
        // capacity — next read_exact with same or smaller len reuses the
        // allocation (resize only zero-fills, no heap alloc).
        let data = self.read.scratch.split_off(0);
        self.read.scratch_filled = 0;
        Poll::Ready(Ok(data))
    }
}

// --- AsyncWrite impl ---

impl AsyncWrite for AeadStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.write.err.is_some() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "previous write error",
            )));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let this = &mut *self;

        // If we have pending data to flush, try flushing first
        if this.write.pending_pos < this.write.pending.len() {
            match this.poll_flush_pending(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        // Build a new frame
        if let Some(ref max) = this.write.max_frame_count {
            if this.write.frame_count >= *max {
                let e = io::Error::other("AEAD write frame count limit exceeded");
                this.write.err = Some(e);
                return Poll::Ready(Err(io::Error::other("frame count exceeded")));
            }
        }

        let chunk_size = buf.len().min(DEFAULT_MAX_PAYLOAD_SIZE);
        let plaintext = &buf[..chunk_size];

        // Send stream nonce first if needed
        if !this.write.header_sent {
            #[cfg(debug_assertions)]
            tracing::debug!(nonce = %crate::hex_encode(&this.write.nonce), "[AEAD-WRITE] first write: nonce={}", crate::hex_encode(&this.write.nonce));
            #[cfg(not(debug_assertions))]
            tracing::debug!("[AEAD-WRITE] first write");
            // Queue the nonce write
            let mut pending = this.write.stream_nonce.clone();
            let overhead = this.algorithm.overhead();
            let ciphertext_len = (plaintext.len() + overhead) as u32;
            let mut header = [0u8; AEAD_FRAME_HEADER_SIZE];
            header.copy_from_slice(&ciphertext_len.to_be_bytes());

            this.write.aad_buf.clear();
            this.write
                .aad_buf
                .extend_from_slice(&this.write.stream_nonce);
            this.write.aad_buf.extend_from_slice(&header);

            let sealed = match this.write.cipher.encrypt(
                &this.write.nonce,
                plaintext.to_vec(),
                &this.write.aad_buf,
            ) {
                Ok(s) => s,
                Err(e) => {
                    let io_err = io::Error::other(e);
                    this.write.err = Some(io_err);
                    return Poll::Ready(Err(io::Error::other("encrypt failed")));
                }
            };

            pending.extend_from_slice(&header);
            pending.extend_from_slice(&sealed);

            if !increment_nonce(&mut this.write.nonce) {
                return Poll::Ready(Err(io::Error::other("AEAD write nonce exhausted")));
            }
            this.write.frame_count += 1;
            this.write.header_sent = true;
            tracing::debug!(frame = %this.write.frame_count, pending_len = %this.write.pending.len(), "[AEAD-WRITE] frame={} encrypted, pending_len={}", this.write.frame_count, this.write.pending.len());

            this.write.pending = pending;
            this.write.pending_pos = 0;
        } else {
            let overhead = this.algorithm.overhead();
            let ciphertext_len = (plaintext.len() + overhead) as u32;
            let mut header = [0u8; AEAD_FRAME_HEADER_SIZE];
            header.copy_from_slice(&ciphertext_len.to_be_bytes());

            this.write.aad_buf.clear();
            this.write
                .aad_buf
                .extend_from_slice(&this.write.stream_nonce);
            this.write.aad_buf.extend_from_slice(&header);

            let sealed = match this.write.cipher.encrypt(
                &this.write.nonce,
                plaintext.to_vec(),
                &this.write.aad_buf,
            ) {
                Ok(s) => s,
                Err(e) => {
                    let io_err = io::Error::other(e);
                    this.write.err = Some(io_err);
                    return Poll::Ready(Err(io::Error::other("encrypt failed")));
                }
            };

            if !increment_nonce(&mut this.write.nonce) {
                return Poll::Ready(Err(io::Error::other("AEAD write nonce exhausted")));
            }
            this.write.frame_count += 1;

            let mut pending = Vec::with_capacity(AEAD_FRAME_HEADER_SIZE + sealed.len());
            pending.extend_from_slice(&header);
            pending.extend_from_slice(&sealed);
            this.write.pending = pending;
            this.write.pending_pos = 0;
        }

        // Flush the pending data
        match this.poll_flush_pending(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(chunk_size)),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        // Flush any pending write data first
        match this.poll_flush_pending(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
        Pin::new(&mut *this.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        // Flush pending writes before shutdown
        match this.poll_flush_pending(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
        Pin::new(&mut *this.inner).poll_shutdown(cx)
    }
}

impl AeadStream {
    fn poll_flush_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.write.pending_pos < self.write.pending.len() {
            let pin = Pin::new(&mut *self.inner);
            match pin.poll_write(cx, &self.write.pending[self.write.pending_pos..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "write zero",
                    )));
                }
                Poll::Ready(Ok(n)) => {
                    self.write.pending_pos += n;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.write.pending.clear();
        self.write.pending_pos = 0;
        Poll::Ready(Ok(()))
    }
}

// ---------------------------------------------------------------------------
// Key derivation (HKDF-SHA256)
// ---------------------------------------------------------------------------

/// Derive AEAD control keys using HKDF-SHA256.
///
/// Matches Go frp `deriveAEADControlKeys`:
/// - IKM = token bytes (raw, not PBKDF2-derived)
/// - salt = transcript_hash
/// - info = "frp wire v2 control aead <algorithm> <direction>"
/// - output = 32 bytes
pub fn derive_aead_control_keys(
    token: &[u8],
    algorithm: AeadAlgorithm,
    transcript_hash: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let client_to_server =
        derive_aead_control_key(token, algorithm, transcript_hash, "client-to-server")?;
    let server_to_client =
        derive_aead_control_key(token, algorithm, transcript_hash, "server-to-client")?;
    Ok((client_to_server, server_to_client))
}

fn derive_aead_control_key(
    token: &[u8],
    algorithm: AeadAlgorithm,
    transcript_hash: &[u8],
    direction: &str,
) -> Result<Vec<u8>, String> {
    let info = format!(
        "frp wire v2 control aead {} {}",
        algorithm.as_str(),
        direction
    );
    let salt = Salt::new(HKDF_SHA256, transcript_hash);
    let prk = salt.extract(token);
    let mut okm = vec![0u8; AEAD_KEY_SIZE];
    let info_refs = [info.as_bytes()];
    let okm_result = prk
        .expand(&info_refs, HKDF_SHA256)
        .map_err(|e| format!("HKDF expand: {e}"))?;
    okm_result
        .fill(&mut okm)
        .map_err(|e| format!("HKDF fill: {e}"))?;
    Ok(okm)
}

// ---------------------------------------------------------------------------
// Helper: increment nonce (big-endian, returns false on wrap)
// ---------------------------------------------------------------------------

fn increment_nonce(nonce: &mut [u8]) -> bool {
    for i in (0..nonce.len()).rev() {
        nonce[i] = nonce[i].wrapping_add(1);
        if nonce[i] != 0 {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Helper: generate random bytes
// ---------------------------------------------------------------------------

pub fn generate_random(len: usize) -> Result<Vec<u8>, String> {
    let mut buf = vec![0u8; len];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    Ok(buf)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_increment_nonce() {
        let mut nonce = vec![0u8; 12];
        assert!(increment_nonce(&mut nonce));
        assert_eq!(nonce[11], 1);
        assert_eq!(nonce[0], 0);

        // Fill with max value
        nonce = vec![0xFFu8; 12];
        assert!(!increment_nonce(&mut nonce)); // wraps to all zeros
    }

    #[test]
    fn test_aead_algorithm_from_str() {
        assert_eq!(
            AeadAlgorithm::from_str("aes-256-gcm"),
            Ok(AeadAlgorithm::Aes256Gcm)
        );
        #[cfg(feature = "chacha20")]
        assert_eq!(
            AeadAlgorithm::from_str("xchacha20-poly1305"),
            Ok(AeadAlgorithm::XChaCha20Poly1305)
        );
        assert_eq!(AeadAlgorithm::from_str("unknown"), Err(()));
    }

    #[test]
    fn test_key_derivation_deterministic() {
        let token = b"test-token";
        let transcript = b"test-transcript-hash-32bytes!!";
        let (c2s1, s2c1) =
            derive_aead_control_keys(token, AeadAlgorithm::Aes256Gcm, transcript).unwrap();
        let (c2s2, s2c2) =
            derive_aead_control_keys(token, AeadAlgorithm::Aes256Gcm, transcript).unwrap();
        assert_eq!(c2s1, c2s2);
        assert_eq!(s2c1, s2c2);
        assert_ne!(c2s1, s2c1); // different directions should give different keys
    }

    #[test]
    fn test_generate_random() {
        let r1 = generate_random(32).unwrap();
        let r2 = generate_random(32).unwrap();
        assert_eq!(r1.len(), 32);
        assert_eq!(r2.len(), 32);
        assert_ne!(r1, r2); // extremely unlikely to collide
    }

    #[tokio::test]
    async fn test_aead_stream_combined_roundtrip_aes256gcm() {
        test_aead_combined_roundtrip(AeadAlgorithm::Aes256Gcm).await;
    }

    #[cfg(feature = "chacha20")]
    #[tokio::test]
    async fn test_aead_stream_combined_roundtrip_xchacha20() {
        test_aead_combined_roundtrip(AeadAlgorithm::XChaCha20Poly1305).await;
    }

    async fn test_aead_combined_roundtrip(alg: AeadAlgorithm) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let key = generate_random(32).unwrap();
        // Use same key for both directions for test (simulates symmetric key)
        let read_key = key.clone();
        let write_key = key.clone();

        let (client, server) = tokio::io::duplex(65536);

        let mut client_aead =
            AeadStream::new(Box::new(client), alg, &read_key, &write_key).unwrap();

        let write_task = tokio::spawn(async move {
            client_aead
                .write_all(b"hello world this is a test of AEAD")
                .await
                .unwrap();
            client_aead.flush().await.unwrap();
        });

        let mut server_aead =
            AeadStream::new(Box::new(server), alg, &read_key, &write_key).unwrap();
        let mut buf = vec![0u8; 1024];
        let mut total = 0;
        loop {
            let n = server_aead.read(&mut buf[total..]).await.unwrap();
            if n == 0 {
                break;
            }
            total += n;
        }
        assert_eq!(&buf[..total], b"hello world this is a test of AEAD");

        write_task.await.unwrap();
    }

    /// Reproduces the `read_exact` partial-read bug: when the inner stream
    /// delivers a frame across multiple reads with a `Poll::Pending` in
    /// between (normal under network fragmentation), `read_exact` allocates a
    /// fresh buffer each poll and drops the bytes already consumed from the
    /// inner stream. Those bytes are lost from the wire, corrupting the AEAD
    /// frame → decrypt auth failure or length/content mismatch.
    #[tokio::test]
    async fn test_aead_stream_survives_fragmented_pending_reads() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::time::{timeout, Duration};

        let key = generate_random(32).unwrap();

        // --- Produce a real multi-frame AEAD ciphertext stream ---
        // 100KB forces 2 frames since the max payload size is 64KB.
        let plaintext = (0..100_000u32).map(|i| i as u8).collect::<Vec<u8>>();

        let (client, server) = tokio::io::duplex(1 << 20);
        let mut writer =
            AeadStream::new(Box::new(client), AeadAlgorithm::Aes256Gcm, &key, &key).unwrap();

        let plaintext_for_task = plaintext.clone();
        let write_task = tokio::spawn(async move {
            writer.write_all(&plaintext_for_task).await.unwrap();
            writer.flush().await.unwrap();
            writer.shutdown().await.unwrap();
        });

        // Read the raw framed AEAD bytes (stream_nonce + frames) off the
        // server end of the duplex to EOF.
        let mut server = server;
        let mut ciphertext = Vec::new();
        server.read_to_end(&mut ciphertext).await.unwrap();
        write_task.await.unwrap();
        assert!(
            ciphertext.len() > 100_000,
            "expected framed ciphertext larger than plaintext, got {}",
            ciphertext.len()
        );

        // --- Mock reader: tiny 3-byte chunks with a Pending injected between
        // every delivery, guaranteeing partial-then-Pending sequences mid-frame.
        struct ChunkedPendingReader {
            ciphertext: Vec<u8>,
            pos: usize,
            toggle: bool,
        }

        impl ChunkedPendingReader {
            fn new(ciphertext: Vec<u8>) -> Self {
                Self {
                    ciphertext,
                    pos: 0,
                    toggle: false,
                }
            }
        }

        impl AsyncRead for ChunkedPendingReader {
            fn poll_read(
                self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                let this = self.get_mut();
                if this.pos >= this.ciphertext.len() {
                    // EOF: nothing filled.
                    return Poll::Ready(Ok(()));
                }
                this.toggle = !this.toggle;
                if this.toggle {
                    // "Pending turn": deliver no bytes, wake so the runtime
                    // re-polls immediately.
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                // "Deliver turn": hand over a tiny chunk.
                let n = (this.ciphertext.len() - this.pos)
                    .min(3)
                    .min(buf.remaining());
                let start = this.pos;
                buf.put_slice(&this.ciphertext[start..start + n]);
                this.pos += n;
                Poll::Ready(Ok(()))
            }
        }

        impl AsyncWrite for ChunkedPendingReader {
            fn poll_write(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                buf: &[u8],
            ) -> Poll<io::Result<usize>> {
                Poll::Ready(Ok(buf.len()))
            }
            fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
            fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }

        let mut reader = AeadStream::new(
            Box::new(ChunkedPendingReader::new(ciphertext)),
            AeadAlgorithm::Aes256Gcm,
            &key,
            &key,
        )
        .unwrap();

        let got = timeout(Duration::from_secs(10), async move {
            let mut got = Vec::new();
            let mut buf = vec![0u8; 4096];
            loop {
                let n = reader
                    .read(&mut buf[..])
                    .await
                    .expect("AEAD read failed — bug: read_exact lost partial data on Pending");
                if n == 0 {
                    break;
                }
                got.extend_from_slice(&buf[..n]);
            }
            got
        })
        .await
        .expect("timed out — bug: read_exact loses partial data on Pending");

        assert_eq!(
            got.len(),
            100_000,
            "length mismatch: read_exact dropped bytes on Pending"
        );
        assert_eq!(
            got, plaintext,
            "content mismatch: AEAD frame corruption from lost partial reads"
        );
    }
}
