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
use chacha20poly1305::{KeyInit, XChaCha20Poly1305};
#[cfg(feature = "chacha20")]
use chacha20poly1305::aead::Aead;
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
            Self::Aes256Gcm => 12,   // AES-256-GCM standard nonce
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
            return Err(format!("AEAD key must be {} bytes, got {}", AEAD_KEY_SIZE, key.len()));
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

    fn encrypt(&self, nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
        match self {
            Self::Aes256Gcm(key) => {
                let nonce = Nonce::try_assume_unique_for_key(nonce)
                    .map_err(|e| format!("aes-gcm nonce: {e}"))?;
                let aad = Aad::from(aad);
                let mut in_out = plaintext.to_vec();
                // Tag is appended by seal_in_place
                key.seal_in_place_append_tag(nonce, aad, &mut in_out)
                    .map_err(|e| format!("aes-gcm encrypt: {e}"))?;
                Ok(in_out)
            }
            #[cfg(feature = "chacha20")]
            Self::XChaCha20Poly1305(c) => {
                let nonce = chacha20poly1305::XNonce::from_slice(nonce);
                let payload = chacha20poly1305::aead::Payload { msg: plaintext, aad };
                c.encrypt(nonce, payload)
                    .map_err(|e| format!("xchacha20 encrypt: {e}"))
            }
        }
    }

    fn decrypt(&self, nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
        match self {
            Self::Aes256Gcm(key) => {
                let nonce = Nonce::try_assume_unique_for_key(nonce)
                    .map_err(|e| format!("aes-gcm nonce: {e}"))?;
                let aad = Aad::from(aad);
                let mut in_out = ciphertext.to_vec();
                let plaintext = key.open_in_place(nonce, aad, &mut in_out)
                    .map_err(|e| format!("aes-gcm decrypt: {e}"))?;
                Ok(plaintext.to_vec())
            }
            #[cfg(feature = "chacha20")]
            Self::XChaCha20Poly1305(c) => {
                let nonce = chacha20poly1305::XNonce::from_slice(nonce);
                let payload = chacha20poly1305::aead::Payload { msg: ciphertext, aad };
                c.decrypt(nonce, payload)
                    .map_err(|e| format!("xchacha20 decrypt: {e}"))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// AEAD Stream Writer
// ---------------------------------------------------------------------------

/// Writes plaintext as framed AEAD records.
///
/// First write sends stream nonce (random, cleartext). Each subsequent write
/// produces one or more frames: `[4B ciphertext_len][AEAD ciphertext+tag]`.
/// AAD = stream_nonce + 4-byte frame header. Nonce increments per frame.
pub struct AeadStreamWriter<W: AsyncWrite + Unpin> {
    inner: W,
    cipher: AeadCipher,
    algorithm: AeadAlgorithm,
    max_payload_size: usize,
    max_frame_count: Option<u64>,
    frame_count: u64,
    stream_nonce: Vec<u8>,
    nonce: Vec<u8>,
    header_sent: bool,
    write_err: Option<io::Error>,
}

impl<W: AsyncWrite + Unpin> AeadStreamWriter<W> {
    pub fn new(inner: W, algorithm: AeadAlgorithm, key: &[u8]) -> Result<Self, String> {
        let cipher = AeadCipher::new(algorithm, key)?;
        let nonce_size = algorithm.nonce_size();
        let mut nonce = vec![0u8; nonce_size];
        rand::rngs::OsRng.fill_bytes(&mut nonce);

        Ok(Self {
            inner,
            cipher,
            algorithm,
            max_payload_size: DEFAULT_MAX_PAYLOAD_SIZE,
            max_frame_count: algorithm.max_frame_count(),
            frame_count: 0,
            stream_nonce: nonce.clone(),
            nonce,
            header_sent: false,
            write_err: None,
        })
    }

    fn write_frame(&mut self, plaintext: &[u8], cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(ref max) = self.max_frame_count {
            if self.frame_count >= *max {
                let e = io::Error::other(format!("AEAD stream frame count limit {} exceeded", max));
                self.write_err = Some(e);
                return Poll::Ready(Err(io::Error::other("frame count exceeded")));
            }
        }

        // Send stream nonce if first frame
        if !self.header_sent {
            match self.write_all(&self.nonce.clone(), cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
            self.header_sent = true;
        }

        let overhead = self.algorithm.overhead();
        let ciphertext_len = (plaintext.len() + overhead) as u32;
        let mut header = [0u8; AEAD_FRAME_HEADER_SIZE];
        header.copy_from_slice(&ciphertext_len.to_be_bytes());

        // AAD = stream_nonce || header
        let mut aad = Vec::with_capacity(self.stream_nonce.len() + AEAD_FRAME_HEADER_SIZE);
        aad.extend_from_slice(&self.stream_nonce);
        aad.extend_from_slice(&header);

        let sealed = match self.cipher.encrypt(&self.nonce, plaintext, &aad) {
            Ok(s) => s,
            Err(e) => {
                let io_err = io::Error::other(e);
                self.write_err = Some(io_err);
                return Poll::Ready(Err(io::Error::other("encrypt failed")));
            }
        };

        // Increment nonce (big-endian)
        if !increment_nonce(&mut self.nonce) {
            let e = io::Error::other("AEAD nonce exhausted");
            self.write_err = Some(e);
            return Poll::Ready(Err(io::Error::other("nonce exhausted")));
        }
        self.frame_count += 1;

        // Write frame: [4B header][ciphertext]
        let mut out = Vec::with_capacity(AEAD_FRAME_HEADER_SIZE + sealed.len());
        out.extend_from_slice(&header);
        out.extend_from_slice(&sealed);

        self.write_all(&out, cx)
    }

    fn write_all(&mut self, data: &[u8], cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut pos = 0;
        while pos < data.len() {
            let pin = Pin::new(&mut self.inner);
            match pin.poll_write(cx, &data[pos..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::WriteZero, "write zero")));
                }
                Poll::Ready(Ok(n)) => pos += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {
                    // We've made partial progress; caller should retry
                    if pos > 0 {
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                    return Poll::Pending;
                }
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for AeadStreamWriter<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.write_err.is_some() {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "previous write error")));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        // Write one frame per call (caller will call again for remaining data).
        // But we need to handle up to max_payload_size bytes.
        let chunk_size = buf.len().min(self.max_payload_size);
        match self.write_frame(&buf[..chunk_size], cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(chunk_size)),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

// ---------------------------------------------------------------------------
// AEAD Stream Reader
// ---------------------------------------------------------------------------

/// Reads and decrypts the framed AEAD stream.
///
/// First read consumes the stream nonce. Each subsequent frame is authenticated
/// with stream_nonce+header as AAD. EOF at frame boundary is treated as clean EOF.
pub struct AeadStreamReader<R: AsyncRead + Unpin> {
    inner: R,
    cipher: AeadCipher,
    algorithm: AeadAlgorithm,
    max_payload_size: usize,
    max_frame_count: Option<u64>,
    frame_count: u64,
    stream_nonce: Option<Vec<u8>>,
    nonce: Vec<u8>,
    header_read: bool,
    buf: Vec<u8>,
    buf_pos: usize,
    read_err: Option<io::Error>,
}

impl<R: AsyncRead + Unpin> AeadStreamReader<R> {
    pub fn new(inner: R, algorithm: AeadAlgorithm, key: &[u8]) -> Result<Self, String> {
        let cipher = AeadCipher::new(algorithm, key)?;
        Ok(Self {
            inner,
            cipher,
            algorithm,
            max_payload_size: DEFAULT_MAX_PAYLOAD_SIZE,
            max_frame_count: algorithm.max_frame_count(),
            frame_count: 0,
            stream_nonce: None,
            nonce: vec![0u8; algorithm.nonce_size()],
            header_read: false,
            buf: Vec::new(),
            buf_pos: 0,
            read_err: None,
        })
    }

    /// Returns `Ok(true)` when a frame was decoded, `Ok(false)` on clean EOF.
    fn read_frame(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        // Read stream nonce on first frame
        if !self.header_read {
            match self.read_exact(self.nonce.len(), cx) {
                Poll::Ready(Ok(data)) => {
                    self.nonce.copy_from_slice(&data);
                    self.stream_nonce = Some(data.to_vec());
                    self.header_read = true;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        // Read 4-byte header (ciphertext length). EOF here = clean end of stream.
        let header = match self.read_exact(AEAD_FRAME_HEADER_SIZE, cx) {
            Poll::Ready(Ok(data)) => {
                let mut h = [0u8; AEAD_FRAME_HEADER_SIZE];
                h.copy_from_slice(&data);
                h
            }
            Poll::Ready(Err(ref e)) if e.kind() == io::ErrorKind::UnexpectedEof => {
                return Poll::Ready(Ok(false)); // clean EOF
            }
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        };

        if let Some(ref max) = self.max_frame_count {
            if self.frame_count >= *max {
                return Poll::Ready(Err(io::Error::other("AEAD stream frame count limit exceeded")));
            }
        }

        let ciphertext_len = u32::from_be_bytes(header) as usize;
        let overhead = self.algorithm.overhead();
        if ciphertext_len < overhead {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData,
                format!("AEAD ciphertext length {ciphertext_len} < overhead {overhead}"))));
        }
        let max_ciphertext = self.max_payload_size + overhead;
        if ciphertext_len > max_ciphertext {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData,
                format!("AEAD ciphertext length {ciphertext_len} exceeds limit {max_ciphertext}"))));
        }

        let ciphertext = match self.read_exact(ciphertext_len, cx) {
            Poll::Ready(Ok(data)) => data,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        };

        // AAD = stream_nonce || header
        let stream_nonce = self.stream_nonce.as_ref()
            .expect("stream_nonce must be set after header read");
        let mut aad = Vec::with_capacity(stream_nonce.len() + AEAD_FRAME_HEADER_SIZE);
        aad.extend_from_slice(stream_nonce);
        aad.extend_from_slice(&header);

        let plaintext = match self.cipher.decrypt(&self.nonce, &ciphertext, &aad) {
            Ok(p) => p,
            Err(e) => {
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData,
                    format!("AEAD decrypt: {e}"))));
            }
        };

        if !increment_nonce(&mut self.nonce) {
            return Poll::Ready(Err(io::Error::other("AEAD nonce exhausted")));
        }
        self.frame_count += 1;

        self.buf = plaintext;
        self.buf_pos = 0;
        Poll::Ready(Ok(true))
    }

    fn read_exact(&mut self, len: usize, cx: &mut Context<'_>) -> Poll<io::Result<Vec<u8>>> {
        let mut data = vec![0u8; len];
        let mut buf = ReadBuf::new(&mut data);
        loop {
            let pin = Pin::new(&mut self.inner);
            match pin.poll_read(cx, &mut buf) {
                Poll::Ready(Ok(())) => {
                    if buf.filled().len() < len {
                        // Need more data; continue
                        continue;
                    }
                    // Check if we got EOF
                    if buf.filled().is_empty() {
                        return Poll::Ready(Err(io::Error::new(io::ErrorKind::UnexpectedEof,
                            "AEAD stream: unexpected EOF")));
                    }
                    return Poll::Ready(Ok(data));
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for AeadStreamReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.read_err.is_some() {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "previous read error")));
        }
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        // Serve from buffered plaintext
        if self.buf_pos < self.buf.len() {
            let available = self.buf.len() - self.buf_pos;
            let to_copy = available.min(buf.remaining());
            buf.put_slice(&self.buf[self.buf_pos..self.buf_pos + to_copy]);
            self.buf_pos += to_copy;
            if self.buf_pos >= self.buf.len() {
                self.buf.clear();
                self.buf_pos = 0;
            }
            return Poll::Ready(Ok(()));
        }

        // Read next frame
        match self.read_frame(cx) {
            Poll::Ready(Ok(true)) => {
                // Now serve from the new buffer
                let available = self.buf.len() - self.buf_pos;
                let to_copy = available.min(buf.remaining());
                buf.put_slice(&self.buf[self.buf_pos..self.buf_pos + to_copy]);
                self.buf_pos += to_copy;
                if self.buf_pos >= self.buf.len() {
                    self.buf.clear();
                    self.buf_pos = 0;
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Ok(false)) => {
                // Clean EOF
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => {
                self.read_err = Some(io::Error::new(e.kind(), e.to_string()));
                Poll::Ready(Err(e))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

// ---------------------------------------------------------------------------
// Combined AeadStream (AsyncRead + AsyncWrite) — wraps Box<dyn AsyncReadWriteUnpin>
// ---------------------------------------------------------------------------

/// Trait alias for AsyncRead + AsyncWrite + Unpin + Send.
pub trait AsyncReadWriteUnpin: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncReadWriteUnpin for T {}

/// Combined AEAD stream wrapping a bidirectional byte transport.
///
/// Internally manages independent read and write states, each with their own
/// nonce, cipher, and buffering. Matches Go frp's pattern of wrapping an
/// `io.ReadWriter` with separate AEAD reader/writer halves.
pub struct AeadStream {
    inner: Box<dyn AsyncReadWriteUnpin>,
    algorithm: AeadAlgorithm,
    // Read state
    read_cipher: AeadCipher,
    read_nonce: Vec<u8>,
    read_stream_nonce: Option<Vec<u8>>,
    read_header_read: bool,
    read_frame_count: u64,
    read_max_frame_count: Option<u64>,
    read_buf: Vec<u8>,
    read_buf_pos: usize,
    read_err: Option<io::Error>,
    // Write state
    write_cipher: AeadCipher,
    write_nonce: Vec<u8>,
    write_stream_nonce: Vec<u8>,
    write_header_sent: bool,
    write_frame_count: u64,
    write_max_frame_count: Option<u64>,
    write_pending: Vec<u8>,
    write_pending_pos: usize,
    write_err: Option<io::Error>,
}

impl AeadStream {
    /// Create a new AEAD stream wrapping `inner`.
    ///
    /// `read_key` and `write_key` are the derived directional AEAD keys
    /// (32 bytes each). `algorithm` selects AES-256-GCM or XChaCha20-Poly1305.
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

        Ok(Self {
            inner,
            algorithm,
            read_cipher,
            read_nonce: vec![0u8; nonce_size],
            read_stream_nonce: None,
            read_header_read: false,
            read_frame_count: 0,
            read_max_frame_count: algorithm.max_frame_count(),
            read_buf: Vec::new(),
            read_buf_pos: 0,
            read_err: None,
            write_cipher,
            write_nonce: write_nonce.clone(),
            write_stream_nonce: write_nonce,
            write_header_sent: false,
            write_frame_count: 0,
            write_max_frame_count: algorithm.max_frame_count(),
            write_pending: Vec::new(),
            write_pending_pos: 0,
            write_err: None,
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
        if self.read_err.is_some() {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "previous read error")));
        }
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        // Serve from buffered plaintext
        if self.read_buf_pos < self.read_buf.len() {
            let available = self.read_buf.len() - self.read_buf_pos;
            let to_copy = available.min(buf.remaining());
            buf.put_slice(&self.read_buf[self.read_buf_pos..self.read_buf_pos + to_copy]);
            self.read_buf_pos += to_copy;
            if self.read_buf_pos >= self.read_buf.len() {
                self.read_buf.clear();
                self.read_buf_pos = 0;
            }
            return Poll::Ready(Ok(()));
        }

        // Read next frame
        let this = &mut *self;
        match this.poll_read_frame(cx) {
            Poll::Ready(Ok(true)) => {
                // Serve from new buffer
                let available = this.read_buf.len() - this.read_buf_pos;
                let to_copy = available.min(buf.remaining());
                buf.put_slice(&this.read_buf[this.read_buf_pos..this.read_buf_pos + to_copy]);
                this.read_buf_pos += to_copy;
                if this.read_buf_pos >= this.read_buf.len() {
                    this.read_buf.clear();
                    this.read_buf_pos = 0;
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Ok(false)) => {
                // Clean EOF at frame boundary
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => {
                this.read_err = Some(io::Error::new(e.kind(), e.to_string()));
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
        tracing::debug!(read_header_read = %self.read_header_read, read_frame_count = %self.read_frame_count, "[AEAD-READ] poll_read_frame called, read_header_read={}, read_frame_count={}",
            self.read_header_read, self.read_frame_count);
        // Read stream nonce on first frame
        if !self.read_header_read {
            match self.read_exact(self.read_nonce.len(), cx) {
                Poll::Ready(Ok(data)) => {
                    self.read_nonce.copy_from_slice(&data);
                    self.read_stream_nonce = Some(data.to_vec());
                    self.read_header_read = true;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        // Read 4-byte header. EOF here = clean end of stream.
        let header = match self.read_exact(AEAD_FRAME_HEADER_SIZE, cx) {
            Poll::Ready(Ok(data)) => {
                let mut h = [0u8; AEAD_FRAME_HEADER_SIZE];
                h.copy_from_slice(&data);
                h
            }
            Poll::Ready(Err(ref e)) if e.kind() == io::ErrorKind::UnexpectedEof => {
                return Poll::Ready(Ok(false)); // clean EOF
            }
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        };

        if let Some(ref max) = self.read_max_frame_count {
            if self.read_frame_count >= *max {
                return Poll::Ready(Err(io::Error::other("AEAD read frame count limit exceeded")));
            }
        }

        let ciphertext_len = u32::from_be_bytes(header) as usize;
        let overhead = self.algorithm.overhead();
        if ciphertext_len < overhead {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData,
                format!("AEAD ciphertext length {ciphertext_len} < overhead {overhead}"))));
        }
        let max_ciphertext = DEFAULT_MAX_PAYLOAD_SIZE + overhead;
        if ciphertext_len > max_ciphertext {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData,
                format!("AEAD ciphertext length {ciphertext_len} exceeds limit {max_ciphertext}"))));
        }

        let ciphertext = match self.read_exact(ciphertext_len, cx) {
            Poll::Ready(Ok(data)) => data,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        };

        let stream_nonce = self.read_stream_nonce.as_ref()
            .expect("stream_nonce must be set");
        let mut aad = Vec::with_capacity(stream_nonce.len() + AEAD_FRAME_HEADER_SIZE);
        aad.extend_from_slice(stream_nonce);
        aad.extend_from_slice(&header);

        let plaintext = match self.read_cipher.decrypt(&self.read_nonce, &ciphertext, &aad) {
            Ok(p) => {
                tracing::debug!(frame = %self.read_frame_count, plaintext_len = %p.len(), "[AEAD-READ] frame={} decrypt OK, plaintext_len={}", self.read_frame_count, p.len());
                p
            }
            Err(e) => {
                #[cfg(debug_assertions)]
                tracing::warn!(frame = %self.read_frame_count, error = %e, nonce = %hex::encode(&self.read_nonce), stream_nonce = %hex::encode(stream_nonce), "[AEAD-READ] frame={} decrypt FAILED: {} (nonce={}, stream_nonce={})",
                    self.read_frame_count, e,
                    hex::encode(&self.read_nonce),
                    hex::encode(stream_nonce));
                #[cfg(not(debug_assertions))]
                tracing::warn!(frame = %self.read_frame_count, error = %e, "[AEAD-READ] frame={} decrypt FAILED: {}", self.read_frame_count, e);
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData,
                    format!("AEAD decrypt: {e}"))));
            }
        };

        if !increment_nonce(&mut self.read_nonce) {
            return Poll::Ready(Err(io::Error::other("AEAD read nonce exhausted")));
        }
        self.read_frame_count += 1;

        self.read_buf = plaintext;
        self.read_buf_pos = 0;
        Poll::Ready(Ok(true))
    }

    fn read_exact(&mut self, len: usize, cx: &mut Context<'_>) -> Poll<io::Result<Vec<u8>>> {
        let mut data = vec![0u8; len];
        let mut buf = ReadBuf::new(&mut data);
        while buf.filled().len() < len {
            let prev = buf.filled().len();
            let pin = Pin::new(&mut *self.inner);
            match pin.poll_read(cx, &mut buf) {
                Poll::Ready(Ok(())) => {
                    if buf.filled().len() == prev {
                        // EOF: no more bytes available
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            format!("AEAD stream: unexpected EOF (need {len}, got {prev})"),
                        )));
                    }
                    if buf.filled().len() == buf.capacity() {
                        return Poll::Ready(Ok(data));
                    }
                    // Need more bytes — loop
                    continue;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
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
        if self.write_err.is_some() {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "previous write error")));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let this = &mut *self;

        // If we have pending data to flush, try flushing first
        if this.write_pending_pos < this.write_pending.len() {
            match this.poll_flush_pending(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        // Build a new frame
        if let Some(ref max) = this.write_max_frame_count {
            if this.write_frame_count >= *max {
                let e = io::Error::other("AEAD write frame count limit exceeded");
                this.write_err = Some(e);
                return Poll::Ready(Err(io::Error::other("frame count exceeded")));
            }
        }

        let chunk_size = buf.len().min(DEFAULT_MAX_PAYLOAD_SIZE);
        let plaintext = &buf[..chunk_size];

        // Send stream nonce first if needed
        if !this.write_header_sent {
            #[cfg(debug_assertions)]
            tracing::debug!(nonce = %hex::encode(&this.write_nonce), "[AEAD-WRITE] first write: nonce={}", hex::encode(&this.write_nonce));
            #[cfg(not(debug_assertions))]
            tracing::debug!("[AEAD-WRITE] first write");
            // Queue the nonce write
            let mut pending = this.write_stream_nonce.clone();
            let overhead = this.algorithm.overhead();
            let ciphertext_len = (plaintext.len() + overhead) as u32;
            let mut header = [0u8; AEAD_FRAME_HEADER_SIZE];
            header.copy_from_slice(&ciphertext_len.to_be_bytes());

            let mut aad = Vec::with_capacity(this.write_stream_nonce.len() + AEAD_FRAME_HEADER_SIZE);
            aad.extend_from_slice(&this.write_stream_nonce);
            aad.extend_from_slice(&header);

            let sealed = match this.write_cipher.encrypt(&this.write_nonce, plaintext, &aad) {
                Ok(s) => s,
                Err(e) => {
                    let io_err = io::Error::other(e);
                    this.write_err = Some(io_err);
                    return Poll::Ready(Err(io::Error::other("encrypt failed")));
                }
            };

            pending.extend_from_slice(&header);
            pending.extend_from_slice(&sealed);

            if !increment_nonce(&mut this.write_nonce) {
                return Poll::Ready(Err(io::Error::other("AEAD write nonce exhausted")));
            }
            this.write_frame_count += 1;
            this.write_header_sent = true;
            tracing::debug!(frame = %this.write_frame_count, pending_len = %this.write_pending.len(), "[AEAD-WRITE] frame={} encrypted, pending_len={}", this.write_frame_count, this.write_pending.len());

            this.write_pending = pending;
            this.write_pending_pos = 0;
        } else {
            let overhead = this.algorithm.overhead();
            let ciphertext_len = (plaintext.len() + overhead) as u32;
            let mut header = [0u8; AEAD_FRAME_HEADER_SIZE];
            header.copy_from_slice(&ciphertext_len.to_be_bytes());

            let mut aad = Vec::with_capacity(this.write_stream_nonce.len() + AEAD_FRAME_HEADER_SIZE);
            aad.extend_from_slice(&this.write_stream_nonce);
            aad.extend_from_slice(&header);

            let sealed = match this.write_cipher.encrypt(&this.write_nonce, plaintext, &aad) {
                Ok(s) => s,
                Err(e) => {
                    let io_err = io::Error::other(e);
                    this.write_err = Some(io_err);
                    return Poll::Ready(Err(io::Error::other("encrypt failed")));
                }
            };

            if !increment_nonce(&mut this.write_nonce) {
                return Poll::Ready(Err(io::Error::other("AEAD write nonce exhausted")));
            }
            this.write_frame_count += 1;

            let mut pending = Vec::with_capacity(AEAD_FRAME_HEADER_SIZE + sealed.len());
            pending.extend_from_slice(&header);
            pending.extend_from_slice(&sealed);
            this.write_pending = pending;
            this.write_pending_pos = 0;
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
        while self.write_pending_pos < self.write_pending.len() {
            let pin = Pin::new(&mut *self.inner);
            match pin.poll_write(cx, &self.write_pending[self.write_pending_pos..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::WriteZero, "write zero")));
                }
                Poll::Ready(Ok(n)) => {
                    self.write_pending_pos += n;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.write_pending.clear();
        self.write_pending_pos = 0;
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
    let client_to_server = derive_aead_control_key(token, algorithm, transcript_hash, "client-to-server")?;
    let server_to_client = derive_aead_control_key(token, algorithm, transcript_hash, "server-to-client")?;
    Ok((client_to_server, server_to_client))
}

fn derive_aead_control_key(
    token: &[u8],
    algorithm: AeadAlgorithm,
    transcript_hash: &[u8],
    direction: &str,
) -> Result<Vec<u8>, String> {
    let info = format!("frp wire v2 control aead {} {}", algorithm.as_str(), direction);
    let salt = Salt::new(HKDF_SHA256, transcript_hash);
    let prk = salt.extract(token);
    let mut okm = vec![0u8; AEAD_KEY_SIZE];
    let info_refs = [info.as_bytes()];
    let okm_result = prk.expand(&info_refs, HKDF_SHA256)
        .map_err(|e| format!("HKDF expand: {e}"))?;
    okm_result.fill(&mut okm)
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
        assert_eq!(AeadAlgorithm::from_str("aes-256-gcm"), Ok(AeadAlgorithm::Aes256Gcm));
        #[cfg(feature = "chacha20")]
        assert_eq!(AeadAlgorithm::from_str("xchacha20-poly1305"), Ok(AeadAlgorithm::XChaCha20Poly1305));
        assert_eq!(AeadAlgorithm::from_str("unknown"), Err(()));
    }

    #[test]
    fn test_key_derivation_deterministic() {
        let token = b"test-token";
        let transcript = b"test-transcript-hash-32bytes!!";
        let (c2s1, s2c1) = derive_aead_control_keys(
            token, AeadAlgorithm::Aes256Gcm, transcript
        ).unwrap();
        let (c2s2, s2c2) = derive_aead_control_keys(
            token, AeadAlgorithm::Aes256Gcm, transcript
        ).unwrap();
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

        let mut client_aead = AeadStream::new(Box::new(client), alg, &read_key, &write_key).unwrap();

        let write_task = tokio::spawn(async move {
            client_aead.write_all(b"hello world this is a test of AEAD").await.unwrap();
            client_aead.flush().await.unwrap();
        });

        let mut server_aead = AeadStream::new(Box::new(server), alg, &read_key, &write_key).unwrap();
        let mut buf = vec![0u8; 1024];
        let mut total = 0;
        loop {
            let n = server_aead.read(&mut buf[total..]).await.unwrap();
            if n == 0 { break; }
            total += n;
        }
        assert_eq!(&buf[..total], b"hello world this is a test of AEAD");

        write_task.await.unwrap();
    }
}
