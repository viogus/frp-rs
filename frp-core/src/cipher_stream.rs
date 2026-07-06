//! AES-128-CFB streaming cipher for control connection and bridge encryption.
//!
//! Matches Go frp v0.69.1 `crypto.NewReader` / `crypto.NewWriter` behavior.
//! Each direction exchanges a 16-byte random IV: writer prepends it on first
//! write, reader consumes it on first read. Both directions are independent.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use aes::Aes128;

pub trait AsyncReadWriteUnpin: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncReadWriteUnpin for T {}

/// CFB-128 state matching Go frp's `crypto/cipher` CFB mode.
///
/// In CFB-128 mode, AES encrypts the feedback register to produce a 16-byte
/// keystream block. This keystream is XORed with input bytes. After each byte,
/// the corresponding ciphertext byte is shifted into the feedback register.
/// When all 16 keystream bytes are consumed, the feedback register (now filled
/// with 16 bytes of ciphertext) is re-encrypted to produce the next keystream.
struct CfbState {
    aes: Aes128,
    feedback: [u8; 16],       // feedback register (IV initially, then ciphertext)
    keystream: [u8; 16],      // current 16-byte keystream block
    used: usize,              // how many keystream bytes consumed (0..16)
}

impl CfbState {
    fn new(key: &[u8; 16], iv: &[u8; 16]) -> Self {
        use aes::cipher::{BlockEncrypt, KeyInit};
        let aes = Aes128::new_from_slice(key).expect("AES-128 key must be 16 bytes");
        let mut state = CfbState {
            aes,
            feedback: *iv,
            keystream: [0u8; 16],
            used: 16, // force re-encrypt on first byte
        };
        state.keystream = state.feedback;
        state.aes.encrypt_block((&mut state.keystream).into());
        state.used = 0;
        state
    }

    /// Refill the keystream by encrypting the current feedback register.
    fn refill(&mut self) {
        use aes::cipher::BlockEncrypt;
        self.keystream = self.feedback;
        self.aes.encrypt_block((&mut self.keystream).into());
        self.used = 0;
    }

    fn encrypt(&mut self, data: &mut [u8]) {
        for byte in data.iter_mut() {
            if self.used >= 16 {
                self.refill();
            }
            *byte ^= self.keystream[self.used];
            self.feedback[self.used] = *byte;
            self.used += 1;
        }
    }

    fn decrypt(&mut self, data: &mut [u8]) {
        for byte in data.iter_mut() {
            if self.used >= 16 {
                self.refill();
            }
            let ct = *byte;
            *byte ^= self.keystream[self.used];
            self.feedback[self.used] = ct;
            self.used += 1;
        }
    }
}

/// Streaming AES-128-CFB decrypting reader.
///
/// On first read, consumes a 16-byte IV from the underlying stream (sent by
/// the peer's Writer), then CFB-decrypts subsequent bytes.
/// Matches Go frp v0.69.1 `crypto.NewReader` behavior.
pub struct CipherReader<R: AsyncRead + Unpin> {
    inner: R,
    key: [u8; 16],
    cfb: Option<CfbState>,
    iv_buf: Vec<u8>,
    iv_read: usize,
}

impl<R: AsyncRead + Unpin> CipherReader<R> {
    pub fn new(inner: R, key: [u8; 16]) -> Self {
        Self {
            inner,
            key,
            cfb: None,
            iv_buf: vec![0u8; 16],
            iv_read: 0,
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for CipherReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;

        // First, read the 16-byte IV sent by the peer's Writer.
        if this.iv_read < 16 {
            let needed = 16 - this.iv_read;
            let mut tmp = vec![0u8; needed];
            let mut tmp_buf = ReadBuf::new(&mut tmp);
            match Pin::new(&mut this.inner).poll_read(cx, &mut tmp_buf) {
                Poll::Ready(Ok(())) => {
                    let filled = tmp_buf.filled().len();
                    if filled == 0 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "CipherReader: EOF while reading IV",
                        )));
                    }
                    this.iv_buf[this.iv_read..this.iv_read + filled]
                        .copy_from_slice(&tmp[..filled]);
                    this.iv_read += filled;
                    if this.iv_read < 16 {
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                    // IV complete — initialize CFB state.
                    let mut iv = [0u8; 16];
                    iv.copy_from_slice(&this.iv_buf);
                    this.cfb = Some(CfbState::new(&this.key, &iv));
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        let cfb = this.cfb.as_mut().expect("IV must be read before decrypting");
        let needed = buf.remaining();
        let mut tmp = vec![0u8; needed];
        let mut tmp_buf = ReadBuf::new(&mut tmp);
        match Pin::new(&mut this.inner).poll_read(cx, &mut tmp_buf) {
            Poll::Ready(Ok(())) => {
                let filled = tmp_buf.filled().len();
                if filled > 0 {
                    cfb.decrypt(&mut tmp[..filled]);
                    buf.put_slice(&tmp[..filled]);
                }
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

/// Streaming AES-128-CFB encrypting writer.
///
/// On first write, generates a random 16-byte IV and writes it before the
/// encrypted data. Matches Go frp v0.69.1 `crypto.NewWriter` behavior.
///
/// Partial-write safety: if the underlying stream cannot accept all bytes at
/// once (common with KCP), the first-write buffer is saved and retried on
/// subsequent poll_write calls without re-encrypting.
pub struct CipherWriter<W: AsyncWrite + Unpin> {
    inner: W,
    key: [u8; 16],
    cfb: Option<CfbState>,
    iv_sent: bool,
    /// Buffered first write (IV + encrypted payload). Saved across partial writes.
    first_write_buf: Option<Vec<u8>>,
    /// Bytes already written from first_write_buf.
    first_write_pos: usize,
}

impl<W: AsyncWrite + Unpin> CipherWriter<W> {
    pub fn new(inner: W, key: [u8; 16]) -> Self {
        Self { inner, key, cfb: None, iv_sent: false, first_write_buf: None, first_write_pos: 0 }
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for CipherWriter<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;

        // Flush pending first-write buffer (partial write retry).
        if let Some(ref pending) = this.first_write_buf {
            let remaining = &pending[this.first_write_pos..];
            match Pin::new(&mut this.inner).poll_write(cx, remaining) {
                Poll::Ready(Ok(n)) => {
                    this.first_write_pos += n;
                    if this.first_write_pos >= pending.len() {
                        this.first_write_buf = None;
                        this.first_write_pos = 0;
                    } else {
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        // On first write, generate random IV and prepend it.
        // Matches Go frp v0.69.1 `crypto.NewWriter` behavior.
        if !this.iv_sent {
            this.iv_sent = true;
            let mut iv = [0u8; 16];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut iv);
            this.cfb = Some(CfbState::new(&this.key, &iv));
            let mut encrypted = buf.to_vec();
            this.cfb.as_mut().unwrap().encrypt(&mut encrypted);
            let mut output = Vec::with_capacity(16 + encrypted.len());
            output.extend_from_slice(&iv);
            output.extend_from_slice(&encrypted);
            match Pin::new(&mut this.inner).poll_write(cx, &output) {
                Poll::Ready(Ok(n)) if n >= output.len() => {
                    return Poll::Ready(Ok(buf.len()));
                }
                Poll::Ready(Ok(n)) => {
                    this.first_write_buf = Some(output);
                    this.first_write_pos = n;
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {
                    this.first_write_buf = Some(output);
                    this.first_write_pos = 0;
                    return Poll::Pending;
                }
            }
        }

        let cfb = this.cfb.as_mut().expect("IV must be sent before encrypting");
        let mut encrypted = buf.to_vec();
        cfb.encrypt(&mut encrypted);
        Pin::new(&mut this.inner).poll_write(cx, &encrypted)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Combined AES-128-CFB stream (reader + writer in one).
///
/// Each direction exchanges its own 16-byte random IV.
/// Writer prepends IV on first write; reader consumes IV on first read.
/// Matches Go frp v0.69.1 `crypto.NewCryptoReadWriter` behavior.
pub struct CipherStream<S: AsyncRead + AsyncWrite + Unpin> {
    inner: S,
    read_key: [u8; 16],
    write_key: [u8; 16],
    read_cfb: Option<CfbState>,
    write_cfb: Option<CfbState>,
    iv_read: usize,
    iv_buf: Vec<u8>,
    iv_sent: bool,
    write_iv: [u8; 16],
    /// Buffered first write for partial-write retry safety.
    first_write_buf: Option<Vec<u8>>,
    first_write_pos: usize,
}

impl<S: AsyncRead + AsyncWrite + Unpin> CipherStream<S> {
    pub fn new(inner: S, key: [u8; 16]) -> Self {
        let mut write_iv = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut write_iv);
        Self {
            inner,
            read_key: key,
            write_key: key,
            read_cfb: None,
            write_cfb: None,
            iv_read: 0,
            iv_buf: vec![0u8; 16],
            iv_sent: false,
            write_iv,
            first_write_buf: None,
            first_write_pos: 0,
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for CipherStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;

        // First, read the 16-byte IV sent by the peer's Writer.
        if this.iv_read < 16 {
            let needed = 16 - this.iv_read;
            tracing::debug!(iv_read = this.iv_read, needed, "CipherStream: reading IV");
            let mut tmp = vec![0u8; needed];
            let mut tmp_buf = ReadBuf::new(&mut tmp);
            match Pin::new(&mut this.inner).poll_read(cx, &mut tmp_buf) {
                Poll::Ready(Ok(())) => {
                    let filled = tmp_buf.filled().len();
                    tracing::debug!(filled, iv_read = this.iv_read, "CipherStream: IV read chunk");
                    if filled == 0 {
                        tracing::warn!("CipherStream: EOF while reading IV (got {} of 16)", this.iv_read);
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "CipherStream: EOF while reading IV",
                        )));
                    }
                    this.iv_buf[this.iv_read..this.iv_read + filled]
                        .copy_from_slice(&tmp[..filled]);
                    this.iv_read += filled;
                    if this.iv_read < 16 {
                        tracing::debug!(iv_read = this.iv_read, "CipherStream: IV incomplete, waiting");
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                    let mut iv = [0u8; 16];
                    iv.copy_from_slice(&this.iv_buf);
                    this.read_cfb = Some(CfbState::new(&this.read_key, &iv));
                    tracing::debug!(iv_hex = %hex::encode(&iv), "CipherStream: IV read complete");
                }
                Poll::Ready(Err(e)) => {
                    tracing::warn!(error = %e, "CipherStream: error reading IV");
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => return Poll::Pending,
            }
        }

        let cfb = this.read_cfb.as_mut().expect("IV must be read before decrypting");
        let needed = buf.remaining();
        let mut tmp = vec![0u8; needed];
        let mut tmp_buf = ReadBuf::new(&mut tmp);
        match Pin::new(&mut this.inner).poll_read(cx, &mut tmp_buf) {
            Poll::Ready(Ok(())) => {
                let filled = tmp_buf.filled().len();
                if filled > 0 {
                    cfb.decrypt(&mut tmp[..filled]);
                    buf.put_slice(&tmp[..filled]);
                }
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for CipherStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;

        // Flush pending first-write buffer (partial write retry).
        if let Some(ref pending) = this.first_write_buf {
            let remaining = &pending[this.first_write_pos..];
            match Pin::new(&mut this.inner).poll_write(cx, remaining) {
                Poll::Ready(Ok(n)) => {
                    this.first_write_pos += n;
                    if this.first_write_pos >= pending.len() {
                        this.first_write_buf = None;
                        this.first_write_pos = 0;
                    } else {
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        // On first write, prepend the random IV generated in new().
        if !this.iv_sent {
            this.iv_sent = true;
            this.write_cfb = Some(CfbState::new(&this.write_key, &this.write_iv));
            tracing::debug!(iv_hex = %hex::encode(&this.write_iv), data_len = buf.len(), "CipherStream: first write, sending IV + encrypted data");
            let mut encrypted = buf.to_vec();
            this.write_cfb.as_mut().unwrap().encrypt(&mut encrypted);
            let mut output = Vec::with_capacity(16 + encrypted.len());
            output.extend_from_slice(&this.write_iv);
            output.extend_from_slice(&encrypted);
            match Pin::new(&mut this.inner).poll_write(cx, &output) {
                Poll::Ready(Ok(n)) if n >= output.len() => {
                    return Poll::Ready(Ok(buf.len()));
                }
                Poll::Ready(Ok(n)) => {
                    this.first_write_buf = Some(output);
                    this.first_write_pos = n;
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {
                    this.first_write_buf = Some(output);
                    this.first_write_pos = 0;
                    return Poll::Pending;
                }
            }
        }

        let cfb = this.write_cfb.as_mut().expect("IV must be sent before encrypting");
        let mut encrypted = buf.to_vec();
        cfb.encrypt(&mut encrypted);
        Pin::new(&mut this.inner).poll_write(cx, &encrypted)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
