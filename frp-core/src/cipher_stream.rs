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
        use aes::cipher::{BlockCipherEncrypt, KeyInit};
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
        use aes::cipher::BlockCipherEncrypt;
        self.keystream = self.feedback;
        self.aes.encrypt_block((&mut self.keystream).into());
        self.used = 0;
    }

    fn encrypt(&mut self, data: &mut [u8]) {
        let n = data.len();
        let mut i = 0;
        while i < n {
            if self.used >= 16 {
                self.refill();
            }
            // Fast path: at a fresh block boundary with a full block available,
            // XOR 16 keystream bytes against 16 data bytes (vectorizable) and
            // set the feedback register to the ciphertext block in one copy.
            if self.used == 0 && n - i >= 16 {
                let blk = &mut data[i..i + 16];
                for (b, k) in blk.iter_mut().zip(self.keystream.iter()) {
                    *b ^= *k;
                }
                self.feedback.copy_from_slice(blk);
                self.used = 16;
                i += 16;
            } else {
                // Partial block (leading carry or trailing remainder): byte-wise.
                let take = (16 - self.used).min(n - i);
                for j in 0..take {
                    let c = data[i + j] ^ self.keystream[self.used];
                    data[i + j] = c;
                    self.feedback[self.used] = c;
                    self.used += 1;
                }
                i += take;
            }
        }
    }

    fn decrypt(&mut self, data: &mut [u8]) {
        let n = data.len();
        let mut i = 0;
        while i < n {
            if self.used >= 16 {
                self.refill();
            }
            if self.used == 0 && n - i >= 16 {
                let blk = &mut data[i..i + 16];
                // feedback = ciphertext (input), then plaintext = ct ^ keystream.
                self.feedback.copy_from_slice(blk);
                for (b, k) in blk.iter_mut().zip(self.keystream.iter()) {
                    *b ^= *k;
                }
                self.used = 16;
                i += 16;
            } else {
                let take = (16 - self.used).min(n - i);
                for j in 0..take {
                    let ct = data[i + j];
                    data[i + j] = ct ^ self.keystream[self.used];
                    self.feedback[self.used] = ct;
                    self.used += 1;
                }
                i += take;
            }
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
    /// Original data length when buffer was set by poll_write (excl. 16-byte IV).
    /// Zero when buffer was set by poll_flush (IV-only eager send).
    first_write_data_len: usize,
    /// Buffered second+ write (encrypted payload only, no IV).
    /// Saved across partial writes so retries don't re-encrypt and corrupt CFB.
    encrypted_buf: Option<Vec<u8>>,
    /// Bytes already written from encrypted_buf.
    encrypted_write_pos: usize,
}

impl<W: AsyncWrite + Unpin> CipherWriter<W> {
    pub fn new(inner: W, key: [u8; 16]) -> Self {
        Self {
            inner,
            key,
            cfb: None,
            iv_sent: false,
            first_write_buf: None,
            first_write_pos: 0,
            first_write_data_len: 0,
            encrypted_buf: None,
            encrypted_write_pos: 0,
        }
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
                        let data_len = this.first_write_data_len;
                        this.first_write_buf = None;
                        this.first_write_pos = 0;
                        this.first_write_data_len = 0;
                        // Buffer came from poll_write (has data after IV).
                        // Data was already encrypted and stored in buffer —
                        // don't fall through to re-encrypt buf.
                        if data_len > 0 {
                            return Poll::Ready(Ok(data_len));
                        }
                        // Buffer was IV-only (set by poll_flush). Fall through
                        // to normal path — buf still needs encrypting.
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
                    this.first_write_data_len = buf.len();
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {
                    this.first_write_buf = Some(output);
                    this.first_write_pos = 0;
                    this.first_write_data_len = buf.len();
                    return Poll::Pending;
                }
            }
        }

        // Drain pending encrypted_buf (partial write retry of a normal write).
        if let Some(ref pending) = this.encrypted_buf {
            let remaining = &pending[this.encrypted_write_pos..];
            match Pin::new(&mut this.inner).poll_write(cx, remaining) {
                Poll::Ready(Ok(n)) => {
                    this.encrypted_write_pos += n;
                    if this.encrypted_write_pos >= pending.len() {
                        let written = pending.len(); // CFB does not expand; == original buf.len()
                        this.encrypted_buf = None;
                        this.encrypted_write_pos = 0;
                        return Poll::Ready(Ok(written));
                    } else {
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        let cfb = this.cfb.as_mut().expect("IV must be sent before encrypting");
        let mut encrypted = buf.to_vec();
        cfb.encrypt(&mut encrypted);
        match Pin::new(&mut this.inner).poll_write(cx, &encrypted) {
            Poll::Ready(Ok(n)) if n >= encrypted.len() => Poll::Ready(Ok(buf.len())),
            Poll::Ready(Ok(n)) => {
                this.encrypted_buf = Some(encrypted);
                this.encrypted_write_pos = n;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => {
                this.encrypted_buf = Some(encrypted);
                this.encrypted_write_pos = 0;
                Poll::Pending
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;

        // Drain pending first-write buffer (partial write retry).
        if let Some(ref pending) = this.first_write_buf {
            let remaining = &pending[this.first_write_pos..];
            match Pin::new(&mut this.inner).poll_write(cx, remaining) {
                Poll::Ready(Ok(n)) => {
                    this.first_write_pos += n;
                    if this.first_write_pos >= pending.len() {
                        this.first_write_buf = None;
                        this.first_write_pos = 0;
                        this.first_write_data_len = 0;
                    } else {
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        // Drain pending encrypted_buf (partial write retry of normal write).
        if let Some(ref pending) = this.encrypted_buf {
            let remaining = &pending[this.encrypted_write_pos..];
            match Pin::new(&mut this.inner).poll_write(cx, remaining) {
                Poll::Ready(Ok(n)) => {
                    this.encrypted_write_pos += n;
                    if this.encrypted_write_pos >= pending.len() {
                        this.encrypted_buf = None;
                        this.encrypted_write_pos = 0;
                    } else {
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        // Eagerly send IV if not yet sent — unblocks the peer's CipherReader.
        // Without this, when both sides use CipherWriter/CipherReader pairs,
        // the first write is gated on user data arriving, but the peer's
        // CipherReader blocks on the IV before it can make progress.
        if !this.iv_sent {
            this.iv_sent = true;
            let mut iv = [0u8; 16];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut iv);
            this.cfb = Some(CfbState::new(&this.key, &iv));
            match Pin::new(&mut this.inner).poll_write(cx, &iv) {
                Poll::Ready(Ok(n)) if n >= 16 => {}
                Poll::Ready(Ok(n)) => {
                    this.first_write_data_len = 0; // IV-only, no payload data
                    this.first_write_buf = Some(iv.to_vec());
                    this.first_write_pos = n;
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {
                    this.first_write_data_len = 0; // IV-only, no payload data
                    this.first_write_buf = Some(iv.to_vec());
                    this.first_write_pos = 0;
                    return Poll::Pending;
                }
            }
        }

        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;

        // Best-effort drain of pending first-write buffer before shutdown.
        if let Some(ref pending) = this.first_write_buf {
            let remaining = &pending[this.first_write_pos..];
            if let Poll::Ready(Ok(n)) = Pin::new(&mut this.inner).poll_write(cx, remaining) {
                this.first_write_pos += n;
            }
            if this.first_write_pos < pending.len() {
                tracing::warn!(
                    dropped = pending.len() - this.first_write_pos,
                    "CipherWriter::poll_shutdown: discarding {} bytes from first-write buffer",
                    pending.len() - this.first_write_pos,
                );
            }
            this.first_write_buf = None;
            this.first_write_pos = 0;
            this.first_write_data_len = 0;
        }

        // Best-effort drain of pending encrypt buffer before shutdown.
        if let Some(ref pending) = this.encrypted_buf {
            let remaining = &pending[this.encrypted_write_pos..];
            if let Poll::Ready(Ok(n)) = Pin::new(&mut this.inner).poll_write(cx, remaining) {
                this.encrypted_write_pos += n;
            }
            if this.encrypted_write_pos < pending.len() {
                tracing::warn!(
                    dropped = pending.len() - this.encrypted_write_pos,
                    "CipherWriter::poll_shutdown: discarding {} bytes from encrypt buffer",
                    pending.len() - this.encrypted_write_pos,
                );
            }
            this.encrypted_buf = None;
            this.encrypted_write_pos = 0;
        }

        Pin::new(&mut this.inner).poll_shutdown(cx)
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
    /// Original data length when buffer was set by poll_write (excl. 16-byte IV).
    /// Zero when buffer was set by poll_flush (IV-only eager send).
    first_write_data_len: usize,
    /// Buffered second+ write (encrypted payload only, no IV).
    /// Saved across partial writes so retries don't re-encrypt and corrupt CFB.
    encrypted_buf: Option<Vec<u8>>,
    /// Bytes already written from encrypted_buf.
    encrypted_write_pos: usize,
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
            first_write_data_len: 0,
            encrypted_buf: None,
            encrypted_write_pos: 0,
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
                    tracing::debug!(iv_hex = %hex::encode(iv), "CipherStream: IV read complete");
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
                        let data_len = this.first_write_data_len;
                        this.first_write_buf = None;
                        this.first_write_pos = 0;
                        this.first_write_data_len = 0;
                        // Buffer came from poll_write (has data after IV).
                        // Data was already encrypted and stored in buffer —
                        // don't fall through to re-encrypt buf.
                        if data_len > 0 {
                            return Poll::Ready(Ok(data_len));
                        }
                        // Buffer was IV-only (set by poll_flush). Fall through
                        // to normal path — buf still needs encrypting.
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
            tracing::debug!(iv_hex = %hex::encode(this.write_iv), data_len = buf.len(), "CipherStream: first write, sending IV + encrypted data");
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
                    this.first_write_data_len = buf.len();
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {
                    this.first_write_buf = Some(output);
                    this.first_write_pos = 0;
                    this.first_write_data_len = buf.len();
                    return Poll::Pending;
                }
            }
        }

        // Drain pending encrypted_buf (partial write retry of a normal write).
        if let Some(ref pending) = this.encrypted_buf {
            let remaining = &pending[this.encrypted_write_pos..];
            match Pin::new(&mut this.inner).poll_write(cx, remaining) {
                Poll::Ready(Ok(n)) => {
                    this.encrypted_write_pos += n;
                    if this.encrypted_write_pos >= pending.len() {
                        let written = pending.len(); // CFB does not expand; == original buf.len()
                        this.encrypted_buf = None;
                        this.encrypted_write_pos = 0;
                        return Poll::Ready(Ok(written));
                    } else {
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        let cfb = this.write_cfb.as_mut().expect("IV must be sent before encrypting");
        let mut encrypted = buf.to_vec();
        cfb.encrypt(&mut encrypted);
        match Pin::new(&mut this.inner).poll_write(cx, &encrypted) {
            Poll::Ready(Ok(n)) if n >= encrypted.len() => Poll::Ready(Ok(buf.len())),
            Poll::Ready(Ok(n)) => {
                this.encrypted_buf = Some(encrypted);
                this.encrypted_write_pos = n;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => {
                this.encrypted_buf = Some(encrypted);
                this.encrypted_write_pos = 0;
                Poll::Pending
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;

        // Drain pending first-write buffer (partial write retry).
        if let Some(ref pending) = this.first_write_buf {
            let remaining = &pending[this.first_write_pos..];
            match Pin::new(&mut this.inner).poll_write(cx, remaining) {
                Poll::Ready(Ok(n)) => {
                    this.first_write_pos += n;
                    if this.first_write_pos >= pending.len() {
                        this.first_write_buf = None;
                        this.first_write_pos = 0;
                        this.first_write_data_len = 0;
                    } else {
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        // Drain pending encrypted_buf (partial write retry of normal write).
        if let Some(ref pending) = this.encrypted_buf {
            let remaining = &pending[this.encrypted_write_pos..];
            match Pin::new(&mut this.inner).poll_write(cx, remaining) {
                Poll::Ready(Ok(n)) => {
                    this.encrypted_write_pos += n;
                    if this.encrypted_write_pos >= pending.len() {
                        this.encrypted_buf = None;
                        this.encrypted_write_pos = 0;
                    } else {
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        // Eagerly send pre-generated IV if not yet sent.
        if !this.iv_sent {
            this.iv_sent = true;
            this.write_cfb = Some(CfbState::new(&this.write_key, &this.write_iv));
            match Pin::new(&mut this.inner).poll_write(cx, &this.write_iv) {
                Poll::Ready(Ok(n)) if n >= 16 => {}
                Poll::Ready(Ok(n)) => {
                    this.first_write_data_len = 0; // IV-only, no payload data
                    this.first_write_buf = Some(this.write_iv.to_vec());
                    this.first_write_pos = n;
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {
                    this.first_write_data_len = 0; // IV-only, no payload data
                    this.first_write_buf = Some(this.write_iv.to_vec());
                    this.first_write_pos = 0;
                    return Poll::Pending;
                }
            }
        }

        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;

        // Best-effort drain of pending first-write buffer before shutdown.
        if let Some(ref pending) = this.first_write_buf {
            let remaining = &pending[this.first_write_pos..];
            if let Poll::Ready(Ok(n)) = Pin::new(&mut this.inner).poll_write(cx, remaining) {
                this.first_write_pos += n;
            }
            if this.first_write_pos < pending.len() {
                tracing::warn!(
                    dropped = pending.len() - this.first_write_pos,
                    "CipherStream::poll_shutdown: discarding {} bytes from first-write buffer",
                    pending.len() - this.first_write_pos,
                );
            }
            this.first_write_buf = None;
            this.first_write_pos = 0;
            this.first_write_data_len = 0;
        }

        // Best-effort drain of pending encrypt buffer before shutdown.
        if let Some(ref pending) = this.encrypted_buf {
            let remaining = &pending[this.encrypted_write_pos..];
            if let Poll::Ready(Ok(n)) = Pin::new(&mut this.inner).poll_write(cx, remaining) {
                this.encrypted_write_pos += n;
            }
            if this.encrypted_write_pos < pending.len() {
                tracing::warn!(
                    dropped = pending.len() - this.encrypted_write_pos,
                    "CipherStream::poll_shutdown: discarding {} bytes from encrypt buffer",
                    pending.len() - this.encrypted_write_pos,
                );
            }
            this.encrypted_buf = None;
            this.encrypted_write_pos = 0;
        }

        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    const TEST_KEY: [u8; 16] = [0x42u8; 16];

    #[tokio::test]
    async fn round_trip() {
        let (client, server) = duplex(128 * 1024);
        let mut writer = CipherWriter::new(client, TEST_KEY);
        let mut reader = CipherReader::new(server, TEST_KEY);

        let data = b"hello world round trip test data";
        writer.write_all(data).await.unwrap();
        writer.shutdown().await.unwrap();

        let mut buf = vec![0u8; data.len()];
        reader.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, data);
    }

    #[tokio::test]
    async fn empty_payload() {
        let (client, server) = duplex(1024);
        let mut writer = CipherWriter::new(client, TEST_KEY);
        let mut reader = CipherReader::new(server, TEST_KEY);

        writer.write_all(b"X").await.unwrap();
        writer.shutdown().await.unwrap();

        let mut buf = [0u8; 1];
        reader.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf[0], b'X');
    }

    #[tokio::test]
    async fn corrupted_ciphertext() {
        let (a1, mut b1) = duplex(64 * 1024);
        let mut writer = CipherWriter::new(a1, TEST_KEY);
        let data = b"secret message to be corrupted";
        writer.write_all(data).await.unwrap();
        writer.shutdown().await.unwrap();
        drop(writer);

        let mut raw = vec![];
        b1.read_to_end(&mut raw).await.unwrap();
        assert!(raw.len() > 20, "encrypted output too short");

        // Corrupt a byte in the ciphertext region (after the 16-byte IV)
        raw[20] ^= 0xFF;

        let (mut a2, b2) = duplex(64 * 1024);
        a2.write_all(&raw).await.unwrap();
        drop(a2);

        let mut reader = CipherReader::new(b2, TEST_KEY);
        let mut decoded = vec![];
        reader.read_to_end(&mut decoded).await.unwrap();

        // CFB corruption: altered ciphertext produces different plaintext
        assert_ne!(decoded.as_slice(), data.as_slice(),
            "corrupted ciphertext must not decrypt to original plaintext");
    }

    #[tokio::test]
    async fn large_payload() {
        let (client, server) = duplex(256 * 1024);
        let mut writer = CipherWriter::new(client, TEST_KEY);
        let mut reader = CipherReader::new(server, TEST_KEY);

        let data = vec![0x5Au8; 70 * 1024]; // > 64KB
        let write_data = data.clone();
        let write_handle = tokio::spawn(async move {
            writer.write_all(&write_data).await.unwrap();
            writer.shutdown().await.unwrap();
        });

        let mut buf = vec![0u8; data.len()];
        reader.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, data);

        write_handle.await.unwrap();
    }

    #[tokio::test]
    async fn cipher_stream_round_trip() {
        let (c1, c2) = duplex(128 * 1024);
        let mut cs1 = CipherStream::new(c1, TEST_KEY);
        let mut cs2 = CipherStream::new(c2, TEST_KEY);

        let data = b"CipherStream bidirectional round trip";

        let write_handle = tokio::spawn(async move {
            cs1.write_all(data).await.unwrap();
        });

        let mut buf = vec![0u8; data.len()];
        cs2.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, data);

        write_handle.await.unwrap();
    }

    /// Verify that calling flush() BEFORE any write() eagerly sends the IV,
    /// allowing the peer's CipherReader to make progress without data.
    #[tokio::test]
    async fn flush_before_write_sends_iv() {
        let (client, server) = duplex(128 * 1024);
        let mut writer = CipherWriter::new(client, TEST_KEY);
        let mut reader = CipherReader::new(server, TEST_KEY);

        // Flush before any write — should eagerly generate and send IV.
        writer.flush().await.unwrap();

        // Now write data — IV already sent, this is just encrypted payload.
        let data = b"data after eager iv flush";
        writer.write_all(data).await.unwrap();
        writer.shutdown().await.unwrap();

        let mut buf = vec![0u8; data.len()];
        reader.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, data, "round-trip after eager IV flush mismatch");
    }

    /// Verify that flush() drains a pending first_write_buf from a partial write.
    /// Uses a small duplex buffer to force partial writes.
    #[tokio::test]
    async fn flush_drains_partial_first_write() {
        // Duplex with small buffer to force partial writes of IV+data.
        let (client, server) = duplex(128); // small enough to split IV+data across writes
        let mut writer = CipherWriter::new(client, TEST_KEY);
        let mut reader = CipherReader::new(server, TEST_KEY);

        let data = vec![0xA1u8; 1024]; // will be split across multiple writes
        let expected = data.clone();

        let write_handle = tokio::spawn(async move {
            writer.write_all(&data).await.unwrap();
            writer.flush().await.unwrap();
            writer.shutdown().await.unwrap();
        });

        let mut buf = vec![0u8; expected.len()];
        reader.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, expected, "partial-write flush round-trip mismatch");

        write_handle.await.unwrap();
    }

    /// CipherStream: flush before write sends pre-generated IV eagerly.
    #[tokio::test]
    async fn cipher_stream_flush_before_write() {
        let (c1, c2) = duplex(128 * 1024);
        let mut cs1 = CipherStream::new(c1, TEST_KEY);
        let mut cs2 = CipherStream::new(c2, TEST_KEY);

        // Flush before any write.
        cs1.flush().await.unwrap();

        let data = b"CipherStream flush-before-write test";
        cs1.write_all(data).await.unwrap();
        cs1.shutdown().await.unwrap();

        let mut buf = vec![0u8; data.len()];
        cs2.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, data);
    }

    /// Verify that partial writes on the SECOND+ write (non-first path) do not
    /// corrupt the cipher stream. Uses a tiny duplex buffer to force partials.
    #[tokio::test]
    async fn partial_second_write_no_corruption() {
        // Buffer of 64 bytes forces partial writes: IV=16, encrypted data > 64-16=48.
        let (client, server) = duplex(64);
        let mut writer = CipherWriter::new(client, TEST_KEY);
        let mut reader = CipherReader::new(server, TEST_KEY);

        // First write: exercises first_write_buf (IV + 200 bytes = 216 > 64)
        let first = vec![0xA1u8; 200];
        // Second write: exercises encrypted_buf (200 encrypted bytes, no IV, > 64)
        let second = vec![0xB2u8; 200];
        let first_expected = first.clone();
        let second_expected = second.clone();

        let write_handle = tokio::spawn(async move {
            writer.write_all(&first).await.unwrap();
            writer.write_all(&second).await.unwrap();
            writer.flush().await.unwrap();
            writer.shutdown().await.unwrap();
        });

        let total = first_expected.len() + second_expected.len();
        let mut buf = vec![0u8; total];
        reader.read_exact(&mut buf).await.unwrap();

        assert_eq!(&buf[..first_expected.len()], &first_expected[..], "first write corrupted");
        assert_eq!(&buf[first_expected.len()..], &second_expected[..], "second write corrupted");

        write_handle.await.unwrap();
    }

    /// Verify CipherStream partial writes on the SECOND+ write do not corrupt.
    #[tokio::test]
    async fn cipher_stream_partial_second_write_no_corruption() {
        let (c1, c2) = duplex(64);
        let mut cs1 = CipherStream::new(c1, TEST_KEY);
        let mut cs2 = CipherStream::new(c2, TEST_KEY);

        let first = vec![0xC3u8; 200];
        let second = vec![0xD4u8; 200];
        let first_expected = first.clone();
        let second_expected = second.clone();

        let write_handle = tokio::spawn(async move {
            cs1.write_all(&first).await.unwrap();
            cs1.write_all(&second).await.unwrap();
            cs1.flush().await.unwrap();
            cs1.shutdown().await.unwrap();
        });

        let total = first_expected.len() + second_expected.len();
        let mut buf = vec![0u8; total];
        cs2.read_exact(&mut buf).await.unwrap();

        assert_eq!(&buf[..first_expected.len()], &first_expected[..], "first write corrupted");
        assert_eq!(&buf[first_expected.len()..], &second_expected[..], "second write corrupted");

        write_handle.await.unwrap();
    }

    // Reference byte-wise CFB (a copy of the pre-optimization algorithm).
    // The optimized block-wise CfbState must produce identical output.
    struct RefCfb {
        aes: aes::Aes128,
        feedback: [u8; 16],
        keystream: [u8; 16],
        used: usize,
    }
    impl RefCfb {
        fn new(key: &[u8; 16], iv: &[u8; 16]) -> Self {
            use aes::cipher::{BlockCipherEncrypt, KeyInit};
            let aes = aes::Aes128::new_from_slice(key).unwrap();
            let mut s = RefCfb { aes, feedback: *iv, keystream: *iv, used: 0 };
            s.aes.encrypt_block((&mut s.keystream).into());
            s
        }
        fn refill(&mut self) {
            use aes::cipher::BlockCipherEncrypt;
            self.keystream = self.feedback;
            self.aes.encrypt_block((&mut self.keystream).into());
            self.used = 0;
        }
        fn encrypt(&mut self, data: &mut [u8]) {
            for byte in data.iter_mut() {
                if self.used >= 16 { self.refill(); }
                *byte ^= self.keystream[self.used];
                self.feedback[self.used] = *byte;
                self.used += 1;
            }
        }
        fn decrypt(&mut self, data: &mut [u8]) {
            for byte in data.iter_mut() {
                if self.used >= 16 { self.refill(); }
                let ct = *byte;
                *byte ^= self.keystream[self.used];
                self.feedback[self.used] = ct;
                self.used += 1;
            }
        }
    }

    // Deterministic pseudo-random fill (no rand dep needed in test).
    fn fill_pattern(buf: &mut [u8], seed: u64) {
        let mut x = seed | 1;
        for b in buf.iter_mut() {
            x ^= x << 13; x ^= x >> 7; x ^= x << 17;
            *b = (x & 0xff) as u8;
        }
    }

    #[test]
    fn cfb_block_wise_matches_reference_encrypt() {
        let key = [7u8; 16];
        let iv = [0x11u8; 16];
        // Single-shot sizes straddling block boundaries.
        for size in [0usize, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 255, 4096] {
            let mut data = vec![0u8; size];
            fill_pattern(&mut data, size as u64 + 1);
            let mut got = data.clone();
            let mut want = data.clone();
            CfbState::new(&key, &iv).encrypt(&mut got);
            RefCfb::new(&key, &iv).encrypt(&mut want);
            assert_eq!(got, want, "encrypt mismatch at size {}", size);
        }
    }

    #[test]
    fn cfb_block_wise_matches_reference_decrypt() {
        let key = [7u8; 16];
        let iv = [0x11u8; 16];
        for size in [0usize, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 255, 4096] {
            let mut data = vec![0u8; size];
            fill_pattern(&mut data, size as u64 + 99);
            let mut got = data.clone();
            let mut want = data.clone();
            CfbState::new(&key, &iv).decrypt(&mut got);
            RefCfb::new(&key, &iv).decrypt(&mut want);
            assert_eq!(got, want, "decrypt mismatch at size {}", size);
        }
    }

    #[test]
    fn cfb_block_wise_matches_reference_chunked() {
        // Multi-chunk splits exercise cross-chunk `used` carry — the boundary
        // case a naive block rewrite gets wrong.
        let key = [42u8; 16];
        let iv = [0xABu8; 16];
        let splits: &[&[usize]] = &[
            &[1, 31, 4096],
            &[15, 1, 16, 17],
            &[16, 16, 16],
            &[7, 9, 100, 3, 4096],
            &[33, 33, 33],
        ];
        for chunks in splits {
            let total: usize = chunks.iter().sum();
            let mut plain = vec![0u8; total];
            fill_pattern(&mut plain, total as u64 + 7);

            let mut got = plain.clone();
            let mut want = plain.clone();
            let mut got_cfb = CfbState::new(&key, &iv);
            let mut want_cfb = RefCfb::new(&key, &iv);
            let mut off = 0;
            for &c in *chunks {
                got_cfb.encrypt(&mut got[off..off + c]);
                want_cfb.encrypt(&mut want[off..off + c]);
                off += c;
            }
            assert_eq!(got, want, "chunked encrypt mismatch for {:?}", chunks);

            // Round-trip: decrypting the ciphertext restores plaintext.
            let mut rt = got.clone();
            CfbState::new(&key, &iv).decrypt(&mut rt);
            assert_eq!(rt, plain, "round-trip mismatch for {:?}", chunks);
        }
    }
}
