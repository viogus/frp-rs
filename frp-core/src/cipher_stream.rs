//! AES-128-CFB streaming cipher for control connection and bridge encryption.
//!
//! # Security Note: CFB is confidentiality-only (no integrity)
//!
//! AES-128-CFB (V1 protocol) provides **confidentiality only** — it does NOT
//! provide integrity/authentication. CFB mode is malleable: an attacker who
//! can modify ciphertext can predictably flip bits in the decrypted plaintext
//! without detection. This is acceptable for the frp V1 control channel because:
//!
//! - The channel carries structured JSON messages — bit flips produce invalid
//!   JSON, caught by serde deserialization.
//! - The attacker must be on-path (MITM between client and server).
//! - TLS wraps the transport when available, providing AEAD at the transport
//!   layer.
//!
//! **Prefer V2 protocol** which uses AEAD (AES-256-GCM or XChaCha20-Poly1305).
//! V2 provides authenticated encryption (confidentiality + integrity) and is
//! the recommended protocol for new deployments.
//!
//! Matches Go frp v0.69.1 `crypto.NewReader` / `crypto.NewWriter` behavior.
//! Each direction exchanges a 16-byte random IV: writer prepends it on first
//! write, reader consumes it on first read. Both directions are independent.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

use aes::Aes128;

pub trait AsyncReadWriteUnpin: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncReadWriteUnpin for T {}

/// Overwrite `buf` with zeros using volatile stores.
///
/// A plain `fill(0)`/`memset` can be eliminated by LLVM as a dead store when
/// the allocation is freed immediately after (the typical lifetime of a
/// cipher key), so the wipe must survive optimization to actually erase the
/// material. Same primitive as `auth::zeroize_string`.
pub(crate) fn zeroize_bytes(buf: &mut [u8]) {
    let ptr = buf.as_mut_ptr();
    let len = buf.len();
    // SAFETY: `ptr..ptr+len` is exactly the allocation backing `buf`, valid
    // for the slice's lifetime (we hold `&mut [u8]`), and `u8` writes are
    // valid for any alignment. Each `write_volatile` is a single byte store.
    unsafe {
        for i in 0..len {
            core::ptr::write_volatile(ptr.add(i), 0u8);
        }
    }
}

/// CFB-128 state matching Go frp's `crypto/cipher` CFB mode.
///
/// In CFB-128 mode, AES encrypts the feedback register to produce a 16-byte
/// keystream block. This keystream is XORed with input bytes. After each byte,
/// the corresponding ciphertext byte is shifted into the feedback register.
/// When all 16 keystream bytes are consumed, the feedback register (now filled
/// with 16 bytes of ciphertext) is re-encrypted to produce the next keystream.
struct CfbState {
    aes: Aes128,
    feedback: [u8; 16],  // feedback register (IV initially, then ciphertext)
    keystream: [u8; 16], // current 16-byte keystream block
    used: usize,         // how many keystream bytes consumed (0..16)
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
    #[inline]
    fn refill(&mut self) {
        use aes::cipher::BlockCipherEncrypt;
        self.keystream = self.feedback;
        self.aes.encrypt_block((&mut self.keystream).into());
        self.used = 0;
    }

    #[inline]
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
                // u128 single-instruction XOR on little-endian (pxor/veor).
                let state_u128 = u128::from_le_bytes(self.keystream);
                let data_u128 = u128::from_le_bytes(
                    data[i..i + 16]
                        .try_into()
                        .expect("16-byte slice guaranteed by n - i >= 16 guard above"),
                );
                let result = (state_u128 ^ data_u128).to_le_bytes();
                data[i..i + 16].copy_from_slice(&result);
                self.feedback = result;
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

    #[inline]
    fn decrypt(&mut self, data: &mut [u8]) {
        let n = data.len();
        let mut i = 0;
        while i < n {
            if self.used >= 16 {
                self.refill();
            }
            if self.used == 0 && n - i >= 16 {
                // feedback = ciphertext (input), then plaintext = ct ^ keystream.
                self.feedback = data[i..i + 16]
                    .try_into()
                    .expect("16-byte slice guaranteed by n - i >= 16 guard above");
                // u128 single-instruction XOR on little-endian (pxor/veor).
                let state_u128 = u128::from_le_bytes(self.keystream);
                let data_u128 = u128::from_le_bytes(self.feedback);
                let result = (state_u128 ^ data_u128).to_le_bytes();
                data[i..i + 16].copy_from_slice(&result);
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

impl Drop for CfbState {
    fn drop(&mut self) {
        // Wipe the feedback register and keystream block: they hold derived
        // key material (the IV-then-ciphertext feedback chained through AES)
        // that would otherwise persist in memory after the cipher state is
        // freed. The AES key schedule inside `aes` is out of our reach.
        zeroize_bytes(&mut self.feedback);
        zeroize_bytes(&mut self.keystream);
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
    iv_buf: [u8; 16],
    iv_read: usize,
}

impl<R: AsyncRead + Unpin> CipherReader<R> {
    pub fn new(inner: R, key: [u8; 16]) -> Self {
        Self {
            inner,
            key,
            cfb: None,
            iv_buf: [0u8; 16],
            iv_read: 0,
        }
    }
}

impl<R: AsyncRead + Unpin> Drop for CipherReader<R> {
    fn drop(&mut self) {
        // Wipe the AES-128 key copy this reader retains.
        zeroize_bytes(&mut self.key);
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
            let filled;
            {
                let iv_dest = &mut this.iv_buf[this.iv_read..];
                let mut tmp_buf = ReadBuf::new(iv_dest);
                match Pin::new(&mut this.inner).poll_read(cx, &mut tmp_buf) {
                    Poll::Ready(Ok(())) => {
                        filled = tmp_buf.filled().len();
                        if filled == 0 {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "CipherReader: EOF while reading IV",
                            )));
                        }
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }
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

        let cfb = this
            .cfb
            .as_mut()
            .expect("IV must be read before decrypting");

        // Zero-copy: read encrypted data directly into the user's ReadBuf,
        // decrypt in-place, then advance to commit the decrypted bytes.
        let filled;
        {
            let inner_slice = buf.initialize_unfilled();
            let mut inner_buf = ReadBuf::new(inner_slice);
            match Pin::new(&mut this.inner).poll_read(cx, &mut inner_buf) {
                Poll::Ready(Ok(())) => {
                    filled = inner_buf.filled().len();
                }
                other => return other,
            }
            // inner_buf is no longer used; NLL releases its borrow on inner_slice.
            if filled > 0 {
                cfb.decrypt(&mut inner_slice[..filled]);
            }
        }
        if filled > 0 {
            buf.advance(filled);
        }
        Poll::Ready(Ok(()))
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
/// Shared AES-128-CFB **write** state machine, used by both `CipherWriter`
/// (a pure writer) and `CipherStream` (a combined reader+writer). It owns every
/// write-side field — key, CFB state, the random IV, the partial-write retry
/// buffers and the reusable encrypt scratch — and exposes the
/// `poll_write`/`poll_flush`/`poll_shutdown` methods over a borrowed underlying
/// `AsyncWrite`. This keeps the ~280-line partial-write/IV logic defined ONCE
/// (audit #11): previously it was near-verbatim duplicated in `CipherStream`,
/// and a bug fixed on one path could silently stay on the other.
///
/// The IV is generated up front (in `new`) and emitted with the first
/// write (or first `flush`) — identical wire behavior to generating it lazily,
/// since the random IV always precedes the first ciphertext byte.
struct CipherWriterState {
    key: [u8; 16],
    cfb: Option<CfbState>,
    write_iv: [u8; 16],
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
    /// Reused encrypt scratch — avoids a per-chunk `Vec` allocation on the hot
    /// write path. Moved out (via `mem::take`) only on the rare partial-write
    /// branch, then regrown on the next call.
    scratch: Vec<u8>,
}

impl CipherWriterState {
    fn new(key: [u8; 16]) -> Self {
        let mut write_iv = [0u8; 16];
        rand::TryRng::try_fill_bytes(&mut rand::rngs::SysRng, &mut write_iv)
            .expect("SysRng failure");
        Self {
            key,
            cfb: None,
            write_iv,
            iv_sent: false,
            first_write_buf: None,
            first_write_pos: 0,
            first_write_data_len: 0,
            encrypted_buf: None,
            encrypted_write_pos: 0,
            scratch: Vec::new(),
        }
    }

    /// Send the random IV to the peer. Must be called once before
    /// write_encrypted. Idempotent — subsequent calls are no-ops.
    async fn send_iv<W: AsyncWrite + Unpin>(&mut self, inner: &mut W) -> io::Result<()> {
        if self.iv_sent {
            return Ok(());
        }
        self.iv_sent = true;
        self.cfb = Some(CfbState::new(&self.key, &self.write_iv));
        inner.write_all(&self.write_iv).await
    }

    /// Encrypt `data` in-place (CFB) and write to the underlying transport.
    /// `data` is overwritten with ciphertext — caller must not read it after.
    /// IV must already be sent (via poll_write first write, poll_flush, or send_iv).
    async fn write_encrypted<W: AsyncWrite + Unpin>(
        &mut self,
        inner: &mut W,
        data: &mut [u8],
    ) -> io::Result<usize> {
        self.send_iv(inner).await?;
        let cfb = self.cfb.as_mut().expect("IV must be set after send_iv");
        cfb.encrypt(data);
        inner.write_all(data).await?;
        Ok(data.len())
    }

    fn poll_write<W: AsyncWrite + Unpin>(
        &mut self,
        cx: &mut Context<'_>,
        inner: &mut W,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self;

        // Flush pending first-write buffer (partial write retry).
        if let Some(ref pending) = this.first_write_buf {
            let remaining = &pending[this.first_write_pos..];
            match Pin::new(&mut *inner).poll_write(cx, remaining) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "write zero",
                    )));
                }
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

        // A first-write (IV+data) buffer fully drained inside poll_flush:
        // first_write_data_len keeps the pending claim (see poll_flush). The
        // caller re-polls with the same buf — return the claim without
        // re-encrypting (the CFB keystream already advanced past it).
        if this.first_write_data_len > 0 {
            let data_len = this.first_write_data_len;
            this.first_write_data_len = 0;
            return Poll::Ready(Ok(data_len));
        }

        // On first write, emit the random IV generated in new().
        if !this.iv_sent {
            this.iv_sent = true;
            this.cfb = Some(CfbState::new(&this.key, &this.write_iv));
            // Encrypt into reusable scratch buffer — avoids buf.to_vec() allocation.
            this.scratch.clear();
            this.scratch.extend_from_slice(buf);
            this.cfb
                .as_mut()
                .expect("cfb set to Some on first write above")
                .encrypt(&mut this.scratch);
            let mut output = Vec::with_capacity(16 + this.scratch.len());
            output.extend_from_slice(&this.write_iv);
            output.extend_from_slice(&this.scratch);
            match Pin::new(&mut *inner).poll_write(cx, &output) {
                Poll::Ready(Ok(n)) if n >= output.len() => {
                    return Poll::Ready(Ok(buf.len()));
                }
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "write zero",
                    )));
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
            match Pin::new(&mut *inner).poll_write(cx, remaining) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "write zero",
                    )));
                }
                Poll::Ready(Ok(n)) => {
                    this.encrypted_write_pos += n;
                    if this.encrypted_write_pos >= pending.len() {
                        let written = pending.len(); // CFB does not expand; == original buf.len()
                                                     // Return buffer to scratch to reuse allocation on next write.
                        this.scratch = this
                            .encrypted_buf
                            .take()
                            .expect("encrypted_buf is Some — checked above");
                        this.scratch.clear();
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

        let cfb = this
            .cfb
            .as_mut()
            .expect("IV must be sent before encrypting");
        this.scratch.clear();
        this.scratch.extend_from_slice(buf);
        cfb.encrypt(&mut this.scratch);
        match Pin::new(&mut *inner).poll_write(cx, &this.scratch) {
            Poll::Ready(Ok(n)) if n >= this.scratch.len() => Poll::Ready(Ok(buf.len())),
            Poll::Ready(Ok(0)) => {
                Poll::Ready(Err(io::Error::new(io::ErrorKind::WriteZero, "write zero")))
            }
            Poll::Ready(Ok(n)) => {
                // Partial write: hand the un-written remainder to the pending
                // buffer (rare backpressure path — pays one alloc via take).
                this.encrypted_buf = Some(std::mem::take(&mut this.scratch));
                this.encrypted_write_pos = n;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => {
                this.encrypted_buf = Some(std::mem::take(&mut this.scratch));
                this.encrypted_write_pos = 0;
                Poll::Pending
            }
        }
    }

    fn poll_flush<W: AsyncWrite + Unpin>(
        &mut self,
        cx: &mut Context<'_>,
        inner: &mut W,
    ) -> Poll<io::Result<()>> {
        let this = self;

        // Drain pending first-write buffer (partial write retry).
        if let Some(ref pending) = this.first_write_buf {
            let remaining = &pending[this.first_write_pos..];
            match Pin::new(&mut *inner).poll_write(cx, remaining) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "write zero",
                    )));
                }
                Poll::Ready(Ok(n)) => {
                    this.first_write_pos += n;
                    if this.first_write_pos >= pending.len() {
                        // Stash the write claim instead of discarding it:
                        // this buffer may carry IV+data whose poll_write is
                        // still pending, and poll_flush has no buf argument
                        // to consume. The next poll_write sees the stashed
                        // first_write_data_len and returns it WITHOUT
                        // re-encrypting (re-encrypting with the already
                        // advanced CFB keystream would double-encrypt the
                        // payload). IV-only writes (data_len == 0, parked by
                        // poll_flush itself) fall through to the eager-IV
                        // arm below as before.
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

        // Drain pending encrypted_buf (partial write retry of normal write).
        if let Some(ref pending) = this.encrypted_buf {
            let remaining = &pending[this.encrypted_write_pos..];
            match Pin::new(&mut *inner).poll_write(cx, remaining) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "write zero",
                    )));
                }
                Poll::Ready(Ok(n)) => {
                    this.encrypted_write_pos += n;
                    if this.encrypted_write_pos >= pending.len() {
                        // Return buffer to scratch to reuse allocation.
                        this.scratch = this
                            .encrypted_buf
                            .take()
                            .expect("encrypted_buf is Some — checked above");
                        this.scratch.clear();
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
        if !this.iv_sent {
            this.iv_sent = true;
            this.cfb = Some(CfbState::new(&this.key, &this.write_iv));
            match Pin::new(&mut *inner).poll_write(cx, &this.write_iv) {
                Poll::Ready(Ok(n)) if n >= 16 => {}
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "write zero",
                    )));
                }
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

        Pin::new(&mut *inner).poll_flush(cx)
    }

    fn poll_shutdown<W: AsyncWrite + Unpin>(
        &mut self,
        cx: &mut Context<'_>,
        inner: &mut W,
    ) -> Poll<io::Result<()>> {
        let this = self;

        // Best-effort drain of pending first-write buffer before shutdown.
        if let Some(ref pending) = this.first_write_buf {
            let remaining = &pending[this.first_write_pos..];
            if let Poll::Ready(Ok(n)) = Pin::new(&mut *inner).poll_write(cx, remaining) {
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
            if let Poll::Ready(Ok(n)) = Pin::new(&mut *inner).poll_write(cx, remaining) {
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

        Pin::new(&mut *inner).poll_shutdown(cx)
    }
}

/// Writer of an AES-128-CFB encrypted stream.
///
/// Outputs the random IV as a 16-byte prefix, then a continuous CFB
/// ciphertext stream (no per-frame length prefix) — matching Go frp v0.69.1
/// `crypto.NewWriter`.
pub struct CipherWriter<W: AsyncWrite + Unpin> {
    inner: W,
    state: CipherWriterState,
}

impl<W: AsyncWrite + Unpin> CipherWriter<W> {
    pub fn new(inner: W, key: [u8; 16]) -> Self {
        Self {
            inner,
            state: CipherWriterState::new(key),
        }
    }

    /// Encrypt `data` in-place (CFB) and write to the underlying transport.
    /// `data` is overwritten with ciphertext — caller must not read it after.
    /// IV must already be sent (via poll_write first write, poll_flush, or send_iv).
    pub async fn write_encrypted(&mut self, data: &mut [u8]) -> io::Result<usize> {
        self.state.write_encrypted(&mut self.inner, data).await
    }
}

impl<W: AsyncWrite + Unpin> Drop for CipherWriter<W> {
    fn drop(&mut self) {
        // Wipe the AES-128 key copy this writer retains.
        zeroize_bytes(&mut self.state.key);
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for CipherWriter<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        this.state.poll_write(cx, &mut this.inner, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        this.state.poll_flush(cx, &mut this.inner)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        this.state.poll_shutdown(cx, &mut this.inner)
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
    read_cfb: Option<CfbState>,
    iv_read: usize,
    iv_buf: [u8; 16],
    /// Write-side state (IV, CFB, partial-write retry buffers) — delegated to
    /// the shared `CipherWriterState` so the write path is defined once (#11).
    write_state: CipherWriterState,
}

impl<S: AsyncRead + AsyncWrite + Unpin> CipherStream<S> {
    pub fn new(inner: S, key: [u8; 16]) -> Self {
        Self {
            inner,
            read_key: key,
            read_cfb: None,
            iv_read: 0,
            iv_buf: [0u8; 16],
            write_state: CipherWriterState::new(key),
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> Drop for CipherStream<S> {
    fn drop(&mut self) {
        // Wipe both directional AES-128 key copies this stream retains.
        zeroize_bytes(&mut self.read_key);
        zeroize_bytes(&mut self.write_state.key);
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
            let filled;
            {
                tracing::debug!(
                    iv_read = this.iv_read,
                    needed = 16 - this.iv_read,
                    "CipherStream: reading IV"
                );
                let iv_dest = &mut this.iv_buf[this.iv_read..];
                let mut tmp_buf = ReadBuf::new(iv_dest);
                match Pin::new(&mut this.inner).poll_read(cx, &mut tmp_buf) {
                    Poll::Ready(Ok(())) => {
                        filled = tmp_buf.filled().len();
                        tracing::debug!(
                            filled,
                            iv_read = this.iv_read,
                            "CipherStream: IV read chunk"
                        );
                        if filled == 0 {
                            let iv_read = this.iv_read;
                            tracing::warn!(
                                iv_read,
                                "CipherStream: EOF while reading IV (got {iv_read} of 16)"
                            );
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "CipherStream: EOF while reading IV",
                            )));
                        }
                    }
                    Poll::Ready(Err(e)) => {
                        tracing::warn!(error = %e, "CipherStream: error reading IV");
                        return Poll::Ready(Err(e));
                    }
                    Poll::Pending => return Poll::Pending,
                }
            }
            this.iv_read += filled;
            if this.iv_read < 16 {
                tracing::debug!(
                    iv_read = this.iv_read,
                    "CipherStream: IV incomplete, waiting"
                );
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            let mut iv = [0u8; 16];
            iv.copy_from_slice(&this.iv_buf);
            this.read_cfb = Some(CfbState::new(&this.read_key, &iv));
            tracing::debug!(iv_hex = %crate::hex_encode(&iv), "CipherStream: IV read complete");
        }

        let cfb = this
            .read_cfb
            .as_mut()
            .expect("IV must be read before decrypting");

        // Zero-copy: read encrypted data directly into the user's ReadBuf,
        // decrypt in-place, then advance to commit the decrypted bytes.
        let filled;
        {
            let inner_slice = buf.initialize_unfilled();
            let mut inner_buf = ReadBuf::new(inner_slice);
            match Pin::new(&mut this.inner).poll_read(cx, &mut inner_buf) {
                Poll::Ready(Ok(())) => {
                    filled = inner_buf.filled().len();
                }
                other => return other,
            }
            // inner_buf is no longer used; NLL releases its borrow on inner_slice.
            if filled > 0 {
                cfb.decrypt(&mut inner_slice[..filled]);
            }
        }
        if filled > 0 {
            buf.advance(filled);
        }
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for CipherStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        // Delegate to the shared write state machine (which owns the write IV,
        // CFB state and partial-write retry buffers) — defined once, not
        // duplicated from CipherWriter (audit #11).
        this.write_state.poll_write(cx, &mut this.inner, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        this.write_state.poll_flush(cx, &mut this.inner)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        this.write_state.poll_shutdown(cx, &mut this.inner)
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
        assert_ne!(
            decoded.as_slice(),
            data.as_slice(),
            "corrupted ciphertext must not decrypt to original plaintext"
        );
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

        assert_eq!(
            &buf[..first_expected.len()],
            &first_expected[..],
            "first write corrupted"
        );
        assert_eq!(
            &buf[first_expected.len()..],
            &second_expected[..],
            "second write corrupted"
        );

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

        assert_eq!(
            &buf[..first_expected.len()],
            &first_expected[..],
            "first write corrupted"
        );
        assert_eq!(
            &buf[first_expected.len()..],
            &second_expected[..],
            "second write corrupted"
        );

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
            let mut s = RefCfb {
                aes,
                feedback: *iv,
                keystream: *iv,
                used: 0,
            };
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

    // Deterministic pseudo-random fill (no rand dep needed in test).
    fn fill_pattern(buf: &mut [u8], seed: u64) {
        let mut x = seed | 1;
        for b in buf.iter_mut() {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
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

            // Chunked decrypt vs reference: feed the SAME ciphertext through
            // both implementations in identical chunk splits, directly
            // verifying cross-chunk `used` carry on the decrypt path.
            let mut got_dec = got.clone();
            let mut want_dec = got.clone();
            let mut got_dec_cfb = CfbState::new(&key, &iv);
            let mut want_dec_cfb = RefCfb::new(&key, &iv);
            let mut doff = 0;
            for &c in *chunks {
                got_dec_cfb.decrypt(&mut got_dec[doff..doff + c]);
                want_dec_cfb.decrypt(&mut want_dec[doff..doff + c]);
                doff += c;
            }
            assert_eq!(
                got_dec, want_dec,
                "chunked decrypt mismatch for {:?}",
                chunks
            );

            // Round-trip: decrypting the ciphertext restores plaintext.
            let mut rt = got.clone();
            CfbState::new(&key, &iv).decrypt(&mut rt);
            assert_eq!(rt, plain, "round-trip mismatch for {:?}", chunks);
        }
    }

    /// Verify that CipherReader round-trips correctly when reading in small chunks
    /// that force multiple poll_read calls, exercising the zero-copy decrypt path.
    #[tokio::test]
    async fn cipher_reader_zero_copy_small_chunks() {
        let (client, server) = duplex(64 * 1024);
        let mut writer = CipherWriter::new(client, TEST_KEY);
        let mut reader = CipherReader::new(server, TEST_KEY);

        // Varied (non-uniform) plaintext so any byte-reorder/CFB-offset bug in
        // the in-place decrypt surfaces as a mismatch, not a silent pass.
        let data: Vec<u8> = (0..4096).map(|i| (i % 251) as u8).collect();
        let expected = data.clone();

        let write_handle = tokio::spawn(async move {
            writer.write_all(&data).await.unwrap();
            writer.shutdown().await.unwrap();
        });

        // Read in very small chunks (1 byte at a time) to force multiple
        // poll_read calls across the zero-copy decrypt path.
        let mut buf = vec![0u8; expected.len()];
        let mut off = 0;
        while off < expected.len() {
            let n = reader.read(&mut buf[off..off + 1]).await.unwrap();
            if n == 0 {
                break;
            }
            off += n;
        }
        assert_eq!(off, expected.len(), "short read");
        assert_eq!(buf, expected, "zero-copy small-chunk round-trip mismatch");

        write_handle.await.unwrap();
    }

    /// Directly exercise the `filled < inner_slice.len()` partial-fill case:
    /// the reader offers a large buffer while the writer flushes small chunks
    /// with delays, so each poll_read fills only part of the initialized
    /// unfilled region. Asserts `advance(filled)` commits exactly the decrypted
    /// bytes in order across many partial polls.
    #[tokio::test]
    async fn cipher_reader_zero_copy_partial_fill() {
        let (client, server) = duplex(64 * 1024);
        let mut writer = CipherWriter::new(client, TEST_KEY);
        let mut reader = CipherReader::new(server, TEST_KEY);

        let total = 8192usize;
        let data: Vec<u8> = (0..total).map(|i| (i % 251) as u8).collect();
        let expected = data.clone();

        // Writer flushes in 137-byte chunks with a yield between each, so the
        // reader's large-buffer reads observe short inner deliveries.
        let write_handle = tokio::spawn(async move {
            for chunk in data.chunks(137) {
                writer.write_all(chunk).await.unwrap();
                writer.flush().await.unwrap();
                tokio::task::yield_now().await;
            }
            writer.shutdown().await.unwrap();
        });

        // Read into a large buffer each call; inner deliveries are short, so
        // filled < buf.remaining() on essentially every poll.
        let mut got = Vec::with_capacity(total);
        let mut buf = vec![0u8; total];
        loop {
            let n = reader.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
        }
        assert_eq!(got.len(), total, "short read on partial-fill path");
        assert_eq!(got, expected, "zero-copy partial-fill round-trip mismatch");

        write_handle.await.unwrap();
    }

    /// Verify that CipherReader handles EOF correctly on the zero-copy path
    /// (inner reader returns 0 bytes after IV).
    #[tokio::test]
    async fn cipher_reader_zero_copy_eof_after_iv() {
        // Write IV only, then close — CipherReader should see 0 bytes from
        // the inner reader on the first decrypt call.
        let (client, server) = duplex(1024);
        let mut writer = CipherWriter::new(client, TEST_KEY);
        // Flush sends IV, then drop the writer closes the stream.
        writer.flush().await.unwrap();
        drop(writer);

        let mut reader = CipherReader::new(server, TEST_KEY);
        let mut buf = [0u8; 64];
        let n = reader.read(&mut buf).await.unwrap();
        assert_eq!(n, 0, "should get EOF after IV with no data");
    }

    /// Peer closes after writing only PART of the 16-byte IV: the read must
    /// return UnexpectedEof — not hang, and not decrypt with a partial IV.
    #[tokio::test]
    async fn eof_mid_iv_returns_unexpected_eof() {
        let (mut client, server) = duplex(1024);
        // Write 5 of the 16 IV bytes, then close.
        client.write_all(&[0xABu8; 5]).await.unwrap();
        drop(client);

        let mut reader = CipherReader::new(server, TEST_KEY);
        let mut buf = [0u8; 64];
        let err = reader.read(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
        assert!(
            err.to_string().contains("EOF while reading IV"),
            "unexpected error: {err}"
        );
    }

    /// Same EOF-mid-IV contract for the combined CipherStream reader.
    #[tokio::test]
    async fn cipher_stream_eof_mid_iv_returns_unexpected_eof() {
        let (mut client, server) = duplex(1024);
        client.write_all(&[0xCDu8; 5]).await.unwrap();
        drop(client);

        let mut stream = CipherStream::new(server, TEST_KEY);
        let mut buf = [0u8; 64];
        let err = stream.read(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
        assert!(
            err.to_string().contains("EOF while reading IV"),
            "unexpected error: {err}"
        );
    }

    /// Verify that the scratch buffer is reused across multiple sequential writes,
    /// producing correct round-trip decryption for each chunk and the concatenated result.
    #[tokio::test]
    async fn cipher_writer_scratch_reuse_roundtrip() {
        let (client, server) = duplex(128 * 1024);
        let mut writer = CipherWriter::new(client, TEST_KEY);
        let mut reader = CipherReader::new(server, TEST_KEY);

        let chunks: &[&[u8]] = &[
            b"first chunk of data ",
            b"second chunk follows ",
            b"third and final chunk",
        ];

        // Write all chunks sequentially through the same CipherWriter,
        // exercising scratch reuse on every write after the first (which
        // goes through first_write_buf).
        for chunk in chunks {
            writer.write_all(chunk).await.unwrap();
        }
        writer.shutdown().await.unwrap();

        // Read and verify the concatenated plaintext.
        let total: usize = chunks.iter().map(|c| c.len()).sum();
        let mut buf = vec![0u8; total];
        reader.read_exact(&mut buf).await.unwrap();
        let expected: Vec<u8> = chunks.concat();
        assert_eq!(buf, expected, "scratch-reuse round-trip mismatch");
    }

    #[tokio::test]
    async fn cipher_writer_write_encrypted_roundtrip() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (client, server) = tokio::io::duplex(4096);
        let key = [0xABu8; 16];
        let mut writer = CipherWriter::new(client, key);
        let mut reader = CipherReader::new(server, key);

        let mut plaintext = b"hello world encrypted in-place".to_vec();
        let expected = plaintext.clone();

        // write_encrypted sends IV then encrypts in-place
        writer.write_encrypted(&mut plaintext).await.unwrap();
        // plaintext is now ciphertext — verify it changed
        assert_ne!(
            &plaintext, &expected,
            "plaintext should be encrypted in-place"
        );
        writer.inner.shutdown().await.unwrap();

        let mut decrypted = vec![0u8; expected.len()];
        reader.read_exact(&mut decrypted).await.unwrap();
        assert_eq!(&decrypted, &expected, "roundtrip should recover original");
    }
}
