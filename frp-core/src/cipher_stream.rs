//! AES-128-CFB streaming cipher for control connection and bridge encryption.
//!
//! Matches Go frp v0.69.1 `libcrypto.NewReader` / `libcrypto.NewWriter` behavior.
//! Each direction has its own random 16-byte IV. Cipher state is continuous.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;

pub trait AsyncReadWriteUnpin: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncReadWriteUnpin for T {}

/// Streaming AES-128-CFB decrypting reader.
///
/// Reads 16-byte IV on first read, then decrypts all subsequent reads with
/// continuous CFB state. Matches Go frp `crypto.NewReader`.
pub struct CipherReader<R: AsyncRead + Unpin> {
    inner: R,
    state: ReadState,
    key: [u8; 16],
}

impl<R: AsyncRead + Unpin> CipherReader<R> {
    pub fn new(inner: R, key: [u8; 16]) -> Self {
        Self {
            inner,
            key,
            state: ReadState::ReadingIv { buf: [0u8; 16], filled: 0 },
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
        loop {
            match &mut this.state {
                ReadState::Decrypting { cfb } => {
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
                            return Poll::Ready(Ok(()));
                        }
                        other => return other,
                    }
                }
                ReadState::ReadingIv { buf: iv_buf, filled } => {
                    let mut tmp = ReadBuf::new(&mut iv_buf[*filled..]);
                    match Pin::new(&mut this.inner).poll_read(cx, &mut tmp) {
                        Poll::Ready(Ok(())) => {
                            let n = tmp.filled().len();
                            if n == 0 {
                                // Stream closed before IV could be read
                                return Poll::Ready(Ok(()));
                            }
                            *filled += n;
                            if *filled == 16 {
                                let cfb = CfbState::new(&this.key, iv_buf);
                                this.state = ReadState::Decrypting { cfb: Box::new(cfb) };
                            }
                            continue;
                        }
                        other => return other,
                    }
                }
            }
        }
    }
}

/// Streaming AES-128-CFB encrypting writer.
///
/// Writes 16-byte random IV on first write, then encrypts all subsequent
/// writes with continuous CFB state. Matches Go frp `crypto.NewWriter`.
pub struct CipherWriter<W: AsyncWrite + Unpin> {
    inner: W,
    state: WriteState,
    key: [u8; 16],
}

impl<W: AsyncWrite + Unpin> CipherWriter<W> {
    pub fn new(inner: W, key: [u8; 16]) -> Self {
        Self {
            inner,
            key,
            state: WriteState::Writing { buf: Vec::new(), pos: 0, cfb: None, buf_consumed: 0 },
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
        match &mut this.state {
            WriteState::Encrypting { cfb, pending, pos } => {
                // If no pending data, encrypt the new buf
                if pending.is_empty() {
                    let mut encrypted = buf.to_vec();
                    cfb.encrypt(&mut encrypted);
                    *pending = encrypted;
                    *pos = 0;
                }
                match Pin::new(&mut this.inner).poll_write(cx, &pending[*pos..]) {
                    Poll::Ready(Ok(n)) => {
                        *pos += n;
                        let consumed = n;
                        if *pos >= pending.len() {
                            pending.clear();
                            *pos = 0;
                        }
                        Poll::Ready(Ok(consumed))
                    }
                    other => other,
                }
            }
            WriteState::Writing { buf: wbuf, pos, cfb: saved_cfb, buf_consumed } => {
                // First write: generate IV, encrypt data, write IV+data as one buffer.
                if wbuf.is_empty() {
                    use rand::RngCore;
                    let mut iv = [0u8; 16];
                    rand::rngs::OsRng.fill_bytes(&mut iv);
                    let mut cfb = CfbState::new(&this.key, &iv);
                    let mut encrypted = buf.to_vec();
                    cfb.encrypt(&mut encrypted);
                    *wbuf = iv.to_vec();
                    wbuf.extend_from_slice(&encrypted);
                    *pos = 0;
                    *buf_consumed = 0;
                    *saved_cfb = Some(cfb);
                }
                // Flush the combined buffer
                match Pin::new(&mut this.inner).poll_write(cx, &wbuf[*pos..]) {
                    Poll::Ready(Ok(n)) => {
                        *pos += n;
                        // Calculate how many bytes of the original caller buf
                        // have been flushed: after 16-byte IV, remaining bytes are encrypted(buf)
                        let total_consumed = if *pos <= 16 {
                            0
                        } else {
                            (*pos - 16).min(buf.len())
                        };
                        let incremental = total_consumed.saturating_sub(*buf_consumed);
                        *buf_consumed = total_consumed;
                        if *pos >= wbuf.len() {
                            let cfb = saved_cfb.take().expect("cfb must be set after first write");
                            this.state = WriteState::Encrypting { cfb, pending: Vec::new(), pos: 0 };
                        }
                        // If inner writer made progress but no caller bytes consumed yet
                        // (still flushing IV prefix), signal Pending to avoid Ok(0) which
                        // tokio's write_all/copy_buf treats as "write side closed".
                        if n > 0 && incremental == 0 {
                            cx.waker().wake_by_ref();
                            Poll::Pending
                        } else {
                            Poll::Ready(Ok(incremental))
                        }
                    }
                    other => other,
                }
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // SAFETY: W: Unpin guarantees we can project through Pin to access
        // `state` and `inner` fields. No moves occur — only field mutation.
        let this = unsafe { self.as_mut().get_unchecked_mut() };

        // If still in initial Writing state with no buffered data, generate
        // and flush the IV eagerly. This prevents a deadlock when both sides
        // of a connection create CipherWriter/CipherReader pairs: each side's
        // CipherReader blocks waiting for the other side's IV, but neither
        // CipherWriter sends its IV until user data arrives.
        if let WriteState::Writing { buf: wbuf, pos, cfb: saved_cfb, buf_consumed } = &mut this.state {
            if wbuf.is_empty() {
                use rand::RngCore;
                let mut iv = [0u8; 16];
                rand::rngs::OsRng.fill_bytes(&mut iv);
                let cfb_state = CfbState::new(&this.key, &iv);
                *wbuf = iv.to_vec();
                *pos = 0;
                *buf_consumed = 0;
                *saved_cfb = Some(cfb_state);
            }
            // Write the IV buffer to the inner writer
            match Pin::new(&mut this.inner).poll_write(cx, &wbuf[*pos..]) {
                Poll::Ready(Ok(n)) => {
                    *pos += n;
                    if *pos >= wbuf.len() {
                        let cfb = saved_cfb.take().expect("cfb must be set after IV generation");
                        this.state = WriteState::Encrypting { cfb, pending: Vec::new(), pos: 0 };
                        // IV fully flushed — now flush inner writer
                        return Pin::new(&mut this.inner).poll_flush(cx);
                    }
                    // IV partially written, wake and retry
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending,
            }
        } else {
            Pin::new(&mut this.inner).poll_flush(cx)
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

struct CfbState {
    cipher: Aes128,
    feedback: [u8; 16],
    offset: usize,
}

impl CfbState {
    fn new(key: &[u8; 16], iv: &[u8; 16]) -> Self {
        let cipher = Aes128::new_from_slice(key).expect("AES-128 key");
        let mut feedback = [0u8; 16];
        feedback.copy_from_slice(iv);
        cipher.encrypt_block((&mut feedback).into());
        Self { cipher, feedback, offset: 0 }
    }

    fn encrypt(&mut self, data: &mut [u8]) {
        for byte in data.iter_mut() {
            if self.offset == 16 {
                self.cipher.encrypt_block((&mut self.feedback).into());
                self.offset = 0;
            }
            *byte ^= self.feedback[self.offset];
            self.feedback[self.offset] = *byte;
            self.offset += 1;
        }
    }

    fn decrypt(&mut self, data: &mut [u8]) {
        for byte in data.iter_mut() {
            if self.offset == 16 {
                self.cipher.encrypt_block((&mut self.feedback).into());
                self.offset = 0;
            }
            let ct = *byte;
            *byte ^= self.feedback[self.offset];
            self.feedback[self.offset] = ct;
            self.offset += 1;
        }
    }
}

enum ReadState {
    ReadingIv { buf: [u8; 16], filled: usize },
    Decrypting { cfb: Box<CfbState> },
}

enum WriteState {
    Writing { buf: Vec<u8>, pos: usize, cfb: Option<CfbState>, buf_consumed: usize },
    Encrypting { cfb: CfbState, pending: Vec<u8>, pos: usize },
}

pub struct CipherStream {
    inner: Box<dyn AsyncReadWriteUnpin>,
    read_state: ReadState,
    write_state: WriteState,
    key: [u8; 16],
}

impl CipherStream {
    pub fn new(inner: Box<dyn AsyncReadWriteUnpin>, key: [u8; 16]) -> Self {
        Self {
            inner,
            key,
            read_state: ReadState::ReadingIv { buf: [0u8; 16], filled: 0 },
            write_state: WriteState::Writing { buf: Vec::new(), pos: 0, cfb: None, buf_consumed: 0 },
        }
    }
}

impl AsyncRead for CipherStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        loop {
            match &mut this.read_state {
                ReadState::Decrypting { cfb } => {
                    let needed = buf.remaining();
                    let mut tmp = vec![0u8; needed];
                    let mut tmp_buf = ReadBuf::new(&mut tmp);
                    let pin = Pin::new(&mut *this.inner);
                    match pin.poll_read(cx, &mut tmp_buf) {
                        Poll::Ready(Ok(())) => {
                            let filled = tmp_buf.filled().len();
                            if filled > 0 {
                                cfb.decrypt(&mut tmp[..filled]);
                                buf.put_slice(&tmp[..filled]);
                            }
                            return Poll::Ready(Ok(()));
                        }
                        other => return other,
                    }
                }
                ReadState::ReadingIv { buf: iv_buf, filled } => {
                    let pin = Pin::new(&mut *this.inner);
                    let mut tmp = ReadBuf::new(&mut iv_buf[*filled..]);
                    match pin.poll_read(cx, &mut tmp) {
                        Poll::Ready(Ok(())) => {
                            let n = tmp.filled().len();
                            if n == 0 {
                                // Stream closed before IV could be read
                                return Poll::Ready(Ok(()));
                            }
                            *filled += n;
                            if *filled == 16 {
                                let cfb = CfbState::new(&this.key, iv_buf);
                                this.read_state = ReadState::Decrypting { cfb: Box::new(cfb) };
                            }
                            continue;
                        }
                        other => return other,
                    }
                }
            }
        }
    }
}

impl AsyncWrite for CipherStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        match &mut this.write_state {
            WriteState::Encrypting { cfb, pending, pos } => {
                // If no pending data, encrypt the new buf
                if pending.is_empty() {
                    let mut encrypted = buf.to_vec();
                    cfb.encrypt(&mut encrypted);
                    *pending = encrypted;
                    *pos = 0;
                }
                let pin = Pin::new(&mut *this.inner);
                match pin.poll_write(cx, &pending[*pos..]) {
                    Poll::Ready(Ok(n)) => {
                        *pos += n;
                        let consumed = n;
                        if *pos >= pending.len() {
                            pending.clear();
                            *pos = 0;
                        }
                        Poll::Ready(Ok(consumed))
                    }
                    other => other,
                }
            }
            WriteState::Writing { buf: wbuf, pos, cfb: saved_cfb, buf_consumed } => {
                // First write: generate IV, encrypt data, write IV+data as one buffer.
                if wbuf.is_empty() {
                    use rand::RngCore;
                    let mut iv = [0u8; 16];
                    rand::rngs::OsRng.fill_bytes(&mut iv);
                    let mut cfb = CfbState::new(&this.key, &iv);
                    let mut encrypted = buf.to_vec();
                    cfb.encrypt(&mut encrypted);
                    *wbuf = iv.to_vec();
                    wbuf.extend_from_slice(&encrypted);
                    *pos = 0;
                    *buf_consumed = 0;
                    *saved_cfb = Some(cfb);
                }
                // Flush the combined buffer
                let pin = Pin::new(&mut *this.inner);
                match pin.poll_write(cx, &wbuf[*pos..]) {
                    Poll::Ready(Ok(n)) => {
                        *pos += n;
                        // Calculate how many bytes of the original caller buf
                        // have been flushed: after 16-byte IV, remaining bytes are encrypted(buf)
                        let total_consumed = if *pos <= 16 {
                            0
                        } else {
                            (*pos - 16).min(buf.len())
                        };
                        let incremental = total_consumed.saturating_sub(*buf_consumed);
                        *buf_consumed = total_consumed;
                        if *pos >= wbuf.len() {
                            let cfb = saved_cfb.take().expect("cfb must be set after first write");
                            this.write_state = WriteState::Encrypting { cfb, pending: Vec::new(), pos: 0 };
                        }
                        if n > 0 && incremental == 0 {
                            cx.waker().wake_by_ref();
                            Poll::Pending
                        } else {
                            Poll::Ready(Ok(incremental))
                        }
                    }
                    other => other,
                }
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cfb_self_roundtrip() {
        let key = [0xABu8; 16];
        let iv = [0xCDu8; 16];
        let plaintext = b"Hello, World! This is a test of CFB encryption.";

        let mut enc = CfbState::new(&key, &iv);
        let mut encrypted = plaintext.to_vec();
        enc.encrypt(&mut encrypted);

        let mut dec = CfbState::new(&key, &iv);
        let mut decrypted = encrypted.clone();
        dec.decrypt(&mut decrypted);

        assert_eq!(plaintext, decrypted.as_slice());
        assert_ne!(plaintext, encrypted.as_slice());
    }

    #[test]
    fn test_cfb_vs_standard_crate() {
        // Verify our CfbState matches cfb_mode crate's Encryptor
        use cfb_mode::cipher::{AsyncStreamCipher, KeyIvInit};
        use aes::Aes128;

        let key = [0x12u8; 16];
        let iv = [0x34u8; 16];
        let plaintext = b"test data for cfb";

        // Our implementation
        let mut our_cfb = CfbState::new(&key, &iv);
        let mut our_enc = plaintext.to_vec();
        our_cfb.encrypt(&mut our_enc);

        // Standard crate implementation
        let std_enc = cfb_mode::Encryptor::<Aes128>::new((&key).into(), (&iv).into());
        let mut std_encrypted = plaintext.to_vec();
        std_enc.encrypt(&mut std_encrypted);

        assert_eq!(our_enc, std_encrypted, "Our CFB encryption must match standard crate");
    }
}

    #[test]
    fn test_key_derivation_matches_go() {
        let token = "cc12122121212121212112565656CCtzT";
        let key = crate::encryption::derive_key(token);
        eprintln!("Key: {}", hex::encode(key));
        // Expected from Go (salt="frp"): 004bc8379ee00e3d0c9eb0953c0b212c
        assert_eq!(hex::encode(key), "004bc8379ee00e3d0c9eb0953c0b212c");
    }

    #[test]
    fn test_cfb_matches_go() {
        let token = "cc12122121212121212112565656CCtzT";
        let key = crate::encryption::derive_key(token);
        let iv = [0x01u8,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10];
        let plain = [0x70u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x49, 0x7b, 0x22, 0x70, 0x72, 0x6f, 0x78, 0x79];

        let mut cfb = CfbState::new(&key, &iv);
        let mut ciphertext = plain.to_vec();
        cfb.encrypt(&mut ciphertext);
        eprintln!("Ciphertext: {}", hex::encode(&ciphertext));
        // Expected from Go (salt="frp"): d0710014c7af8e001ea6bfb27e97e1f7
        assert_eq!(hex::encode(&ciphertext), "d0710014c7af8e001ea6bfb27e97e1f7");
    }

    #[tokio::test]
    async fn test_cipher_stream_roundtrip() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        
        let token = "cc12122121212121212112565656CCtzT";
        let key = crate::encryption::derive_key(token);
        
        // Create a pair of connected streams (simulating TCP)
        let (client_side, server_side) = tokio::io::duplex(4096);
        
        // Client wraps its side in CipherStream
        let mut client = CipherStream::new(
            Box::new(client_side),
            key,
        );
        
        // Server also wraps its side in CipherStream  
        let mut server = CipherStream::new(
            Box::new(server_side),
            key,
        );
        
        // Client writes NewProxy V1 frame
        let np_json = b"{\"proxy_name\":\"test\",\"proxy_type\":\"tcp\",\"remote_port\":10081}";
        let np_len = np_json.len() as u64;
        let mut v1_frame = Vec::new();
        v1_frame.push(0x70u8); // NewProxy type
        v1_frame.extend_from_slice(&np_len.to_be_bytes());
        v1_frame.extend_from_slice(np_json);
        
        // Write through CipherStream (encrypts)
        client.write_all(&v1_frame).await.unwrap();
        client.flush().await.unwrap();
        
        // Read through server's CipherStream (decrypts)
        let mut decrypted = vec![0u8; v1_frame.len()];
        server.read_exact(&mut decrypted).await.unwrap();
        
        eprintln!("Original: {}", hex::encode(&v1_frame));
        eprintln!("Decrypted: {}", hex::encode(&decrypted));
        assert_eq!(decrypted, v1_frame, "Round-trip failed!");
        
        // Second message (PING)
        let ping = b"h\x00\x00\x00\x00\x00\x00\x00\x04ping";
        client.write_all(ping).await.unwrap();
        client.flush().await.unwrap();
        
        let mut decrypted2 = vec![0u8; ping.len()];
        server.read_exact(&mut decrypted2).await.unwrap();
        
        eprintln!("Ping decrypted: {}", hex::encode(&decrypted2));
        assert_eq!(decrypted2, ping, "Second message round-trip failed!");
    }

#[cfg(test)]
mod go_interop_tests {
    use tokio::io::AsyncReadExt;
    
    #[tokio::test]
    async fn test_decrypt_go_format() {
        // Verify CipherReader can decrypt data in Go frp format:
        //   [16-byte random IV][CFB-encrypted V1 frame]
        // Key: PBKDF2-SHA1(token="enc-test-token-2024", salt="crypto", 64, 16)
        //   = a58f5b6761113b3aee79551cac8842c0
        let token = "enc-test-token-2024";
        let key = crate::encryption::derive_key(token);
        assert_eq!(hex::encode(key), "c78f3c47ae07c8dade6c6a76009db8cf");

        // Pre-computed: [IV=965be112...][CFB-ct of NewProxy V1 frame] (salt="frp")
        let wire = hex::decode(
            "965be1126c68f86001726011ba25e3b8\
             084e5968c0dd229c6543b0dfc928a237d93a7f814343ba693cc61661f7f59121\
             74e889a0b1d6c8afe88c7e60802fcec10dd7d41b8551addd938681e1dcb84941\
             f7f8f46671d745200c"
        ).unwrap();

        // Expected plaintext: V1 NewProxy frame
        let np_json = b"{\"proxy_name\":\"enc-echo\",\"proxy_type\":\"tcp\",\"remote_port\":19902}";
        let np_len = np_json.len() as u64;
        let mut expected = Vec::new();
        expected.push(0x70u8);
        expected.extend_from_slice(&np_len.to_be_bytes());
        expected.extend_from_slice(np_json);

        let mut reader = crate::cipher_stream::CipherReader::new(wire.as_slice(), key);
        let mut decrypted = vec![0u8; expected.len()];
        reader.read_exact(&mut decrypted).await.unwrap();

        assert_eq!(decrypted, expected, "Go-format CFB decryption must produce correct V1 frame");
    }
}
