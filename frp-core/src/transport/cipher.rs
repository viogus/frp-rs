//! AES-128-CFB encrypted transport: [`CipherStream`] implements
//! [`Transport`] for any wrapped inner transport.

use std::io;

use tokio::io::{AsyncRead, AsyncWrite};

use crate::cipher_stream::CipherStream;

use super::Transport;

impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> Transport for CipherStream<S> {
    fn debug_name(&self) -> &'static str {
        "IoStream::Cipher"
    }
    fn into_encrypted(self: Box<Self>, _key: [u8; 16]) -> io::Result<Box<dyn Transport>> {
        // A Cipher stream is never re-encrypted in practice (into_encrypted
        // runs on the freshly-dialed login stream); returning self unchanged
        // also keeps the blanket `Transport for CipherStream<S>` from
        // recursing through the default wrap.
        Ok(self)
    }
    fn bridge_split_err(&self) -> Option<&'static str> {
        Some("Cipher stream unexpected in bridge")
    }
}
