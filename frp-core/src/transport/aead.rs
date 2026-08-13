//! AEAD encrypted transport: [`AeadStream`] (AES-256-GCM or
//! XChaCha20-Poly1305 V2 control stream) implements [`Transport`].

use std::io;

use crate::crypto::AeadStream;

use super::Transport;

impl Transport for AeadStream {
    fn debug_name(&self) -> &'static str {
        "IoStream::Aead"
    }
    fn into_encrypted(self: Box<Self>, _key: [u8; 16]) -> io::Result<Box<dyn Transport>> {
        // Already AEAD-encrypted (V2 with crypto). Don't double-wrap.
        Ok(self)
    }
    fn bridge_split_err(&self) -> Option<&'static str> {
        Some("Aead stream unexpected in bridge")
    }
}
