//! Minimal base64 (RFC 4648, standard alphabet with `=` padding).
//!
//! Inline replacement for the `data-encoding` crate (~47KB of `.text` in
//! frps). This module provides only what the codebase uses: encode and
//! decode with the standard `A-Za-z0-9+/` alphabet. No streaming, no
//! configurable alphabets, no line wrapping.
//!
//! Wire-compatible with Go's `base64.StdEncoding`, which is what Go frp
//! uses for V2 handshake fields (`ClientHello.serverRandom` etc.) and
//! `VnetPacket.data`.

use std::fmt;

const ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Decode failures for [`decode`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Base64Error {
    /// Input length is not a multiple of 4.
    InvalidLength(usize),
    /// A character outside the standard alphabet, or `=` in a data position.
    InvalidChar(usize),
    /// `=` padding in a non-terminal position.
    InvalidPadding(usize),
}

impl fmt::Display for Base64Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Base64Error::InvalidLength(len) => write!(
                f,
                "invalid base64 length: {len} (must be a multiple of 4)"
            ),
            Base64Error::InvalidChar(pos) => {
                write!(f, "invalid base64 character at byte {pos}")
            }
            Base64Error::InvalidPadding(pos) => {
                write!(f, "invalid base64 padding at byte {pos}")
            }
        }
    }
}

impl std::error::Error for Base64Error {}

/// Encode `data` as base64 with the standard alphabet and `=` padding.
pub fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    let mut chunks = data.chunks_exact(3);
    for chunk in &mut chunks {
        let b0 = chunk[0];
        let b1 = chunk[1];
        let b2 = chunk[2];
        out.push(ALPHABET[(b0 >> 2) as usize] as char);
        out.push(ALPHABET[((b0 & 0x03) << 4 | b1 >> 4) as usize] as char);
        out.push(ALPHABET[((b1 & 0x0f) << 2 | b2 >> 6) as usize] as char);
        out.push(ALPHABET[(b2 & 0x3f) as usize] as char);
    }
    match chunks.remainder() {
        [] => {}
        [b0] => {
            out.push(ALPHABET[(b0 >> 2) as usize] as char);
            out.push(ALPHABET[((b0 & 0x03) << 4) as usize] as char);
            out.push('=');
            out.push('=');
        }
        [b0, b1] => {
            out.push(ALPHABET[(b0 >> 2) as usize] as char);
            out.push(ALPHABET[((b0 & 0x03) << 4 | b1 >> 4) as usize] as char);
            out.push(ALPHABET[((b1 & 0x0f) << 2) as usize] as char);
            out.push('=');
        }
        _ => unreachable!("chunks_exact remainder has at most 2 bytes"),
    }
    out
}

fn decode_char(c: u8, pos: usize) -> Result<u8, Base64Error> {
    match c {
        b'A'..=b'Z' => Ok(c - b'A'),
        b'a'..=b'z' => Ok(c - b'a' + 26),
        b'0'..=b'9' => Ok(c - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        _ => Err(Base64Error::InvalidChar(pos)),
    }
}

/// Decode standard-alphabet base64 (padding required, as produced by
/// [`encode`] and by Go's `base64.StdEncoding`).
pub fn decode(input: &str) -> Result<Vec<u8>, Base64Error> {
    let bytes = input.as_bytes();
    if bytes.len() % 4 != 0 {
        return Err(Base64Error::InvalidLength(bytes.len()));
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let mut i = 0;
    while i < bytes.len() {
        let c0 = decode_char(bytes[i], i)?;
        let c1 = decode_char(bytes[i + 1], i + 1)?;
        let c2 = bytes[i + 2];
        let c3 = bytes[i + 3];
        match (c2, c3) {
            (b'=', b'=') => {
                out.push((c0 << 2) | (c1 >> 4));
            }
            (b'=', _) => return Err(Base64Error::InvalidPadding(i + 2)),
            (_, b'=') => {
                let c2 = decode_char(c2, i + 2)?;
                out.push((c0 << 2) | (c1 >> 4));
                out.push(((c1 & 0x0f) << 4) | (c2 >> 2));
            }
            (_, _) => {
                let c2 = decode_char(c2, i + 2)?;
                let c3 = decode_char(c3, i + 3)?;
                out.push((c0 << 2) | (c1 >> 4));
                out.push(((c1 & 0x0f) << 4) | (c2 >> 2));
                out.push(((c2 & 0x03) << 6) | c3);
            }
        }
        i += 4;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 4648 section 10 test vectors.
    #[test]
    fn test_encode_vectors() {
        assert_eq!(encode(b""), "");
        assert_eq!(encode(b"f"), "Zg==");
        assert_eq!(encode(b"fo"), "Zm8=");
        assert_eq!(encode(b"foo"), "Zm9v");
        assert_eq!(encode(b"foob"), "Zm9vYg==");
        assert_eq!(encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(encode(b"foobar"), "Zm9vYmFy");
        // Full 64-char alphabet sweep: bytes 0..255 → 4 groups × 64 symbols.
        let all: Vec<u8> = (0..=255).collect();
        assert_eq!(decode(&encode(&all)).unwrap(), all);
    }

    #[test]
    fn test_roundtrip() {
        for len in 0..=66 {
            let data: Vec<u8> = (0..len as u8).cycle().take(len).collect();
            assert_eq!(decode(&encode(&data)).unwrap(), data, "len {len}");
        }
    }

    #[test]
    fn test_decode_errors() {
        assert_eq!(decode("a"), Err(Base64Error::InvalidLength(1)));
        assert_eq!(decode("abcd"), Ok(b"\x69\xb7\x1d".to_vec()));
        assert!(decode("ab!d").is_err()); // invalid char
        assert_eq!(decode("ab=d"), Err(Base64Error::InvalidPadding(2)));
        assert_eq!(decode("a=d="), Err(Base64Error::InvalidChar(1)));
        assert!(decode("====").is_err());
        assert_eq!(decode("aGVsbG8=").unwrap(), b"hello");
        assert_eq!(decode("aGVsbG8").is_err(), true); // wrong length
    }
}
