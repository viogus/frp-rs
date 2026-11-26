use ssh_key::PrivateKey;

use super::Encryption;
use crate::keys::Error;

/// Decode a secret key in the PKCS#5 format.
///
/// frp-rs vendored patch: legacy OpenSSL `DEK-Info` encrypted PEM keys are
/// never loaded by the frp-rs SSH gateway (consistent with Patch 1/2 in
/// `openssh.rs` and `pkcs8.rs`). Reject unconditionally so the duplicate
/// `md5 0.8` dependency is not required.
pub fn decode_pkcs5(
    _secret: &[u8],
    _password: Option<&str>,
    _enc: Encryption,
) -> Result<PrivateKey, Error> {
    Err(Error::KeyIsEncrypted)
}
