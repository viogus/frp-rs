use ssh_key::PrivateKey;

use crate::keys::Error;

/// Decode a secret key given in the OpenSSH format, deciphering it if
/// needed using the supplied password.
///
/// frp-rs patch: encrypted-key decryption is removed. Upstream russh calls
/// `PrivateKey::decrypt(password)` for passphrase-protected OpenSSH keys,
/// which pulls ssh-key's `encryption` feature (bcrypt-pbkdf + ssh-cipher's
/// aes-gcm/chacha20poly1305). frp-rs loads only unencrypted host keys (its
/// SSH gateway calls `load_secret_key(path, None)`), so the decrypt path is
/// dead code. Encrypted keys now return `Error::KeyIsEncrypted` regardless
/// of the supplied password.
pub fn decode_openssh(secret: &[u8], _password: Option<&str>) -> Result<PrivateKey, Error> {
    let pk = PrivateKey::from_bytes(secret)?;
    if pk.is_encrypted() {
        return Err(Error::KeyIsEncrypted);
    }
    Ok(pk)
}
