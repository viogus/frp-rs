use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Generate a token for authentication using HMAC-SHA256.
/// The message is typically the timestamp as a string.
pub fn generate_token(token: &str, timestamp: i64) -> String {
    let mut mac = HmacSha256::new_from_slice(token.as_bytes())
        .expect("HMAC can take key of any size");
    mac.update(timestamp.to_string().as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Verify a token against a known secret and timestamp.
pub fn verify_token(token: &str, timestamp: i64, expected_hex: &str) -> bool {
    let computed = generate_token(token, timestamp);
    // Constant-time comparison
    computed.len() == expected_hex.len()
        && computed
            .as_bytes()
            .iter()
            .zip(expected_hex.as_bytes())
            .all(|(a, b)| a == b)
}

/// Authentication configuration.
#[derive(Debug, Clone)]
pub struct AuthConfig {
    pub method: AuthMethod,
    pub token: String,
    pub additional_data: Option<String>,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            method: AuthMethod::Token,
            token: String::new(),
            additional_data: None,
        }
    }
}

/// Supported authentication methods.
#[derive(Debug, Clone, PartialEq)]
pub enum AuthMethod {
    Token,
    Oidc,
}

impl AuthConfig {
    /// Validate a login attempt. Returns Ok(()) if valid, Err with reason if invalid.
    pub fn validate_login(&self, privilege_key: Option<&str>, timestamp: Option<i64>) -> Result<(), String> {
        if self.token.is_empty() {
            // No token configured: always allow
            return Ok(());
        }

        let key = privilege_key.unwrap_or("");
        let ts = timestamp.unwrap_or(0);

        match self.method {
            AuthMethod::Token => {
                let expected = generate_token(&self.token, ts);
                if key != expected {
                    return Err("invalid authentication token".into());
                }
                Ok(())
            }
            AuthMethod::Oidc => Err("OIDC auth not implemented in Rust frp".into()),
        }
    }

    /// Generate the privilege_key for a login message.
    pub fn generate_login_key(&self, timestamp: i64) -> Option<String> {
        if self.token.is_empty() {
            return None;
        }
        match self.method {
            AuthMethod::Token => Some(generate_token(&self.token, timestamp)),
            AuthMethod::Oidc => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_gen_and_verify() {
        let token = "my-secret-token";
        let ts = 1234567890i64;
        let gen = generate_token(token, ts);
        assert!(verify_token(token, ts, &gen));
        assert!(!verify_token(token, ts + 1, &gen));
    }

    #[test]
    fn test_auth_config_validate() {
        let cfg = AuthConfig {
            method: AuthMethod::Token,
            token: "secret".into(),
            additional_data: None,
        };
        let ts = 100i64;
        let key = generate_token("secret", ts);
        assert!(cfg.validate_login(Some(&key), Some(ts)).is_ok());
        assert!(cfg.validate_login(Some(&key), Some(ts + 1)).is_err());
        assert!(cfg.validate_login(Some("wrong"), Some(ts)).is_err());

        let empty_cfg = AuthConfig::default();
        assert!(empty_cfg.validate_login(None, None).is_ok());
    }
}
