use md5::{Md5, Digest};

/// Generate a token for authentication using MD5 (matching Go frp v0.69.1).
/// The message is typically the timestamp as a string.
pub fn generate_token(token: &str, timestamp: i64) -> String {
    let mut hasher = Md5::new();
    hasher.update(token.as_bytes());
    hasher.update(timestamp.to_string().as_bytes());
    hex::encode(hasher.finalize())
}

/// Verify a token against a known secret and timestamp.
pub fn verify_token(token: &str, timestamp: i64, expected_hex: &str) -> bool {
    generate_token(token, timestamp) == expected_hex
}

/// Authentication configuration.
#[derive(Debug, Clone)]
pub struct AuthConfig {
    pub method: AuthMethod,
    pub token: String,
    pub oidc_issuer: String,
    pub oidc_audience: String,
    pub oidc_skip_expiry: bool,
    pub oidc_skip_issuer: bool,
    pub additional_data: Option<String>,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            method: AuthMethod::Token,
            token: String::new(),
            oidc_issuer: String::new(),
            oidc_audience: String::new(),
            oidc_skip_expiry: false,
            oidc_skip_issuer: false,
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
    /// Validate a login attempt. Returns the subject string (empty for token
    /// auth, populated from JWT 'sub' claim for OIDC). Returns Err if invalid.
    pub fn validate_login(&self, privilege_key: Option<&str>, timestamp: Option<i64>) -> Result<String, String> {
        if self.token.is_empty() && self.method == AuthMethod::Token {
            return Ok(String::new());
        }

        let key = privilege_key.unwrap_or("");
        let ts = timestamp.unwrap_or(0);

        match self.method {
            AuthMethod::Token => {
                let expected = generate_token(&self.token, ts);
                if key != expected {
                    return Err("invalid authentication token".into());
                }
                Ok(String::new())
            }
            AuthMethod::Oidc => {
                Err("OIDC auth requires server-side verifier (not configured)".into())
            }
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

// ---------------------------------------------------------------
// OIDC Verifier (server-side)
// ---------------------------------------------------------------

/// Information extracted from a verified OIDC login token.
#[derive(Debug, Clone)]
pub struct LoginOidcToken {
    pub subject: String,
    pub expiry: i64,
}

/// Cached JWKS keys.
struct CachedJwks {
    keys: serde_json::Value,
    fetched_at: std::time::Instant,
    refresh_after: std::time::Duration,
}

/// Server-side OIDC verifier. Discovers JWKS from issuer, verifies JWT tokens,
/// and enforces subject binding for ping/NewWorkConn.
pub struct OidcVerifier {
    audience: String,
    issuer: String,
    jwks_uri: String,
    jwks: tokio::sync::RwLock<Option<CachedJwks>>,
    skip_expiry: bool,
    skip_issuer: bool,
    http: reqwest::Client,
}

impl OidcVerifier {
    /// Create new OidcVerifier. Discovers JWKS URI from issuer's
    /// .well-known/openid-configuration and fetches initial keys.
    pub async fn new(
        issuer: String,
        audience: String,
        skip_expiry: bool,
        skip_issuer: bool,
    ) -> Result<Self, String> {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| format!("OIDC: failed to create HTTP client: {e}"))?;

        let config_url = format!("{}/.well-known/openid-configuration", issuer.trim_end_matches('/'));
        let resp = http.get(&config_url)
            .send()
            .await
            .map_err(|e| format!("OIDC: failed to fetch openid-configuration from {config_url}: {e}"))?;

        if !resp.status().is_success() {
            return Err(format!("OIDC: openid-configuration returned {}", resp.status()));
        }

        let config: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| format!("OIDC: failed to parse openid-configuration: {e}"))?;

        let jwks_uri = config["jwks_uri"]
            .as_str()
            .ok_or_else(|| "OIDC: jwks_uri not found in openid-configuration".to_string())?
            .to_string();

        let verifier = Self {
            audience,
            issuer: issuer.trim_end_matches('/').to_string(),
            jwks_uri,
            jwks: tokio::sync::RwLock::new(None),
            skip_expiry,
            skip_issuer,
            http,
        };

        verifier.refresh_jwks().await?;
        Ok(verifier)
    }

    async fn refresh_jwks(&self) -> Result<(), String> {
        let resp = self.http.get(&self.jwks_uri)
            .send()
            .await
            .map_err(|e| format!("OIDC: failed to fetch JWKS from {}: {e}", self.jwks_uri))?;

        if !resp.status().is_success() {
            return Err(format!("OIDC: JWKS endpoint returned {}", resp.status()));
        }

        let jwks_json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| format!("OIDC: failed to parse JWKS: {e}"))?;

        let mut cache = self.jwks.write().await;
        *cache = Some(CachedJwks {
            keys: jwks_json,
            fetched_at: std::time::Instant::now(),
            refresh_after: std::time::Duration::from_secs(3600),
        });

        Ok(())
    }

    /// Build a jsonwebtoken::DecodingKey from a JWKS key JSON value.
    fn decoding_key_from_jwk(key: &serde_json::Value) -> Result<jsonwebtoken::DecodingKey, String> {
        let kty = key["kty"].as_str().unwrap_or("");
        match kty {
            "RSA" => {
                let n = key["n"].as_str().ok_or("OIDC: missing RSA n in JWK")?;
                let e = key["e"].as_str().ok_or("OIDC: missing RSA e in JWK")?;
                jsonwebtoken::DecodingKey::from_rsa_components(n, e)
                    .map_err(|e| format!("OIDC: invalid RSA JWK: {e}"))
            }
            "EC" => {
                let x = key["x"].as_str().ok_or("OIDC: missing EC x in JWK")?;
                let y = key["y"].as_str().ok_or("OIDC: missing EC y in JWK")?;
                jsonwebtoken::DecodingKey::from_ec_components(x, y)
                    .map_err(|e| format!("OIDC: invalid EC JWK: {e}"))
            }
            "oct" => {
                let k = key["k"].as_str().ok_or("OIDC: missing oct k in JWK")?;
                jsonwebtoken::DecodingKey::from_base64_secret(k)
                    .map_err(|e| format!("OIDC: invalid oct JWK: {e}"))
            }
            _ => Err(format!("OIDC: unsupported JWK key type: {kty}")),
        }
    }

    /// Verify a login JWT. Returns LoginOidcToken with subject and expiry.
    pub async fn verify_login(&self, token: &str) -> Result<LoginOidcToken, String> {
        let header = jsonwebtoken::decode_header(token)
            .map_err(|e| format!("OIDC: failed to decode JWT header: {e}"))?;

        let alg = header.alg;
        let kid = header.kid.clone();

        // Ensure JWKS cached, refresh if stale
        {
            let cache = self.jwks.read().await;
            if let Some(ref c) = *cache {
                if c.fetched_at.elapsed() > c.refresh_after {
                    drop(cache);
                    let _ = self.refresh_jwks().await;
                }
            } else {
                drop(cache);
                self.refresh_jwks().await?;
            }
        }

        let mut validation = jsonwebtoken::Validation::new(alg);
        validation.validate_exp = !self.skip_expiry;
        if !self.skip_issuer {
            validation.set_issuer(&[&self.issuer]);
        }
        validation.set_audience(&[&self.audience]);

        // First attempt with cached JWKS
        let first_result = self.try_verify_token(token, &validation, kid.as_deref()).await;

        match first_result {
            Ok(tok) => Ok(tok),
            Err(first_err) => {
                // Refresh JWKS and retry once
                self.refresh_jwks().await?;
                self.try_verify_token(token, &validation, kid.as_deref()).await
                    .map_err(|_| first_err)
            }
        }
    }

    /// Try to verify a token against currently cached JWKS.
    async fn try_verify_token(
        &self,
        token: &str,
        validation: &jsonwebtoken::Validation,
        kid: Option<&str>,
    ) -> Result<LoginOidcToken, String> {
        let cache = self.jwks.read().await;
        let jwks = cache.as_ref().ok_or_else(|| "OIDC: no JWKS cached".to_string())?;
        let keys = jwks.keys["keys"]
            .as_array()
            .ok_or_else(|| "OIDC: JWKS has no 'keys' array".to_string())?;

        let mut last_err = String::new();

        for key in keys {
            // If kid present in header, only try matching key
            if let Some(expected_kid) = kid {
                if key["kid"].as_str() != Some(expected_kid) {
                    continue;
                }
            }

            let decoding_key = match Self::decoding_key_from_jwk(key) {
                Ok(k) => k,
                Err(e) => {
                    last_err = e;
                    continue;
                }
            };

            match jsonwebtoken::decode::<serde_json::Value>(token, &decoding_key, validation) {
                Ok(data) => {
                    let sub = data.claims["sub"].as_str().unwrap_or("").to_string();
                    let exp = data.claims["exp"].as_i64().unwrap_or(0);
                    return Ok(LoginOidcToken { subject: sub, expiry: exp });
                }
                Err(e) => {
                    last_err = e.to_string();
                }
            }
        }

        Err(format!("OIDC: JWT verification failed: {last_err}"))
    }

    /// Verify a ping JWT — also checks subject matches.
    pub async fn verify_ping(&self, token: &str, expected_sub: &str) -> Result<(), String> {
        let oidc_token = self.verify_login(token).await?;
        if oidc_token.subject != expected_sub {
            return Err(format!(
                "OIDC subject mismatch: expected {expected_sub}, got {}",
                oidc_token.subject
            ));
        }
        Ok(())
    }

    /// Verify a NewWorkConn JWT — same as verify_ping.
    pub async fn verify_new_work_conn(&self, token: &str, expected_sub: &str) -> Result<(), String> {
        self.verify_ping(token, expected_sub).await
    }
}

// ---------------------------------------------------------------
// OIDC Client (client-side)
// ---------------------------------------------------------------

/// Cached OIDC access token.
struct CachedOidcToken {
    access_token: String,
    expires_at: std::time::Instant,
}

/// Client-side OIDC token fetcher. Uses OAuth2 client_credentials grant
/// to obtain access tokens from the IDP and caches them until expiry.
pub struct OidcClient {
    token_endpoint: String,
    client_id: String,
    client_secret: String,
    audience: String,
    scope: String,
    cached: tokio::sync::Mutex<Option<CachedOidcToken>>,
    http: reqwest::Client,
}

impl OidcClient {
    /// Create new OidcClient. If token_endpoint is empty, discovers from issuer.
    pub async fn new(
        client_id: String,
        client_secret: String,
        audience: String,
        token_endpoint: Option<String>,
        scope: String,
        issuer: Option<String>,
    ) -> Result<Self, String> {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| format!("OIDC client: failed to create HTTP client: {e}"))?;

        let endpoint = if let Some(ep) = token_endpoint.filter(|s| !s.is_empty()) {
            ep
        } else if let Some(iss) = issuer.filter(|s| !s.is_empty()) {
            let config_url = format!("{}/.well-known/openid-configuration", iss.trim_end_matches('/'));
            let resp = http.get(&config_url)
                .send()
                .await
                .map_err(|e| format!("OIDC client: failed to fetch openid-configuration from {config_url}: {e}"))?;

            if !resp.status().is_success() {
                return Err(format!("OIDC client: openid-configuration returned {}", resp.status()));
            }

            let config: serde_json::Value = resp
                .json()
                .await
                .map_err(|e| format!("OIDC client: failed to parse openid-configuration: {e}"))?;

            config["token_endpoint"]
                .as_str()
                .ok_or_else(|| "OIDC client: token_endpoint not found in openid-configuration".to_string())?
                .to_string()
        } else {
            return Err("OIDC client: token_endpoint or issuer is required".into());
        };

        let scope = if scope.is_empty() { "openid".to_string() } else { scope };

        Ok(Self {
            token_endpoint: endpoint,
            client_id,
            client_secret,
            audience,
            scope,
            cached: tokio::sync::Mutex::new(None),
            http,
        })
    }

    async fn fetch_token(&self) -> Result<String, String> {
        let params = [
            ("grant_type", "client_credentials"),
            ("client_id", self.client_id.as_str()),
            ("client_secret", self.client_secret.as_str()),
            ("scope", self.scope.as_str()),
            ("audience", self.audience.as_str()),
        ];

        let resp = self.http.post(&self.token_endpoint)
            .form(&params)
            .send()
            .await
            .map_err(|e| format!("OIDC client: token request to {} failed: {e}", self.token_endpoint))?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("OIDC client: token endpoint returned error: {body}"));
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| format!("OIDC client: failed to parse token response: {e}"))?;

        let token = body["access_token"]
            .as_str()
            .ok_or_else(|| "OIDC client: access_token not found in response".to_string())?
            .to_string();

        Ok(token)
    }

    /// Get a valid access token — uses cached if not expired, fetches new otherwise.
    async fn get_token(&self) -> Result<String, String> {
        let mut cache = self.cached.lock().await;
        if let Some(ref cached) = *cache {
            if cached.expires_at > std::time::Instant::now() {
                return Ok(cached.access_token.clone());
            }
        }
        let token = self.fetch_token().await?;
        *cache = Some(CachedOidcToken {
            access_token: token.clone(),
            expires_at: std::time::Instant::now() + std::time::Duration::from_secs(3000), // 50 min default
        });
        Ok(token)
    }

    /// Set privilege_key on a Login message using an OIDC token.
    pub async fn set_login(&self, login: &mut crate::msg::Login) -> Result<(), String> {
        let token = self.get_token().await?;
        login.privilege_key = Some(token);
        login.timestamp = None;
        Ok(())
    }

    /// Set privilege_key on a Ping message using an OIDC token.
    pub async fn set_ping(&self, ping: &mut crate::msg::Ping) -> Result<(), String> {
        let token = self.get_token().await?;
        ping.privilege_key = Some(token);
        ping.timestamp = None;
        Ok(())
    }

    /// Set privilege_key on a NewWorkConn message using an OIDC token.
    pub async fn set_new_work_conn(&self, nwc: &mut crate::msg::NewWorkConn) -> Result<(), String> {
        let token = self.get_token().await?;
        nwc.privilege_key = Some(token);
        nwc.timestamp = None;
        Ok(())
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
            oidc_issuer: String::new(),
            oidc_audience: String::new(),
            oidc_skip_expiry: false,
            oidc_skip_issuer: false,
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
