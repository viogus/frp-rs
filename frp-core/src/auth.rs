use md5::{Md5, Digest};

/// Constant-time slice comparison for auth token verification.
/// XOR-accumulates every byte pair so execution time depends only on
/// the longer input length, not on where the first difference occurs.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        acc |= x ^ y;
    }
    acc == 0
}

/// Generate a token for authentication using MD5 (matching Go frp v0.69.1).
/// The message is typically the timestamp as a string.
pub fn generate_token(token: &str, timestamp: i64) -> String {
    let mut hasher = Md5::new();
    hasher.update(token.as_bytes());
    hasher.update(timestamp.to_string().as_bytes());
    hex::encode(hasher.finalize())
}

/// Verify a token against a known secret and timestamp.
/// Uses constant-time comparison to prevent timing side-channel attacks.
pub fn verify_token(token: &str, timestamp: i64, expected_hex: &str) -> bool {
    let computed = generate_token(token, timestamp);
    constant_time_eq(computed.as_bytes(), expected_hex.as_bytes())
}

/// Authentication configuration.
#[derive(Debug, Clone)]
pub struct AuthConfig {
    pub method: AuthMethod,
    /// NOTE: Token is stored as plain String in memory with no automatic
    /// zeroization. Callers should invoke [`zeroize_string`] on `self.token`
    /// when the `AuthConfig` is dropped or before deallocation.
    /// For defense-in-depth, a future version should use `secrecy::Secret` or
    /// the `zeroize` crate.
    pub token: String,
    pub oidc_issuer: String,
    pub oidc_audience: String,
    pub oidc_skip_expiry: bool,
    pub oidc_skip_issuer: bool,
    pub additional_data: Option<String>,
    /// HTTP/SOCKS5 proxy URL for OIDC HTTP client connections.
    /// Go frp compat: oidcProxyURL.
    pub oidc_proxy_url: String,
    /// Additional auth scopes: "HeartBeats", "NewWorkConns".
    /// When listed, corresponding message types require authentication.
    /// Go frp compat: additionalAuthScopes.
    pub additional_auth_scopes: Vec<String>,
    /// Maximum allowed clock skew for timestamp-based replay protection,
    /// in seconds. Login messages with `|ts - now| > authentication_timeout`
    /// are rejected. Set to 0 to disable timestamp verification (accepts
    /// any timestamp, weakening replay protection).
    ///
    /// Go frp v0.69.1 default: 900 (15 minutes). This implementation defaults
    /// to 15 seconds for tighter replay protection.
    /// Go frp compat: authentication_timeout.
    pub authentication_timeout: i64,
    /// Whether to wrap control connection in AES-128-CFB after LoginResp.
    /// Go frp compat: use_encryption. Default: false (TLS alone is sufficient).
    pub use_encryption: bool,
}

impl Drop for AuthConfig {
    fn drop(&mut self) {
        zeroize_string(&mut self.token);
    }
}

impl AuthConfig {
    /// Construct an `AuthConfig` with default fields and the given token.
    /// Convenience constructor for tests and simple configurations.
    pub fn with_token(token: impl Into<String>) -> Self {
        Self {
            method: AuthMethod::Token,
            token: token.into(),
            oidc_issuer: String::new(),
            oidc_audience: String::new(),
            oidc_skip_expiry: false,
            oidc_skip_issuer: false,
            additional_data: None,
            oidc_proxy_url: String::new(),
            additional_auth_scopes: Vec::new(),
            authentication_timeout: 0,
            use_encryption: false,
        }
    }
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
            oidc_proxy_url: String::new(),
            additional_auth_scopes: Vec::new(),
            authentication_timeout: 15,
            use_encryption: false,
        }
    }
}

/// Supported authentication methods.
#[derive(Debug, Clone, PartialEq)]
pub enum AuthMethod {
    Token,
    #[cfg(feature = "oidc")]
    Oidc,
}

impl AuthConfig {
    /// Validate a login attempt. Returns the subject string (empty for token
    /// auth, populated from JWT 'sub' claim for OIDC). Returns Err if invalid.
    pub fn validate_login(&self, privilege_key: Option<&str>, timestamp: Option<i64>) -> Result<String, String> {
        if self.token.is_empty() && self.method == AuthMethod::Token {
            tracing::error!("CRITICAL: [auth].token is empty with token auth method — server would accept ALL connections. Set a strong token in the config file.");
            // Allow the login to proceed (Go frp backward compat: empty token = no auth check).
            // The check_startup() method should be called at server startup to prevent
            // accidental empty-token configurations in production.
            return Ok(String::new());
        }

        let key = privilege_key.unwrap_or("");

        match self.method {
            AuthMethod::Token => {
                let ts = match timestamp {
                    Some(t) => t,
                    None => return Err("timestamp required for authentication".into()),
                };
                if self.authentication_timeout > 0 {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as i64;
                    if (ts - now).abs() > self.authentication_timeout {
                        return Err("timestamp outside acceptable window".into());
                    }
                }
                let expected = generate_token(&self.token, ts);
                if !constant_time_eq(key.as_bytes(), expected.as_bytes()) {
                    return Err("invalid authentication token".into());
                }
                Ok(String::new())
            }
            #[cfg(feature = "oidc")]
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
            #[cfg(feature = "oidc")]
            AuthMethod::Oidc => None,
        }
    }

    /// Check for critical security misconfigurations at startup.
    /// Call this at server startup to reject dangerously insecure configurations.
    pub fn check_startup(&self) -> Result<(), String> {
        if self.method == AuthMethod::Token && self.token.is_empty() {
            return Err("CRITICAL: [auth].token is empty with token auth method — server would accept ALL connections. Set a strong token in the config file.".into());
        }
        Ok(())
    }
}

// ---------------------------------------------------------------
// OIDC Verifier (server-side)
// ---------------------------------------------------------------

#[cfg(feature = "oidc")]
mod oidc_impl {
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
            proxy_url: Option<String>,
        ) -> Result<Self, String> {
            let mut client_builder = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10));
            if let Some(ref url) = proxy_url.filter(|u| !u.is_empty()) {
                let proxy = reqwest::Proxy::all(url)
                    .map_err(|e| format!("OIDC: invalid proxy URL '{url}': {e}"))?;
                client_builder = client_builder.proxy(proxy);
            }
            let http = client_builder
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

            let body = resp.text().await
                .map_err(|e| format!("OIDC: failed to read openid-configuration: {e}"))?;
            let config: serde_json::Value = serde_json::from_str(&body)
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

            if verifier.skip_expiry {
                tracing::warn!("OIDC: skip_expiry is enabled — expired tokens will be accepted. This weakens authentication security.");
            }
            if verifier.skip_issuer {
                tracing::warn!("OIDC: skip_issuer is enabled — tokens from any issuer will be accepted. This weakens authentication security.");
            }

            verifier.refresh_jwks().await?;
            Ok(verifier)
        }

        /// Start a background task that periodically refreshes JWKS keys.
        /// Prevents latency spikes on token verification when cache is stale.
        pub fn start_background_refresh(self: &std::sync::Arc<Self>) {
            let verifier = self.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
                    if let Err(e) = verifier.refresh_jwks().await {
                        tracing::warn!(error = %e, "OIDC background JWKS refresh failed: {}", e);
                    } else {
                        tracing::debug!("OIDC JWKS refreshed in background");
                    }
                }
            });
        }

        async fn refresh_jwks(&self) -> Result<(), String> {
            let resp = self.http.get(&self.jwks_uri)
                .send()
                .await
                .map_err(|e| format!("OIDC: failed to fetch JWKS from {}: {e}", self.jwks_uri))?;

            if !resp.status().is_success() {
                return Err(format!("OIDC: JWKS endpoint returned {}", resp.status()));
            }

            let body = resp.text().await
                .map_err(|e| format!("OIDC: failed to read JWKS: {e}"))?;
            let jwks_json: serde_json::Value = serde_json::from_str(&body)
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
        pub(crate) fn decoding_key_from_jwk(key: &serde_json::Value) -> Result<jsonwebtoken::DecodingKey, String> {
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
        additional_params: Vec<(String, String)>,
        cached: tokio::sync::Mutex<Option<CachedOidcToken>>,
        http: reqwest::Client,
    }

    impl OidcClient {
        /// Create new OidcClient. If token_endpoint is empty, discovers from issuer.
        ///
        /// `tls_trusted_ca_file`: path to a custom CA certificate PEM file for
        /// the OIDC provider's TLS. Go frp compat: tls_trusted_ca_file.
        ///
        /// `tls_insecure_skip_verify`: skip TLS certificate verification (dev only).
        /// Go frp compat: insecure_skip_verify.
        #[allow(clippy::too_many_arguments)]
        pub async fn new(
            client_id: String,
            client_secret: String,
            audience: String,
            token_endpoint: Option<String>,
            scope: String,
            issuer: Option<String>,
            additional_endpoint_params: &str,
            tls_trusted_ca_file: Option<String>,
            tls_insecure_skip_verify: bool,
            proxy_url: Option<String>,
        ) -> Result<Self, String> {
            let mut client_builder = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10));

            if let Some(ref url) = proxy_url.filter(|u| !u.is_empty()) {
                let proxy = reqwest::Proxy::all(url)
                    .map_err(|e| format!("OIDC client: invalid proxy URL '{url}': {e}"))?;
                client_builder = client_builder.proxy(proxy);
            }

            if let Some(ca_file) = tls_trusted_ca_file.filter(|f| !f.is_empty()) {
                let cert = std::fs::read(&ca_file)
                    .map_err(|e| format!("OIDC client: failed to read CA cert {ca_file}: {e}"))?;
                let cert = reqwest::Certificate::from_pem(&cert)
                    .map_err(|e| format!("OIDC client: invalid CA cert {ca_file}: {e}"))?;
                client_builder = client_builder.add_root_certificate(cert);
            }

            if tls_insecure_skip_verify {
                tracing::warn!("OIDC: tls_insecure_skip_verify is enabled — TLS certificate verification is disabled. This weakens authentication security.");
                client_builder = client_builder.danger_accept_invalid_certs(true);
            }

            let http = client_builder
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

                let body = resp.text().await
                    .map_err(|e| format!("OIDC client: failed to read openid-configuration: {e}"))?;
                let config: serde_json::Value = serde_json::from_str(&body)
                    .map_err(|e| format!("OIDC client: failed to parse openid-configuration: {e}"))?;

                config["token_endpoint"]
                    .as_str()
                    .ok_or_else(|| "OIDC client: token_endpoint not found in openid-configuration".to_string())?
                    .to_string()
            } else {
                return Err("OIDC client: token_endpoint or issuer is required".into());
            };

            let scope = if scope.is_empty() { "openid".to_string() } else { scope };

            // Parse additional endpoint params: "key1=val1&key2=val2" → Vec of (key, val) pairs
            let additional_params: Vec<(String, String)> = additional_endpoint_params
                .split('&')
                .filter(|s| !s.is_empty())
                .filter_map(|pair| {
                    let mut parts = pair.splitn(2, '=');
                    let key = parts.next().unwrap_or("").trim().to_string();
                    let val = parts.next().unwrap_or("").trim().to_string();
                    if key.is_empty() { None } else { Some((key, val)) }
                })
                .collect();

            Ok(Self {
                token_endpoint: endpoint,
                client_id,
                client_secret,
                audience,
                scope,
                additional_params,
                cached: tokio::sync::Mutex::new(None),
                http,
            })
        }

        async fn fetch_token(&self) -> Result<(String, u64), String> {
            let mut params: Vec<(&str, &str)> = vec![
                ("grant_type", "client_credentials"),
                ("client_id", self.client_id.as_str()),
                ("client_secret", self.client_secret.as_str()),
                ("scope", self.scope.as_str()),
                ("audience", self.audience.as_str()),
            ];
            let extra: Vec<(&str, &str)> = self.additional_params.iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect();
            params.extend_from_slice(&extra);

            let resp = self.http.post(&self.token_endpoint)
                .form(&params)
                .send()
                .await
                .map_err(|e| format!("OIDC client: token request to {} failed: {e}", self.token_endpoint))?;

            if !resp.status().is_success() {
                let body = resp.text().await.unwrap_or_default();
                return Err(format!("OIDC client: token endpoint returned error: {body}"));
            }

            let resp_text = resp.text().await
                .map_err(|e| format!("OIDC client: failed to read token response: {e}"))?;
            let body: serde_json::Value = serde_json::from_str(&resp_text)
                .map_err(|e| format!("OIDC client: failed to parse token response: {e}"))?;

            let token = body["access_token"]
                .as_str()
                .ok_or_else(|| "OIDC client: access_token not found in response".to_string())?
                .to_string();

            // Parse expires_in from response (default 3600s = 1 hour).
            // Subtract 60s refresh buffer to avoid edge-of-expiry failures.
            let expires_in: u64 = body["expires_in"]
                .as_u64()
                .unwrap_or(3600)
                .saturating_sub(60);

            Ok((token, expires_in))
        }

        /// Get a valid access token — uses cached if not expired, fetches new otherwise.
        /// Automatically refreshes when token is within 60s of expiry.
        async fn get_token(&self) -> Result<String, String> {
            let mut cache = self.cached.lock().await;
            if let Some(ref cached) = *cache {
                if cached.expires_at > std::time::Instant::now() {
                    return Ok(cached.access_token.clone());
                }
            }
            let (token, expires_in) = self.fetch_token().await?;
            *cache = Some(CachedOidcToken {
                access_token: token.clone(),
                expires_at: std::time::Instant::now() + std::time::Duration::from_secs(expires_in),
            });
            Ok(token)
        }

        /// Return the token endpoint URL (for logging).
        pub fn token_endpoint(&self) -> &str {
            &self.token_endpoint
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
}

#[cfg(feature = "oidc")]
pub use oidc_impl::{LoginOidcToken, OidcVerifier, OidcClient};

// Stub types for when the oidc feature is disabled. These exist so that
// type-level references (struct fields, function parameters, Option<Arc<...>>)
// compile without per-site #[cfg] gates. Actual OIDC logic paths are gated
// by AuthMethod::Oidc which is behind #[cfg(feature = "oidc")].
#[cfg(not(feature = "oidc"))]
pub struct OidcClient;
#[cfg(not(feature = "oidc"))]
pub struct OidcVerifier;
#[cfg(not(feature = "oidc"))]
pub struct LoginOidcToken {
    pub subject: String,
    pub expiry: i64,
}
#[cfg(not(feature = "oidc"))]
impl OidcClient {
    /// Stub — the oidc feature is disabled; AuthMethod::Oidc is unreachable.
    pub async fn set_login(&self, _login: &mut crate::msg::Login) -> Result<(), String> {
        Err("OIDC feature disabled at compile time".into())
    }
    /// Stub.
    pub async fn set_ping(&self, _ping: &mut crate::msg::Ping) -> Result<(), String> {
        Err("OIDC feature disabled at compile time".into())
    }
    /// Stub.
    pub async fn set_new_work_conn(&self, _nwc: &mut crate::msg::NewWorkConn) -> Result<(), String> {
        Err("OIDC feature disabled at compile time".into())
    }
}
#[cfg(not(feature = "oidc"))]
impl OidcVerifier {
    /// Stub.
    pub async fn verify_login(&self, _token: &str) -> Result<LoginOidcToken, String> {
        Err("OIDC feature disabled at compile time".into())
    }
    /// Stub.
    pub async fn verify_ping(&self, _token: &str, _expected_sub: &str) -> Result<(), String> {
        Err("OIDC feature disabled at compile time".into())
    }
    /// Stub.
    pub async fn verify_new_work_conn(&self, _token: &str, _expected_sub: &str) -> Result<(), String> {
        Err("OIDC feature disabled at compile time".into())
    }
}

/// Zeroize a `String` in-place by overwriting each byte with `0x00`.
///
/// Uses `unsafe` to access the `Vec<u8>` backing buffer directly,
/// bypassing Rust's immutability guarantees for `&mut str`.
///
/// Call this on `AuthConfig.token` before deallocation to reduce the
/// window where plaintext credentials reside in memory.
pub fn zeroize_string(s: &mut String) {
    // SAFETY: Vec<u8> is the backing store for String.
    // Overwriting with zeros preserves valid UTF-8 (NUL bytes are valid).
    // No references into `s` can exist while we hold `&mut String`.
    unsafe {
        let v = s.as_mut_vec();
        v.fill(0);
    }
    // Clear len so the now-zeroed bytes are not accidentally re-read.
    s.clear();
}

/// Resolve a token that may use a URL scheme for dynamic sourcing.
///
/// **Prefer [`resolve_dynamic_token_checked`]** — it enforces the
/// `UnsafeFeatures` allowlist for `exec://` and `file://` sources.
/// This function exists for backward compatibility with callers that do
/// not yet thread `UnsafeFeatures` through (frp-server/frp-client service.rs).
///
/// When called without UnsafeFeatures, `exec://` and `file://` sources
/// execute unconditionally (legacy behavior). Use [`resolve_dynamic_token_checked`]
/// to enforce the allowlist.
///
/// Supported schemes:
/// - `file:///absolute/path` — reads the first line of the file
/// - `exec://command arg1 arg2` — runs the command, reads first line of stdout
/// - plain string — returned as-is
///
/// Go frp compat: file:// and exec:// token sources.
pub fn resolve_dynamic_token(token: &str) -> String {
    // Prefer checked variant when available; for backward compat, None
    // means legacy mode (no enforcement).
    match resolve_dynamic_token_inner(token, None) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "resolve_dynamic_token error: {e}");
            String::new()
        }
    }
}

/// Resolve a dynamic token with `UnsafeFeatures` enforcement.
///
/// When the token uses `exec://` or `file://`, the corresponding feature
/// must be enabled in `unsafe_features`. If the feature is not allowed,
/// an error is returned.
///
/// Callers that have access to an `UnsafeFeatures` instance should use
/// this function instead of [`resolve_dynamic_token`].
pub fn resolve_dynamic_token_checked(
    token: &str,
    unsafe_features: &crate::unsafe_features::UnsafeFeatures,
) -> Result<String, String> {
    resolve_dynamic_token_inner(token, Some(unsafe_features))
}

fn resolve_dynamic_token_inner(
    token: &str,
    unsafe_features: Option<&crate::unsafe_features::UnsafeFeatures>,
) -> Result<String, String> {
    if let Some(path) = token.strip_prefix("file://") {
        if let Some(uf) = unsafe_features {
            if !uf.is_enabled(crate::unsafe_features::TOKEN_SOURCE_EXEC) {
                return Err(
                    "file:// token source blocked: TokenSourceExec not in UnsafeFeatures allowlist. \
                     Set [common].unsafe_features = [\"TokenSourceExec\"] to enable."
                        .into(),
                );
            }
        }
        match std::fs::read_to_string(path) {
            Ok(content) => Ok(content.lines().next().unwrap_or("").trim().to_string()),
            Err(e) => Err(format!(
                "Failed to read dynamic token from file://{}: {}",
                path, e
            )),
        }
    } else if let Some(cmd) = token.strip_prefix("exec://") {
        if let Some(uf) = unsafe_features {
            if !uf.is_enabled(crate::unsafe_features::TOKEN_SOURCE_EXEC) {
                return Err(
                    "exec:// token source blocked: TokenSourceExec not in UnsafeFeatures allowlist. \
                     Set [common].unsafe_features = [\"TokenSourceExec\"] to enable."
                        .into(),
                );
            }
        }
        let parts: Vec<&str> = cmd.split_whitespace().collect();
        if parts.is_empty() {
            return Err("Dynamic token exec:// with empty command".into());
        }
        match std::process::Command::new(parts[0])
            .args(&parts[1..])
            .output()
        {
            Ok(o) => {
                if !o.status.success() {
                    let stderr = String::from_utf8_lossy(&o.stderr);
                    return Err(format!(
                        "Dynamic token exec command '{}' exited with {}: {}",
                        cmd,
                        o.status,
                        stderr.trim()
                    ));
                }
                Ok(String::from_utf8_lossy(&o.stdout)
                    .lines()
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_string())
            }
            Err(e) => Err(format!(
                "Failed to exec dynamic token command '{}': {}",
                cmd, e
            )),
        }
    } else {
        Ok(token.to_string())
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
        let mut cfg = AuthConfig::with_token("secret");
        cfg.authentication_timeout = 15;
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let key = generate_token("secret", ts);
        assert!(cfg.validate_login(Some(&key), Some(ts)).is_ok());
        assert!(cfg.validate_login(Some(&key), Some(ts + 1)).is_err());
        assert!(cfg.validate_login(Some("wrong"), Some(ts)).is_err());

        let empty_cfg = AuthConfig::default();
        // Empty token: login passes (Go frp backward compat) but check_startup() guards startup
        assert!(empty_cfg.validate_login(None, None).is_ok());
    }

    #[test]
    #[cfg(feature = "oidc")]
    fn test_auth_config_oidc_rejects_without_verifier() {
        let cfg = AuthConfig {
            method: AuthMethod::Oidc,
            token: String::new(),
            oidc_issuer: "https://issuer.example.com".into(),
            oidc_audience: "my-audience".into(),
            oidc_skip_expiry: false,
            oidc_skip_issuer: false,
            additional_data: None,
            oidc_proxy_url: String::new(),
            additional_auth_scopes: Vec::new(),
            authentication_timeout: 0,
            use_encryption: false,
        };
        // AuthConfig::validate_login for OIDC returns error when no server-side verifier
        let result = cfg.validate_login(Some("some-jwt-token"), Some(100));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("OIDC"));
    }

    #[test]
    #[cfg(feature = "oidc")]
    fn test_decoding_key_from_rsa_jwk() {
        // Minimal RSA JWK with known test values
        let jwk = serde_json::json!({
            "kty": "RSA",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            "e": "AQAB"
        });
        let key = OidcVerifier::decoding_key_from_jwk(&jwk);
        assert!(key.is_ok(), "RSA JWK should parse: {:?}", key.err());
    }

    #[test]
    #[cfg(feature = "oidc")]
    fn test_decoding_key_from_oct_jwk() {
        // oct key for HS256 — "abcdefghijklmnopqrstuvwxyz123456" in standard base64
        let jwk = serde_json::json!({
            "kty": "oct",
            "k": "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY="
        });
        let key = OidcVerifier::decoding_key_from_jwk(&jwk);
        assert!(key.is_ok(), "oct JWK should parse: {:?}", key.err());
    }

    #[test]
    #[cfg(feature = "oidc")]
    fn test_decoding_key_from_ec_jwk() {
        // EC P-256 key
        let jwk = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
            "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
        });
        let key = OidcVerifier::decoding_key_from_jwk(&jwk);
        assert!(key.is_ok(), "EC JWK should parse: {:?}", key.err());
    }

    #[test]
    #[cfg(feature = "oidc")]
    fn test_decoding_key_unsupported_kty() {
        let jwk = serde_json::json!({
            "kty": "UNKNOWN",
            "x": "abc"
        });
        let result = OidcVerifier::decoding_key_from_jwk(&jwk);
        match result {
            Ok(_) => panic!("expected error for unsupported kty"),
            Err(e) => assert!(e.contains("unsupported"), "got: {e}"),
        }
    }

    #[test]
    fn test_auth_config_default() {
        let cfg = AuthConfig::default();
        assert!(matches!(cfg.method, AuthMethod::Token));
        assert!(cfg.token.is_empty());
        assert!(!cfg.oidc_skip_expiry);
        assert!(!cfg.oidc_skip_issuer);
        assert!(cfg.additional_auth_scopes.is_empty());
    }

    #[test]
    fn test_generate_login_key_empty_token() {
        let cfg = AuthConfig::default();
        assert!(cfg.generate_login_key(100).is_none());
    }

    #[test]
    #[cfg(feature = "oidc")]
    fn test_generate_login_key_oidc_returns_none() {
        let cfg = AuthConfig {
            method: AuthMethod::Oidc,
            token: "secret".into(),
            oidc_issuer: String::new(),
            oidc_audience: String::new(),
            oidc_skip_expiry: false,
            oidc_skip_issuer: false,
            additional_data: None,
            oidc_proxy_url: String::new(),
            additional_auth_scopes: Vec::new(),
            authentication_timeout: 0,
            use_encryption: false,
        };
        assert!(cfg.generate_login_key(100).is_none());
    }

    #[test]
    fn test_resolve_dynamic_token_plain() {
        assert_eq!(resolve_dynamic_token("my-token"), "my-token");
        assert_eq!(resolve_dynamic_token(""), "");
    }

    #[test]
    fn test_resolve_dynamic_token_file() {
        let dir = std::env::temp_dir();
        let path = dir.join("frp-test-token.txt");
        std::fs::write(&path, "file-token-value\n").unwrap();
        let url = format!("file://{}", path.display());
        assert_eq!(resolve_dynamic_token(&url), "file-token-value");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_resolve_dynamic_token_file_multiline() {
        let dir = std::env::temp_dir();
        let path = dir.join("frp-test-token-multi.txt");
        std::fs::write(&path, "first-line\nsecond-line\n").unwrap();
        let url = format!("file://{}", path.display());
        assert_eq!(resolve_dynamic_token(&url), "first-line");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_resolve_dynamic_token_file_missing() {
        let result = resolve_dynamic_token("file:///nonexistent/path/token.txt");
        assert!(result.is_empty());
    }

    #[test]
    fn test_resolve_dynamic_token_exec() {
        // Use /bin/echo on Unix — portable across macOS and Linux
        let uf = crate::unsafe_features::UnsafeFeatures::new(crate::unsafe_features::CLIENT_UNSAFE_FEATURES);
        let result = resolve_dynamic_token_checked("exec:///bin/echo dynamic-token-value", &uf);
        assert_eq!(result.unwrap(), "dynamic-token-value");
    }

    #[test]
    fn test_resolve_dynamic_token_exec_blocked_when_not_allowed() {
        let uf = crate::unsafe_features::UnsafeFeatures::default();
        let result = resolve_dynamic_token_checked("exec:///bin/echo secret", &uf);
        assert!(result.is_err());
    }

    // --- Authentication timeout (replay protection) tests ---

    #[test]
    fn test_auth_timeout_default_is_15() {
        let cfg = AuthConfig::default();
        assert_eq!(cfg.authentication_timeout, 15);
    }

    #[test]
    fn test_auth_timeout_zero_disables_check() {
        let cfg = AuthConfig::with_token("secret");
        // Token with a timestamp far in the past should still verify
        // when timeout is disabled (only token matters, not timestamp)
        let far_past = 0i64;
        let key = generate_token("secret", far_past);
        assert!(cfg.validate_login(Some(&key), Some(far_past)).is_ok());
    }

    #[test]
    fn test_auth_timeout_rejects_future_timestamp() {
        let mut cfg = AuthConfig::with_token("secret");
        cfg.authentication_timeout = 15;
        let far_future = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64
            + 60; // 60 seconds in the future
        let key = generate_token("secret", far_future);
        let result = cfg.validate_login(Some(&key), Some(far_future));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("timestamp"));
    }

    #[test]
    fn test_auth_timeout_rejects_past_timestamp() {
        let mut cfg = AuthConfig::with_token("secret");
        cfg.authentication_timeout = 15;
        let far_past = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64
            - 60; // 60 seconds in the past
        let key = generate_token("secret", far_past);
        let result = cfg.validate_login(Some(&key), Some(far_past));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("timestamp"));
    }

    #[test]
    fn test_auth_timeout_accepts_current_timestamp() {
        let mut cfg = AuthConfig::with_token("secret");
        cfg.authentication_timeout = 15;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let key = generate_token("secret", now);
        assert!(cfg.validate_login(Some(&key), Some(now)).is_ok());
    }

    #[test]
    fn test_auth_timeout_boundary_inside_window() {
        let mut cfg = AuthConfig::with_token("secret");
        cfg.authentication_timeout = 15;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        // Exactly at the boundary (should be accepted: |ts-now| <= 15)
        let at_boundary = now + 15;
        let key = generate_token("secret", at_boundary);
        assert!(cfg.validate_login(Some(&key), Some(at_boundary)).is_ok());
    }

    #[test]
    fn test_auth_timeout_boundary_outside_window() {
        let mut cfg = AuthConfig::with_token("secret");
        cfg.authentication_timeout = 15;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        // Just outside the boundary
        let outside = now + 16;
        let key = generate_token("secret", outside);
        let result = cfg.validate_login(Some(&key), Some(outside));
        assert!(result.is_err());
    }

    #[test]
    fn test_auth_timeout_still_rejects_wrong_token_inside_window() {
        // Replay protection: even with a valid timestamp, wrong token fails
        let mut cfg = AuthConfig::with_token("secret");
        cfg.authentication_timeout = 15;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        // Token generated with wrong secret
        let wrong_key = generate_token("wrong-secret", now);
        let result = cfg.validate_login(Some(&wrong_key), Some(now));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid authentication token"));
    }
}
