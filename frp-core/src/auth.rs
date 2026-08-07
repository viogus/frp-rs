use md5::{Digest, Md5};

/// Constant-time slice comparison for auth token verification.
/// XOR-accumulates every byte pair so execution time depends only on
/// the longer input length, not on where the first difference occurs.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        acc |= x ^ y;
    }
    acc == 0
}

/// Constant-time string comparison — execution time depends only on the
/// shorter input length, not on where the first difference occurs.
/// Prevents timing side-channel attacks on credential comparisons.
pub fn constant_time_eq_str(a: &str, b: &str) -> bool {
    let a = a.as_bytes();
    let b = b.as_bytes();
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
    crate::hex_encode(hasher.finalize().as_slice())
}

/// Verify a token against a known secret and timestamp.
/// Uses constant-time comparison to prevent timing side-channel attacks.
pub fn verify_token(token: &str, timestamp: i64, expected_hex: &str) -> bool {
    let computed = generate_token(token, timestamp);
    constant_time_eq(computed.as_bytes(), expected_hex.as_bytes())
}

/// Validate that a timestamp is within the acceptable freshness window.
/// Returns Ok(()) if `timeout_secs` is 0 (disabled) or if `|ts - now| <= timeout_secs`.
/// Returns Err with a message if the timestamp is outside the window.
///
/// Accepts both seconds-precision and milliseconds-precision timestamps
/// (frpc sends milliseconds to avoid same-second reconnect collisions in the
/// server's duplicate-detection table; Go frpc sends seconds). A timestamp is
/// fresh if EITHER interpretation fits the window, so both clients work.
///
/// Go frp compat: matches the `authentication_timeout` check in `AuthConfig::validate_login`.
pub fn validate_timestamp_freshness(timestamp: i64, timeout_secs: i64) -> Result<(), String> {
    if timeout_secs <= 0 {
        return Ok(());
    }
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;
    let now_s = now_ms / 1000;
    // Saturation arithmetic: `timestamp` is attacker-controlled and may be
    // i64::MIN/MAX. Plain `(ts - now).abs()` overflows (debug panic) and the
    // release build's wrapping semantics then depend on integer overflow
    // behavior. saturating_sub + saturating_abs never panics and maps any
    // extreme input to a huge elapsed time → rejected.
    let elapsed_s = timestamp.saturating_sub(now_s).saturating_abs();
    let elapsed_ms = timestamp.saturating_sub(now_ms).saturating_abs();
    let fresh_s = elapsed_s <= timeout_secs;
    let fresh_ms = elapsed_ms <= timeout_secs.saturating_mul(1000);
    if !fresh_s && !fresh_ms {
        return Err("timestamp outside acceptable window".into());
    }
    Ok(())
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
    /// Dynamic source used to resolve the current token on demand.
    /// When set, `resolve_token()` returns a fresh value for each auth
    /// operation instead of the startup snapshot in `token`.
    pub token_source: Option<crate::config::ValueSource>,
    pub oidc_issuer: String,
    pub oidc_audience: String,
    pub oidc_skip_expiry: bool,
    pub oidc_skip_issuer: bool,
    pub oidc_skip_nbf: bool,
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
    /// Go frp has no `authentication_timeout` equivalent (timestamp freshness
    /// is not checked in the token auth path). The config default is 0
    /// (disabled). When set, OIDC uses this for JWT expiry validation.
    /// Go frp compat: authentication_timeout.
    pub authentication_timeout: i64,
    /// When true (default), token auth validates timestamp freshness and
    /// rejects duplicate (run_id, timestamp) pairs to prevent replay attacks.
    /// Set to false to disable timestamp/replay checking (less secure, but
    /// compatible with clients whose clocks are unreliable).
    pub token_auth_timeout: bool,
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
            token_source: None,
            oidc_issuer: String::new(),
            oidc_audience: String::new(),
            oidc_skip_expiry: false,
            oidc_skip_issuer: false,
            oidc_skip_nbf: false,
            additional_data: None,
            oidc_proxy_url: String::new(),
            additional_auth_scopes: Vec::new(),
            authentication_timeout: 0,
            token_auth_timeout: true,
            use_encryption: false,
        }
    }
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            method: AuthMethod::Token,
            token: String::new(),
            token_source: None,
            oidc_issuer: String::new(),
            oidc_audience: String::new(),
            oidc_skip_expiry: false,
            oidc_skip_issuer: false,
            oidc_skip_nbf: false,
            additional_data: None,
            oidc_proxy_url: String::new(),
            additional_auth_scopes: Vec::new(),
            authentication_timeout: 300,
            token_auth_timeout: true,
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
    /// Resolve the current auth token.
    ///
    /// When `token_source` is configured, the source is re-read / re-executed
    /// so the latest value is used for each Login, Ping, or NewWorkConn auth
    /// operation. Otherwise the static `token` is returned.
    pub fn resolve_token(&self) -> Result<String, String> {
        match &self.token_source {
            Some(source) => source
                .resolve()
                .map_err(|e| format!("failed to resolve auth.tokenSource: {e}")),
            None => Ok(self.token.clone()),
        }
    }

    /// Validate a login attempt. Returns the subject string (empty for token
    /// auth, populated from JWT 'sub' claim for OIDC). Returns Err if invalid.
    pub fn validate_login(
        &self,
        privilege_key: Option<&str>,
        timestamp: Option<i64>,
    ) -> Result<String, String> {
        let token = self.resolve_token()?;
        self.validate_login_with_token(token.as_str(), privilege_key, timestamp)
    }

    /// Validate a login attempt against an already-resolved token.
    /// Used by callers that resolve a dynamic source once before validation.
    pub fn validate_login_with_token(
        &self,
        token: &str,
        privilege_key: Option<&str>,
        timestamp: Option<i64>,
    ) -> Result<String, String> {
        if token.is_empty() && self.method == AuthMethod::Token {
            return Err(
                "authentication token is empty. When auth.method = 'token', \
                 you must set auth.token / auth.tokenSource in the config file or use the \
                 --token CLI flag. An empty token would accept ALL connections."
                    .to_string(),
            );
        }

        let key = privilege_key.unwrap_or("");

        match self.method {
            AuthMethod::Token => {
                let ts = match timestamp {
                    Some(t) => t,
                    None => return Err("timestamp required for authentication".into()),
                };
                // Go frp compat: token auth does NOT check timestamp freshness.
                // Go frp's VerifyLogin only checks MD5(token+timestamp) equality;
                // timestamp is included in the hash itself, so replay protection
                // relies on the server rejecting duplicate timestamps (not freshness).
                // frp-rs strips authentication_timeout from token path to match
                // Go behavior — OIDC path keeps the check.
                let expected = generate_token(token, ts);
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
        match self.try_generate_login_key(timestamp) {
            Ok(key) => Some(key),
            Err(e) => {
                tracing::warn!(error = %e, "generate_login_key failed: {e}");
                None
            }
        }
    }

    /// Resolve the current token and generate the privilege_key for a login
    /// message, returning an error when the dynamic source cannot be resolved.
    pub fn try_generate_login_key(&self, timestamp: i64) -> Result<String, String> {
        let token = self.resolve_token()?;
        if token.is_empty() {
            return Err(
                "authentication token is empty. When auth.method = 'token', \
                 you must set auth.token or auth.tokenSource in the config file."
                    .into(),
            );
        }
        match self.method {
            AuthMethod::Token => Ok(generate_token(&token, timestamp)),
            #[cfg(feature = "oidc")]
            AuthMethod::Oidc => Err("OIDC auth does not use token login keys".into()),
        }
    }

    /// Check for critical security misconfigurations at startup.
    /// Call this at server startup to reject dangerously insecure configurations.
    pub fn check_startup(&self) -> Result<(), String> {
        if self.method == AuthMethod::Token {
            let token = self.resolve_token()?;
            if token.is_empty() {
                return Err("CRITICAL: [auth].token / auth.tokenSource resolved empty with token auth method — server would accept ALL connections. Set a strong token in the config file.".into());
            }
        }
        // OIDC configuration validation.
        #[cfg(feature = "oidc")]
        if self.method == AuthMethod::Oidc {
            if self.oidc_issuer.is_empty() {
                return Err(
                    "CRITICAL: [auth].oidc_issuer is empty with OIDC auth method. \
                     Set oidc_issuer to your OIDC provider URL."
                        .into(),
                );
            }
            if self.oidc_audience.is_empty() {
                return Err(
                    "CRITICAL: [auth].oidc_audience is empty with OIDC auth method. \
                     Set oidc_audience to the expected audience claim."
                        .into(),
                );
            }
            if self.oidc_skip_expiry && self.oidc_skip_issuer {
                tracing::warn!(
                    "SECURITY WARNING: both oidc_skip_expiry and oidc_skip_issuer are true. \
                     JWT expiry AND issuer validation are disabled — any validly-signed JWT \
                     from any issuer will be accepted indefinitely. This should only be used \
                     in development environments."
                );
            }
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
        /// JWT ID claim ("jti"), when present in the token. Used for replay
        /// protection (see `OidcVerifier::check_replay`).
        pub jti: Option<String>,
    }

    /// Cached JWKS keys.
    struct CachedJwks {
        keys: serde_json::Value,
        fetched_at: std::time::Instant,
        refresh_after: std::time::Duration,
    }

    /// Internal verification error that also records whether a JWKS refresh
    /// could plausibly fix the failure (signature/key material changed) as
    /// opposed to a semantic token error (expired, missing claims, etc.).
    struct OidcVerifyError {
        message: String,
        refresh_warranted: bool,
    }

    pub(crate) fn is_key_related_error(err: &jsonwebtoken::errors::Error) -> bool {
        use jsonwebtoken::errors::ErrorKind;
        matches!(
            err.kind(),
            ErrorKind::InvalidSignature
                | ErrorKind::InvalidRsaKey(_)
                | ErrorKind::InvalidEcdsaKey
                | ErrorKind::InvalidKeyFormat
                | ErrorKind::InvalidAlgorithm
                | ErrorKind::Crypto(_)
        )
    }

    /// Hard cap on the replay-protection cache entry count. Lazy 24h-TTL
    /// pruning alone cannot bound memory when a holder of valid signed tokens
    /// submits many unique jtis (login throttling was removed); at capacity the
    /// soonest-expiring entry is evicted to make room for the new jti.
    const MAX_SEEN_JTIS: usize = 100_000;

    /// Server-side OIDC verifier. Discovers JWKS from issuer, verifies JWT tokens,
    /// and enforces subject binding for ping/NewWorkConn.
    pub struct OidcVerifier {
        audience: String,
        issuer: String,
        jwks_uri: String,
        jwks: tokio::sync::RwLock<Option<CachedJwks>>,
        skip_expiry: bool,
        skip_issuer: bool,
        skip_nbf: bool,
        http: crate::http_client::HttpClient,
        /// Replay-protection cache: jti → (subject, deadline_unix_seconds).
        /// A jti seen with a different subject is rejected; the same jti with
        /// the same subject is allowed (frpc reconnects reuse the cached token).
        seen_jtis: std::sync::Mutex<std::collections::HashMap<String, (String, i64)>>,
    }

    impl OidcVerifier {
        /// Create new OidcVerifier. Discovers JWKS URI from issuer's
        /// .well-known/openid-configuration and fetches initial keys.
        pub async fn new(
            issuer: String,
            audience: String,
            skip_expiry: bool,
            skip_issuer: bool,
            skip_nbf: bool,
            proxy_url: Option<String>,
        ) -> Result<Self, String> {
            if proxy_url.as_ref().is_some_and(|u| !u.is_empty()) {
                return Err(
                    "OIDC: HTTP proxy is not yet supported. Remove proxy_url from OIDC config."
                        .into(),
                );
            }
            let http = crate::http_client::HttpClientBuilder::new()
                .timeout(std::time::Duration::from_secs(10))
                .build()?;

            let config_url = format!(
                "{}/.well-known/openid-configuration",
                issuer.trim_end_matches('/')
            );
            let resp = http.get(&config_url).await.map_err(|e| {
                format!("OIDC: failed to fetch openid-configuration from {config_url}: {e}")
            })?;

            if !resp.status().is_success() {
                return Err(format!(
                    "OIDC: openid-configuration returned {}",
                    resp.status()
                ));
            }

            let body = resp
                .text()
                .await
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
                skip_nbf,
                http,
                seen_jtis: std::sync::Mutex::new(std::collections::HashMap::new()),
            };

            if verifier.skip_expiry {
                tracing::warn!("OIDC: skip_expiry is enabled — expired tokens will be accepted. This weakens authentication security.");
            }
            if verifier.skip_issuer {
                tracing::warn!("OIDC: skip_issuer is enabled — tokens from any issuer will be accepted. This weakens authentication security.");
            }
            if verifier.skip_nbf {
                tracing::warn!("OIDC: skip_nbf is enabled — tokens issued in the future will be accepted. This weakens authentication security.");
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
            let resp =
                self.http.get(&self.jwks_uri).await.map_err(|e| {
                    format!("OIDC: failed to fetch JWKS from {}: {e}", self.jwks_uri)
                })?;

            if !resp.status().is_success() {
                return Err(format!("OIDC: JWKS endpoint returned {}", resp.status()));
            }

            let body = resp
                .text()
                .await
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
        pub(crate) fn decoding_key_from_jwk(
            key: &serde_json::Value,
        ) -> Result<jsonwebtoken::DecodingKey, String> {
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
                "OKP" => {
                    let crv = key["crv"].as_str().ok_or("OIDC: missing OKP crv in JWK")?;
                    if crv != "Ed25519" {
                        return Err(format!("OIDC: unsupported OKP curve: {crv}"));
                    }
                    let x = key["x"].as_str().ok_or("OIDC: missing OKP x in JWK")?;
                    jsonwebtoken::DecodingKey::from_ed_components(x)
                        .map_err(|e| format!("OIDC: invalid OKP/Ed25519 JWK: {e}"))
                }
                _ => Err(format!("OIDC: unsupported JWK key type: {kty}")),
            }
        }

        /// Verify a login JWT. Returns LoginOidcToken with subject and expiry.
        ///
        /// # Security: jti replay prevention
        ///
        /// Implemented via `check_replay`, called by the server after this
        /// method succeeds. Semantics (user-approved): a jti reused with the
        /// same subject is allowed — frpc caches the OIDC token until expiry
        /// and legitimately re-sends it on reconnect (and for Ping/NewWorkConn);
        /// a jti reused with a different subject is rejected as a cross-identity
        /// replay. Tokens without a jti claim are allowed (documented
        /// limitation — they cannot be tracked; TLS + exp remain the primary
        /// defenses). The cache holds each jti until `expiry + leeway` (or a
        /// fixed TTL when exp is absent) and prunes expired entries lazily on
        /// each call, so it never grows unbounded. Go frp v0.70.1 has no jti
        /// check — this is a frp-rs-specific defense-in-depth measure.
        pub async fn verify_login(&self, token: &str) -> Result<LoginOidcToken, String> {
            let header = jsonwebtoken::decode_header(token)
                .map_err(|e| format!("OIDC: failed to decode JWT header: {e}"))?;

            let alg = header.alg;
            let kid = header.kid.clone();

            // Allowlist of known JWT algorithms. Includes symmetric HMAC algorithms
            // (HS256, HS384, HS512) for oct-key use cases (shared secret JWKs).
            // Algorithm confusion (e.g. HS256 with RSA public key) is prevented by
            // jsonwebtoken's algorithm-vs-key-type verification: an RSA key cannot
            // verify an HMAC signature and vice versa. This allowlist provides
            // defense-in-depth on top of that library-level check.
            const ALLOWED_ALGS: &[jsonwebtoken::Algorithm] = &[
                jsonwebtoken::Algorithm::HS256,
                jsonwebtoken::Algorithm::HS384,
                jsonwebtoken::Algorithm::HS512,
                jsonwebtoken::Algorithm::RS256,
                jsonwebtoken::Algorithm::RS384,
                jsonwebtoken::Algorithm::RS512,
                jsonwebtoken::Algorithm::ES256,
                jsonwebtoken::Algorithm::ES384,
                jsonwebtoken::Algorithm::PS256,
                jsonwebtoken::Algorithm::PS384,
                jsonwebtoken::Algorithm::PS512,
                jsonwebtoken::Algorithm::EdDSA,
            ];
            if !ALLOWED_ALGS.contains(&alg) {
                return Err(format!("OIDC: algorithm {alg:?} not allowed"));
            }

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
            validation.validate_nbf = !self.skip_nbf;
            if !self.skip_issuer {
                validation.set_issuer(&[&self.issuer]);
            }
            validation.set_audience(&[&self.audience]);
            // Require the "sub" (subject) claim in OIDC tokens. Without this,
            // a JWT that omits "sub" would be accepted with an empty subject,
            // potentially bypassing subject-based proxy routing.
            validation.required_spec_claims.insert("sub".to_string());

            // First attempt with cached JWKS
            let first_result = self
                .try_verify_token(token, &validation, kid.as_deref())
                .await;

            match first_result {
                Ok(tok) => Ok(tok),
                Err(first_err) => {
                    // Refresh JWKS and retry once, but only when the failure
                    // could be caused by stale/rotated key material. Semantic
                    // errors (expired token, wrong issuer/audience, missing
                    // claims) must not trigger outbound JWKS refreshes.
                    if !first_err.refresh_warranted {
                        return Err(first_err.message);
                    }
                    self.refresh_jwks().await?;
                    self.try_verify_token(token, &validation, kid.as_deref())
                        .await
                        .map_err(|_| first_err.message)
                }
            }
        }

        /// Try to verify a token against currently cached JWKS.
        async fn try_verify_token(
            &self,
            token: &str,
            validation: &jsonwebtoken::Validation,
            kid: Option<&str>,
        ) -> Result<LoginOidcToken, OidcVerifyError> {
            let cache = self.jwks.read().await;
            let jwks = cache.as_ref().ok_or_else(|| OidcVerifyError {
                message: "OIDC: no JWKS cached".to_string(),
                refresh_warranted: true,
            })?;
            let keys = jwks.keys["keys"]
                .as_array()
                .ok_or_else(|| OidcVerifyError {
                    message: "OIDC: JWKS has no 'keys' array".to_string(),
                    refresh_warranted: true,
                })?;

            let mut last_err = String::new();
            let mut refresh_warranted = false;

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
                        refresh_warranted = true;
                        continue;
                    }
                };

                match jsonwebtoken::decode::<serde_json::Value>(token, &decoding_key, validation) {
                    Ok(data) => {
                        let sub = data.claims["sub"].as_str().unwrap_or("").to_string();
                        // Reject tokens with an empty subject — "sub" is
                        // required_spec_claims so it will exist, but it
                        // could still be the empty string.
                        if sub.is_empty() {
                            last_err = "OIDC: JWT subject (sub) is empty".to_string();
                            refresh_warranted = false;
                            continue;
                        }
                        let exp = data.claims["exp"].as_i64().unwrap_or(0);
                        let jti = data.claims["jti"].as_str().map(|s| s.to_string());
                        return Ok(LoginOidcToken {
                            subject: sub,
                            expiry: exp,
                            jti,
                        });
                    }
                    Err(e) => {
                        last_err = e.to_string();
                        refresh_warranted = is_key_related_error(&e);
                    }
                }
            }

            Err(OidcVerifyError {
                message: format!("OIDC: JWT verification failed: {last_err}"),
                refresh_warranted,
            })
        }

        /// Check a verified login token's jti for replay. Semantics (user-approved):
        /// same jti + same subject → allowed (frpc reconnects reuse the cached token);
        /// same jti + different subject → rejected (cross-identity replay). Tokens
        /// without a jti claim are allowed (cannot be tracked — documented limitation;
        /// TLS + exp remain the primary defenses). The cache holds each jti until
        /// `expiry + leeway` (or a fixed TTL when exp is absent or already past),
        /// prunes expired entries lazily on each call, and caps the entry count
        /// (`MAX_SEEN_JTIS`), evicting the soonest-expiring entry when full.
        pub fn check_replay(
            &self,
            jti: Option<&str>,
            subject: &str,
            expiry: i64,
        ) -> Result<(), String> {
            let Some(jti) = jti else {
                // No jti claim: nothing to track. This is a documented limitation —
                // such tokens cannot be replayed-detected, so TLS + exp stay the
                // primary defenses.
                return Ok(());
            };

            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            // Keep the jti in the cache until exp (+ leeway aligned with
            // jsonwebtoken's default 60s clock skew). Without an exp claim —
            // or when exp is already in the past (skip_expiry accepting
            // expired tokens) — fall back to a fixed 1h TTL so the entry is
            // actually tracked instead of being pruned on the next call. The
            // deadline is capped at 24h so a far-future `exp` cannot make the
            // cache grow unbounded — replay protection only needs to cover
            // the token's realistic lifetime.
            const MAX_JTI_TTL_SECS: i64 = 24 * 3600;
            let deadline = if expiry > now {
                (expiry + 60).min(now + MAX_JTI_TTL_SECS)
            } else {
                now + 3600
            };

            let mut seen = self.seen_jtis.lock().unwrap_or_else(|e| e.into_inner());
            // Lazy pruning of expired entries prevents unbounded growth.
            seen.retain(|_, (_, d)| *d > now);

            match seen.get(jti) {
                Some((stored_subject, _)) if stored_subject == subject => Ok(()),
                Some(_) => Err(format!(
                    "OIDC: JWT jti {jti} reused with a different subject (replay suspected)"
                )),
                None => {
                    if seen.len() >= MAX_SEEN_JTIS {
                        // Cache is at its size cap: evict the entry whose
                        // deadline is soonest (keeps tracking of the longest
                        // lived jtis), then insert the new one. This bounds
                        // memory even under a flood of unique jtis.
                        if let Some(oldest) = seen
                            .iter()
                            .min_by_key(|(_, (_, d))| *d)
                            .map(|(k, _)| k.clone())
                        {
                            seen.remove(&oldest);
                        }
                    }
                    seen.insert(jti.to_string(), (subject.to_string(), deadline));
                    Ok(())
                }
            }
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
        pub async fn verify_new_work_conn(
            &self,
            token: &str,
            expected_sub: &str,
        ) -> Result<(), String> {
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
    ///
    /// Go frp compat: when the token endpoint omits `expires_in`, the cache is
    /// skipped entirely (nonCachingTokenSource) because we cannot know when the
    /// token expires. Without a known expiry, caching risks accepting a revoked
    /// token. Each call fetches a fresh token instead.
    pub struct OidcClient {
        token_endpoint: String,
        client_id: String,
        client_secret: String,
        audience: String,
        scope: String,
        additional_params: Vec<(String, String)>,
        /// Go frp v0.70.1 compat: auth.oidc.tokenSource — a dynamic source
        /// for the access token. Mutually exclusive with all other fields.
        token_source: Option<crate::config::ValueSource>,
        cached: tokio::sync::Mutex<Option<CachedOidcToken>>,
        /// Set to true when the token endpoint omits `expires_in`.
        /// When true, get_token() bypasses the cache and always fetches a fresh token.
        non_caching: std::sync::atomic::AtomicBool,
        http: crate::http_client::HttpClient,
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
            additional_endpoint_params: &std::collections::HashMap<String, String>,
            tls_trusted_ca_file: Option<String>,
            tls_insecure_skip_verify: bool,
            proxy_url: Option<String>,
            token_source: Option<crate::config::ValueSource>,
        ) -> Result<Self, String> {
            if proxy_url.as_ref().is_some_and(|u| !u.is_empty()) {
                return Err(
                    "OIDC client: HTTP proxy is not yet supported. Remove proxy_url from OIDC client config."
                        .into(),
                );
            }

            let ca_cert_pem =
                if let Some(ref ca_file) = tls_trusted_ca_file.filter(|f| !f.is_empty()) {
                    Some(std::fs::read(ca_file).map_err(|e| {
                        format!("OIDC client: failed to read CA cert {ca_file}: {e}")
                    })?)
                } else {
                    None
                };

            if tls_insecure_skip_verify {
                tracing::warn!("OIDC: tls_insecure_skip_verify is enabled — TLS certificate verification is disabled. This weakens authentication security.");
            }

            let http = crate::http_client::HttpClientBuilder::new()
                .timeout(std::time::Duration::from_secs(10))
                .tls_ca_cert_pem(ca_cert_pem)
                .tls_skip_verify(tls_insecure_skip_verify)
                .build()?;

            let endpoint = if token_source.is_some() {
                // Go frp v0.70.1 compat: auth.oidc.tokenSource resolves the
                // token dynamically; no token endpoint is needed.
                String::new()
            } else if let Some(ep) = token_endpoint.filter(|s| !s.is_empty()) {
                ep
            } else if let Some(iss) = issuer.filter(|s| !s.is_empty()) {
                let config_url = format!(
                    "{}/.well-known/openid-configuration",
                    iss.trim_end_matches('/')
                );
                let resp = http.get(&config_url).await.map_err(|e| {
                    format!(
                        "OIDC client: failed to fetch openid-configuration from {config_url}: {e}"
                    )
                })?;

                if !resp.status().is_success() {
                    return Err(format!(
                        "OIDC client: openid-configuration returned {}",
                        resp.status()
                    ));
                }

                let body = resp.text().await.map_err(|e| {
                    format!("OIDC client: failed to read openid-configuration: {e}")
                })?;
                let config: serde_json::Value = serde_json::from_str(&body).map_err(|e| {
                    format!("OIDC client: failed to parse openid-configuration: {e}")
                })?;

                config["token_endpoint"]
                    .as_str()
                    .ok_or_else(|| {
                        "OIDC client: token_endpoint not found in openid-configuration".to_string()
                    })?
                    .to_string()
            } else {
                return Err("OIDC client: token_endpoint or issuer is required".into());
            };

            let scope = if scope.is_empty() {
                "openid".to_string()
            } else {
                scope
            };

            // Parse additional endpoint params (Go: map[string]string).
            let additional_params: Vec<(String, String)> = additional_endpoint_params
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();

            Ok(Self {
                token_endpoint: endpoint,
                client_id,
                client_secret,
                audience,
                scope,
                additional_params,
                token_source,
                cached: tokio::sync::Mutex::new(None),
                non_caching: std::sync::atomic::AtomicBool::new(false),
                http,
            })
        }

        async fn fetch_token(&self) -> Result<(String, u64), String> {
            let mut params: Vec<(&str, &str)> = vec![
                ("grant_type", "client_credentials"),
                ("client_id", self.client_id.as_str()),
                ("client_secret", self.client_secret.as_str()),
                ("scope", self.scope.as_str()),
            ];
            // Go frp compat (oidc.go:137-139): omit the audience parameter
            // when empty instead of sending an empty value.
            if !self.audience.is_empty() {
                params.push(("audience", self.audience.as_str()));
            }
            let extra: Vec<(&str, &str)> = self
                .additional_params
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect();
            params.extend_from_slice(&extra);

            let resp = self
                .http
                .post_form(&self.token_endpoint, &params)
                .await
                .map_err(|e| {
                    format!(
                        "OIDC client: token request to {} failed: {e}",
                        self.token_endpoint
                    )
                })?;

            if !resp.status().is_success() {
                let body = resp.text().await.unwrap_or_default();
                return Err(format!(
                    "OIDC client: token endpoint returned error: {body}"
                ));
            }

            let resp_text = resp
                .text()
                .await
                .map_err(|e| format!("OIDC client: failed to read token response: {e}"))?;
            let body: serde_json::Value = serde_json::from_str(&resp_text)
                .map_err(|e| format!("OIDC client: failed to parse token response: {e}"))?;

            let token = body["access_token"]
                .as_str()
                .ok_or_else(|| "OIDC client: access_token not found in response".to_string())?
                .to_string();

            // Parse expires_in from response (some providers omit this field).
            // Go frp compat: when expires_in is absent, fall back to
            // nonCachingTokenSource — we cannot know when the token expires
            // so every call fetches a fresh one.
            let expires_in_present = body.get("expires_in").and_then(|v| v.as_u64());
            match expires_in_present {
                Some(secs) => {
                    // Subtract 60s refresh buffer to avoid edge-of-expiry failures.
                    let expires_in = secs.saturating_sub(60);
                    Ok((token, expires_in))
                }
                None => {
                    // Provider omitted expires_in: switch to non-caching mode.
                    self.non_caching
                        .store(true, std::sync::atomic::Ordering::Relaxed);
                    tracing::debug!(
                        "OIDC token endpoint omitted expires_in: switching to non-caching mode"
                    );
                    Ok((token, 0))
                }
            }
        }

        /// Get a valid access token — uses cached if not expired, fetches new otherwise.
        /// Automatically refreshes when token is within 60s of expiry.
        /// Falls back to non-caching (always fetch) when expires_in was omitted.
        /// When a tokenSource is configured, resolves it instead (Go
        /// OidcTokenSourceAuthProvider compat).
        async fn get_token(&self) -> Result<String, String> {
            if let Some(ref source) = self.token_source {
                // Go oidc.go:232-238: resolve the ValueSource for the token.
                return source
                    .resolve()
                    .map_err(|e| format!("failed to resolve auth.oidc.tokenSource: {e}"));
            }

            // Go frp compat: non-caching mode — always fetch a fresh token.
            if self.non_caching.load(std::sync::atomic::Ordering::Relaxed) {
                let (token, _expires_in) = self.fetch_token().await?;
                return Ok(token);
            }

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
        /// Go frp compat: preserves the caller-provided timestamp
        /// (Go oidc.go SetLogin only sets PrivilegeKey).
        pub async fn set_login(&self, login: &mut crate::msg::Login) -> Result<(), String> {
            let token = self.get_token().await?;
            login.privilege_key = Some(token);
            Ok(())
        }

        /// Set privilege_key on a Ping message using an OIDC token.
        /// Go frp compat: preserves the caller-provided timestamp.
        pub async fn set_ping(&self, ping: &mut crate::msg::Ping) -> Result<(), String> {
            let token = self.get_token().await?;
            ping.privilege_key = Some(token);
            Ok(())
        }

        /// Set privilege_key on a NewWorkConn message using an OIDC token.
        /// Go frp compat: preserves the caller-provided timestamp.
        pub async fn set_new_work_conn(
            &self,
            nwc: &mut crate::msg::NewWorkConn,
        ) -> Result<(), String> {
            let token = self.get_token().await?;
            nwc.privilege_key = Some(token);
            Ok(())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// Build an `OidcVerifier` without any network I/O. The real `new()`
        /// fetches openid-configuration and JWKS; `check_replay` only touches
        /// `seen_jtis`, so it is testable in isolation.
        fn test_verifier() -> OidcVerifier {
            OidcVerifier {
                audience: String::new(),
                issuer: String::new(),
                jwks_uri: String::new(),
                jwks: tokio::sync::RwLock::new(None),
                skip_expiry: false,
                skip_issuer: false,
                skip_nbf: false,
                http: crate::http_client::HttpClientBuilder::new()
                    .tls_skip_verify(true)
                    .build()
                    .expect("test HTTP client"),
                seen_jtis: std::sync::Mutex::new(std::collections::HashMap::new()),
            }
        }

        fn now() -> i64 {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64
        }

        #[test]
        fn check_replay_same_subject_reuse_allowed() {
            let v = test_verifier();
            // frpc reconnect reuses the cached token with the same jti+subject.
            assert!(v.check_replay(Some("jti-1"), "alice", now() + 3600).is_ok());
            assert!(v.check_replay(Some("jti-1"), "alice", now() + 3600).is_ok());
        }

        #[test]
        fn check_replay_different_subject_rejected() {
            let v = test_verifier();
            assert!(v.check_replay(Some("jti-2"), "alice", now() + 3600).is_ok());
            let err = v
                .check_replay(Some("jti-2"), "mallory", now() + 3600)
                .expect_err("jti reused with a different subject must be rejected");
            assert!(err.contains("replay"), "unexpected error message: {err}");
        }

        #[test]
        fn check_replay_no_jti_allowed() {
            let v = test_verifier();
            // Tokens without a jti claim cannot be tracked — documented limitation.
            assert!(v.check_replay(None, "alice", now() + 3600).is_ok());
            assert!(v.seen_jtis.lock().unwrap().is_empty());
        }

        #[test]
        fn check_replay_expired_entry_pruned() {
            let v = test_verifier();
            // Pre-seed an entry whose deadline is already in the past. The next
            // call must prune it lazily, then accept the jti as a new entry.
            v.seen_jtis
                .lock()
                .unwrap()
                .insert("jti-old".to_string(), ("alice".to_string(), now() - 1));
            assert!(v
                .check_replay(Some("jti-old"), "alice", now() + 3600)
                .is_ok());
            assert_eq!(v.seen_jtis.lock().unwrap().len(), 1);
        }

        #[test]
        fn check_replay_caps_entry_count() {
            let v = test_verifier();
            let now = now();
            // Pre-fill the cache to its size cap with unexpired entries, then
            // insert one more jti. The cache must stay bounded and still track
            // the newest jti (the soonest-expiring entry is evicted to make
            // room).
            {
                let mut seen = v.seen_jtis.lock().unwrap();
                for i in 0..MAX_SEEN_JTIS {
                    seen.insert(format!("pre-jti-{i}"), ("alice".to_string(), now + 100_000));
                }
                assert_eq!(seen.len(), MAX_SEEN_JTIS);
            }
            assert!(v.check_replay(Some("new-jti"), "alice", now + 3600).is_ok());
            let seen = v.seen_jtis.lock().unwrap();
            assert!(seen.len() <= MAX_SEEN_JTIS);
            assert!(seen.contains_key("new-jti"));
        }

        #[test]
        fn check_replay_past_exp_uses_fixed_ttl() {
            let v = test_verifier();
            let now = now();
            // An expired `exp` (e.g. accepted via skip_expiry) must still be
            // tracked: fall back to the fixed 1h TTL instead of computing a
            // deadline in the past that would be pruned on the next call.
            assert!(v
                .check_replay(Some("jti-expired"), "alice", now - 100)
                .is_ok());
            let seen = v.seen_jtis.lock().unwrap();
            let deadline = seen.get("jti-expired").map(|(_, d)| *d);
            assert!(
                deadline.is_some_and(|d| d > now),
                "expired-exp jti must be tracked with a deadline in the future"
            );
        }
    }
}

#[cfg(feature = "oidc")]
pub use oidc_impl::{LoginOidcToken, OidcClient, OidcVerifier};

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
    pub jti: Option<String>,
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
    pub async fn set_new_work_conn(
        &self,
        _nwc: &mut crate::msg::NewWorkConn,
    ) -> Result<(), String> {
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
    pub async fn verify_new_work_conn(
        &self,
        _token: &str,
        _expected_sub: &str,
    ) -> Result<(), String> {
        Err("OIDC feature disabled at compile time".into())
    }
    /// Stub — jti replay checking is unreachable when the oidc feature is
    /// disabled (AuthMethod::Oidc is compiled out).
    pub fn check_replay(
        &self,
        _jti: Option<&str>,
        _subject: &str,
        _expiry: i64,
    ) -> Result<(), String> {
        Ok(())
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
    //
    // We use core::ptr::write_volatile in a manual loop rather than
    // Vec::fill(0) because LLVM can eliminate a plain memset as a dead
    // store when the allocation is freed immediately after (as happens in
    // AuthConfig::drop).  write_volatile forces the store to survive
    // optimisation, which is the whole point of the zeroize primitive.
    unsafe {
        let v = s.as_mut_vec();
        let len = v.len();
        let ptr = v.as_mut_ptr();
        for i in 0..len {
            core::ptr::write_volatile(ptr.add(i), 0u8);
        }
    }
    // Clear len so the now-zeroed bytes are not accidentally re-read.
    s.clear();
}

/// Resolve a dynamic token with `UnsafeFeatures` enforcement.
///
/// When the token uses `exec://`, the `TokenSourceExec` feature
/// must be enabled in `unsafe_features`. If the feature is not allowed,
/// an error is returned.
///
/// `file://` tokens do NOT require an unsafe feature — reading a file
/// is not command execution. This matches Go frp behavior where both
/// `file://` and `exec://` work unconditionally.
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
        // Go frp v0.70.1: only exec token sources require the unsafe-features
        // gate (validation/client.go validateOIDCConfig + token.go); file
        // sources are always allowed.
        let _ = unsafe_features;
        match std::fs::read_to_string(path) {
            Ok(content) => Ok(content.lines().next().unwrap_or("").trim().to_string()),
            Err(e) => Err(format!(
                "Failed to read dynamic token from file://{}: {}",
                path, e
            )),
        }
    } else if let Some(cmd) = token.strip_prefix("exec://") {
        if unsafe_features
            .is_some_and(|uf| !uf.is_enabled(crate::unsafe_features::TOKEN_SOURCE_EXEC))
        {
            return Err(
                "exec:// token source blocked: TokenSourceExec not in UnsafeFeatures allowlist. \
                 Set [common].unsafe_features = [\"TokenSourceExec\"] to enable."
                    .into(),
            );
        }
        let parts: Vec<&str> = cmd.split_whitespace().collect();
        if parts.is_empty() {
            return Err("Dynamic token exec:// with empty command".into());
        }
        // Prefer the async path (tokio::process::Command) when running on a
        // multi-thread tokio runtime so no worker thread is parked on
        // child-process wait. `block_in_place` hands the current worker back
        // to the runtime, then `Handle::block_on` drives the async spawn on
        // this thread (the pattern tokio documents for re-entering the async
        // context of a multi-thread runtime). The synchronous spawn remains
        // as a fallback for callers outside any runtime (unit tests) and for
        // current-thread runtimes, where `block_in_place` would panic.
        let output = match tokio::runtime::Handle::try_current() {
            Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
                tokio::task::block_in_place(|| handle.block_on(exec_token_command_async(&parts)))
            }
            _ => exec_token_command_sync(&parts),
        };
        match output {
            Ok(o) => finish_exec_output(cmd, o),
            Err(e) => Err(format!(
                "Failed to exec dynamic token command '{}': {}",
                cmd, e
            )),
        }
    } else {
        Ok(token.to_string())
    }
}

/// Run the exec:// token command via `tokio::process`, so `wait_with_output`
/// parks the runtime's process driver instead of a worker thread. Returns a
/// `std::process::Output` so both paths share `finish_exec_output`.
async fn exec_token_command_async(parts: &[&str]) -> std::io::Result<std::process::Output> {
    tokio::process::Command::new(parts[0])
        .args(&parts[1..])
        .output()
        .await
}

/// Synchronous fallback used when no multi-thread tokio runtime is available.
fn exec_token_command_sync(parts: &[&str]) -> std::io::Result<std::process::Output> {
    std::process::Command::new(parts[0])
        .args(&parts[1..])
        .output()
}

/// Shared post-processing for both exec paths: check exit status, take the
/// first stdout line and trim it (Go frp `getFirstLine` semantics).
fn finish_exec_output(cmd: &str, o: std::process::Output) -> Result<String, String> {
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

impl crate::config::ValueSource {
    /// Resolve the current value from the configured source.
    /// File sources read and trim the file; exec sources run the command and
    /// trim stdout.
    pub fn resolve(&self) -> Result<String, String> {
        self.validate()
            .map_err(|e| format!("invalid auth.tokenSource: {e}"))?;
        match self.source_type.as_str() {
            "file" => {
                let path = &self.file.as_ref().expect("validated").path;
                std::fs::read_to_string(path)
                    .map(|content| content.trim().to_string())
                    .map_err(|e| format!("failed to read file {path}: {e}"))
            }
            "exec" => {
                let exec = self.exec.as_ref().expect("validated");
                const EXEC_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
                // On tokio multi-thread: block_in_place + Handle::block_on so the
                // child-process wait parks the driver, not a worker.
                if tokio::runtime::Handle::try_current()
                    .is_ok_and(|h| h.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread)
                {
                    return tokio::task::block_in_place(|| {
                        let rt = tokio::runtime::Handle::current();
                        let _guard = rt.enter();
                        let output = rt.block_on(async {
                            tokio::time::timeout(EXEC_TIMEOUT, async {
                                let child = tokio::process::Command::new(&exec.command)
                                    .args(&exec.args)
                                    .envs(exec.env.iter().map(|e| (&e.name, &e.value)))
                                    .stdout(std::process::Stdio::piped())
                                    .stderr(std::process::Stdio::piped())
                                    .kill_on_drop(true)
                                    .spawn()
                                    .map_err(|e| {
                                        format!("failed to execute command {}: {e}", exec.command)
                                    })?;
                                child.wait_with_output().await.map_err(|e| {
                                    format!("failed to execute command {}: {e}", exec.command)
                                })
                            })
                            .await
                        });
                        match output {
                            Ok(Ok(o)) => finish_exec_output(&exec.command, o),
                            Ok(Err(e)) => Err(e),
                            Err(_elapsed) => Err(format!(
                                "failed to execute command {}: timed out after {}s",
                                exec.command,
                                EXEC_TIMEOUT.as_secs()
                            )),
                        }
                    });
                }
                // Sync fallback for no-runtime / current-thread runtime contexts.
                let child = std::process::Command::new(&exec.command)
                    .args(&exec.args)
                    .envs(exec.env.iter().map(|e| (&e.name, &e.value)))
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .spawn()
                    .map_err(|e| format!("failed to execute command {}: {e}", exec.command))?;
                let pid = child.id();
                let (tx, rx) = std::sync::mpsc::channel();
                let waiter = std::thread::spawn(move || {
                    let output = child.wait_with_output();
                    let _ = tx.send(output);
                });
                let output = match rx.recv_timeout(EXEC_TIMEOUT) {
                    Ok(Ok(o)) => {
                        let _ = waiter.join();
                        o
                    }
                    Ok(Err(e)) => {
                        let _ = waiter.join();
                        return Err(format!("failed to execute command {}: {e}", exec.command));
                    }
                    Err(_) => {
                        #[cfg(unix)]
                        {
                            let _ = std::process::Command::new("kill")
                                .args(["-9", &pid.to_string()])
                                .status();
                        }
                        let _ = waiter.join();
                        return Err(format!(
                            "failed to execute command {}: timed out after {}s",
                            exec.command,
                            EXEC_TIMEOUT.as_secs()
                        ));
                    }
                };
                finish_exec_output(&exec.command, output)
            }
            other => Err(format!("unsupported value source type: {other}")),
        }
    }
}

/// Gate exec-based token sources behind the `UnsafeFeatures` allowlist.
/// Go frp v0.70.1 only treats exec sources as unsafe; file sources are allowed.
pub fn validate_token_source_unsafe(
    source: &crate::config::ValueSource,
    unsafe_features: &crate::unsafe_features::UnsafeFeatures,
) -> Result<(), String> {
    if source.source_type == "exec"
        && !unsafe_features.is_enabled(crate::unsafe_features::TOKEN_SOURCE_EXEC)
    {
        return Err(
            "auth.tokenSource exec blocked: TokenSourceExec not in UnsafeFeatures allowlist. \
             Pass --allow-unsafe TokenSourceExec to enable."
                .into(),
        );
    }
    Ok(())
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

    /// Local capture server for OIDC token-endpoint requests. Parses the
    /// application/x-www-form-urlencoded body and exposes the form fields.
    struct TokenEndpointCapture {
        _addr: std::net::SocketAddr,
        /// oneshot receiver receiving the form fields when the server
        /// captures the token request.
        rx: tokio::sync::oneshot::Receiver<std::collections::HashMap<String, String>>,
    }

    impl TokenEndpointCapture {
        async fn start() -> TokenEndpointCapture {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            let (tx, rx) = tokio::sync::oneshot::channel();
            std::thread::spawn(move || {
                // Plain HTTP: read request headers + body, respond 200 JSON.
                // The capture server handles exactly one request.
                if let Some(Ok(mut stream)) = listener.incoming().next() {
                    let mut buf = [0u8; 16384];
                    let n = std::io::Read::read(&mut stream, &mut buf).unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]);
                    let body = req.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
                    let mut form = std::collections::HashMap::new();
                    for pair in body.split('&').filter(|s| !s.is_empty()) {
                        let mut it = pair.splitn(2, '=');
                        let k = it.next().unwrap_or("").to_string();
                        let v = it.next().unwrap_or("").to_string();
                        form.insert(k, v);
                    }
                    let _ = tx.send(form);
                    let _ = std::io::Write::write_all(
                        &mut stream,
                        b"HTTP/1.1 200 OK\r\nContent-Length: 42\r\n\r\n{\"access_token\":\"tok-1\",\"expires_in\":3600}",
                    );
                }
            });
            TokenEndpointCapture { _addr: addr, rx }
        }

        async fn wait(self) -> std::collections::HashMap<String, String> {
            self.rx.await.expect("token endpoint captured a request")
        }
    }

    #[tokio::test]
    #[cfg(feature = "oidc")]
    async fn test_oidc_client_omits_empty_audience_and_sends_additional_params() {
        let capture = TokenEndpointCapture::start().await;
        let endpoint = format!("http://{}/token", capture._addr);

        let client = OidcClient::new(
            "client-1".into(),
            "secret".into(),
            String::new(), // empty audience → must be omitted from the request
            Some(endpoint),
            "openid".into(),
            None,
            &std::collections::HashMap::from([
                ("tenant".to_string(), "acme".to_string()),
                ("region".to_string(), "eu".to_string()),
            ]),
            None,
            false,
            None,
            None,
        )
        .await
        .expect("OidcClient::new");

        let mut login: crate::msg::Login =
            serde_json::from_str(r#"{"timestamp":1234567890}"#).expect("parse Login");
        assert_eq!(login.timestamp, Some(1234567890));
        client
            .set_login(&mut login)
            .await
            .expect("set_login should fetch a token");

        let form = capture.wait().await;
        assert_eq!(
            form.get("grant_type").map(String::as_str),
            Some("client_credentials")
        );
        assert_eq!(form.get("client_id").map(String::as_str), Some("client-1"));
        // Empty audience is omitted entirely (Go oidc.go:137-139).
        assert!(
            !form.contains_key("audience"),
            "empty audience must be omitted: {form:?}"
        );
        // Additional endpoint params are sent as form fields.
        assert_eq!(form.get("tenant").map(String::as_str), Some("acme"));
        assert_eq!(form.get("region").map(String::as_str), Some("eu"));
    }

    #[tokio::test]
    #[cfg(feature = "oidc")]
    async fn test_oidc_client_preserves_timestamp_and_sends_audience_when_set() {
        let capture = TokenEndpointCapture::start().await;
        let endpoint = format!("http://{}/token", capture._addr);

        let client = OidcClient::new(
            "client-1".into(),
            "secret".into(),
            "api-prod".into(), // non-empty audience → sent
            Some(endpoint),
            "openid".into(),
            None,
            &std::collections::HashMap::new(),
            None,
            false,
            None,
            None,
        )
        .await
        .expect("OidcClient::new");

        let mut login: crate::msg::Login =
            serde_json::from_str(r#"{"timestamp":987654321}"#).expect("parse Login");
        client
            .set_login(&mut login)
            .await
            .expect("set_login should fetch a token");

        // Go compat: set_login must NOT clear the caller-provided timestamp.
        assert_eq!(login.timestamp, Some(987654321));

        let form = capture.wait().await;
        assert_eq!(form.get("audience").map(String::as_str), Some("api-prod"));
    }

    #[tokio::test]
    #[cfg(feature = "oidc")]
    async fn test_oidc_client_token_source_resolves_token() {
        // Go frp v0.70.1 compat: auth.oidc.tokenSource resolves the token
        // from a dynamic source instead of the client-credentials flow.
        let dir = tempfile::tempdir().expect("tempdir");
        let token_path = dir.path().join("oidc-token");
        std::fs::write(&token_path, "source-token-123\n").expect("write token file");

        let source = crate::config::ValueSource {
            source_type: "file".into(),
            file: Some(crate::config::FileSource {
                path: token_path.to_str().unwrap().into(),
            }),
            exec: None,
        };

        // No token endpoint needed when a tokenSource is configured.
        let client = OidcClient::new(
            String::new(),
            String::new(),
            String::new(),
            None,
            String::new(),
            None,
            &std::collections::HashMap::new(),
            None,
            false,
            None,
            Some(source),
        )
        .await
        .expect("OidcClient::new with tokenSource");

        let mut login: crate::msg::Login = serde_json::from_str(r#"{}"#).expect("parse Login");
        client
            .set_login(&mut login)
            .await
            .expect("set_login should resolve the source");
        assert_eq!(login.privilege_key.as_deref(), Some("source-token-123"));
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
        // Empty token: login is rejected with a hard error (security fix)
        assert!(empty_cfg.validate_login(None, None).is_err());
    }

    #[test]
    #[cfg(feature = "oidc")]
    fn test_auth_config_oidc_rejects_without_verifier() {
        let cfg = AuthConfig {
            method: AuthMethod::Oidc,
            token: String::new(),
            token_source: None,
            oidc_issuer: "https://issuer.example.com".into(),
            oidc_audience: "my-audience".into(),
            oidc_skip_expiry: false,
            oidc_skip_issuer: false,
            oidc_skip_nbf: false,
            additional_data: None,
            oidc_proxy_url: String::new(),
            additional_auth_scopes: Vec::new(),
            authentication_timeout: 0,
            token_auth_timeout: true,
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
    fn test_decoding_key_from_okp_jwk() {
        // Ed25519 public key from RFC 8032 test vector 1.
        let jwk = serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
        });
        let key = OidcVerifier::decoding_key_from_jwk(&jwk);
        assert!(key.is_ok(), "OKP/Ed25519 JWK should parse: {:?}", key.err());
    }

    #[test]
    #[cfg(feature = "oidc")]
    fn test_decoding_key_from_okp_rejects_unknown_curve() {
        let jwk = serde_json::json!({
            "kty": "OKP",
            "crv": "Ed448",
            "x": "AAAAAAAA"
        });
        let result = OidcVerifier::decoding_key_from_jwk(&jwk);
        let error = result.err().expect("unknown OKP curve must fail");
        assert!(
            error.contains("unsupported OKP curve"),
            "unexpected: {error}"
        );
    }

    #[test]
    #[cfg(feature = "oidc")]
    fn test_key_related_error_classification() {
        use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};

        let future_exp = serde_json::json!({"sub": "user", "exp": 4_102_444_800_u64});
        let token = jsonwebtoken::encode(
            &Header::default(),
            &future_exp,
            &EncodingKey::from_secret(b"correct-key"),
        )
        .expect("encode token");
        let validation = Validation::new(Algorithm::HS256);

        let wrong_key_err = jsonwebtoken::decode::<serde_json::Value>(
            &token,
            &DecodingKey::from_secret(b"wrong-key"),
            &validation,
        )
        .expect_err("wrong key must fail");
        assert!(
            super::oidc_impl::is_key_related_error(&wrong_key_err),
            "signature mismatch should warrant a JWKS refresh: {wrong_key_err}"
        );

        let expired = serde_json::json!({"sub": "user", "exp": 1_000_000_000_u64});
        let expired_token = jsonwebtoken::encode(
            &Header::default(),
            &expired,
            &EncodingKey::from_secret(b"correct-key"),
        )
        .expect("encode expired token");
        let expired_err = jsonwebtoken::decode::<serde_json::Value>(
            &expired_token,
            &DecodingKey::from_secret(b"correct-key"),
            &validation,
        )
        .expect_err("expired token must fail");
        assert!(
            !super::oidc_impl::is_key_related_error(&expired_err),
            "expired token should not trigger a JWKS refresh: {expired_err}"
        );
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
            token_source: None,
            oidc_issuer: String::new(),
            oidc_audience: String::new(),
            oidc_skip_expiry: false,
            oidc_skip_issuer: false,
            oidc_skip_nbf: false,
            additional_data: None,
            oidc_proxy_url: String::new(),
            additional_auth_scopes: Vec::new(),
            authentication_timeout: 0,
            token_auth_timeout: true,
            use_encryption: false,
        };
        assert!(cfg.generate_login_key(100).is_none());
    }

    #[test]
    fn test_auth_config_default_token_auth_timeout() {
        let cfg = AuthConfig::default();
        assert!(cfg.token_auth_timeout);
        let cfg2 = AuthConfig::with_token("test");
        assert!(cfg2.token_auth_timeout);
    }

    #[test]
    #[allow(deprecated)]
    fn test_resolve_dynamic_token_plain() {
        let uf = crate::unsafe_features::UnsafeFeatures::default();
        assert_eq!(
            resolve_dynamic_token_checked("my-token", &uf).unwrap(),
            "my-token"
        );
        assert_eq!(resolve_dynamic_token_checked("", &uf).unwrap(), "");
    }

    #[test]
    fn test_resolve_dynamic_token_file() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("frp-test-token-{}.txt", std::process::id()));
        std::fs::write(&path, "file-token-value\n").unwrap();
        let url = format!("file://{}", path.display());
        let uf = crate::unsafe_features::UnsafeFeatures::default();
        assert_eq!(
            resolve_dynamic_token_checked(&url, &uf).unwrap(),
            "file-token-value"
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_resolve_dynamic_token_file_multiline() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("frp-test-token-multi-{}.txt", std::process::id()));
        std::fs::write(&path, "first-line\nsecond-line\n").unwrap();
        let url = format!("file://{}", path.display());
        let uf = crate::unsafe_features::UnsafeFeatures::default();
        assert_eq!(
            resolve_dynamic_token_checked(&url, &uf).unwrap(),
            "first-line"
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_resolve_dynamic_token_file_missing() {
        let uf = crate::unsafe_features::UnsafeFeatures::default();
        let result = resolve_dynamic_token_checked("file:///nonexistent/path/token.txt", &uf);
        assert!(result.is_err());
    }

    #[test]
    fn test_resolve_dynamic_token_exec() {
        // Use /bin/echo on Unix — portable across macOS and Linux
        let uf = crate::unsafe_features::UnsafeFeatures::new(
            crate::unsafe_features::CLIENT_UNSAFE_FEATURES,
        );
        let result = resolve_dynamic_token_checked("exec:///bin/echo dynamic-token-value", &uf);
        assert_eq!(result.unwrap(), "dynamic-token-value");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_resolve_dynamic_token_exec_on_runtime() {
        // Executed from inside a spawned worker task (not the block_on entry
        // point) so the `block_in_place` + `Handle::block_on` async path is
        // exercised: the exec must resolve without blocking the worker.
        let uf = crate::unsafe_features::UnsafeFeatures::new(
            crate::unsafe_features::CLIENT_UNSAFE_FEATURES,
        );
        let result = tokio::spawn(async move {
            resolve_dynamic_token_checked("exec:///bin/echo runtime-token-value", &uf)
        })
        .await
        .unwrap();
        assert_eq!(result.unwrap(), "runtime-token-value");
    }

    #[test]
    fn test_resolve_dynamic_token_exec_blocked_when_not_allowed() {
        let uf = crate::unsafe_features::UnsafeFeatures::default();
        let result = resolve_dynamic_token_checked("exec:///bin/echo secret", &uf);
        assert!(result.is_err());
    }

    #[test]
    fn test_resolve_dynamic_token_file_allowed_without_unsafe() {
        // Go frp v0.70.1: only exec token sources require the unsafe gate;
        // file sources are always allowed.
        let dir = std::env::temp_dir();
        let path = dir.join(format!("frp-test-token-i3-{}.txt", std::process::id()));
        std::fs::write(&path, "file-token-allowed\n").unwrap();
        let url = format!("file://{}", path.display());
        let uf = crate::unsafe_features::UnsafeFeatures::default();
        let result = resolve_dynamic_token_checked(&url, &uf);
        std::fs::remove_file(&path).ok();
        assert_eq!(result.unwrap(), "file-token-allowed");
    }

    #[test]
    fn test_resolve_dynamic_token_file_allowed_with_feature() {
        // file:// works when TokenSourceFile is in the allowlist.
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "frp-test-token-file-allowed-{}.txt",
            std::process::id()
        ));
        std::fs::write(&path, "file-token-allowed\n").unwrap();
        let url = format!("file://{}", path.display());
        let uf = crate::unsafe_features::UnsafeFeatures::new(&[
            crate::unsafe_features::TOKEN_SOURCE_FILE,
        ]);
        let result = resolve_dynamic_token_checked(&url, &uf);
        std::fs::remove_file(&path).ok();
        assert_eq!(result.unwrap(), "file-token-allowed");
    }

    #[test]
    fn test_auth_config_file_token_source_resolves_on_demand() {
        use std::io::Write;

        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(b" first-token \n").unwrap();
        file.flush().unwrap();
        let mut cfg = AuthConfig::default();
        cfg.token_source = Some(crate::config::ValueSource {
            source_type: "file".into(),
            file: Some(crate::config::FileSource {
                path: file.path().display().to_string(),
            }),
            exec: None,
        });

        assert_eq!(cfg.resolve_token().unwrap(), "first-token");

        std::fs::write(file.path(), b"\n second-token \n\n").unwrap();
        assert_eq!(cfg.resolve_token().unwrap(), "second-token");
    }

    #[test]
    fn test_auth_config_exec_token_source_resolves_with_args_env() {
        let mut cfg = AuthConfig::default();
        cfg.token_source = Some(crate::config::ValueSource {
            source_type: "exec".into(),
            file: None,
            exec: Some(crate::config::ExecSource {
                command: "/bin/sh".into(),
                args: vec!["-c".into(), "printf '%s' \"$TOKEN\"".into()],
                env: vec![crate::config::ExecEnvVar {
                    name: "TOKEN".into(),
                    value: "  secret-token\n".into(),
                }],
            }),
        });

        assert_eq!(cfg.resolve_token().unwrap(), "secret-token");
    }

    #[test]
    fn test_auth_config_validate_login_uses_token_source() {
        use std::io::Write;

        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(b"source-token\n").unwrap();
        file.flush().unwrap();
        let mut cfg = AuthConfig::default();
        cfg.token_source = Some(crate::config::ValueSource {
            source_type: "file".into(),
            file: Some(crate::config::FileSource {
                path: file.path().display().to_string(),
            }),
            exec: None,
        });
        let ts = 1_700_000_000;
        let key = generate_token("source-token", ts);

        assert!(cfg.validate_login(Some(&key), Some(ts)).is_ok());
        assert!(cfg.validate_login(Some("wrong"), Some(ts)).is_err());
        assert_eq!(
            cfg.try_generate_login_key(ts).unwrap(),
            generate_token("source-token", ts)
        );
    }

    #[test]
    fn test_token_source_exec_gated_by_unsafe_features() {
        let source = crate::config::ValueSource {
            source_type: "exec".into(),
            file: None,
            exec: Some(crate::config::ExecSource {
                command: "/bin/echo".into(),
                args: vec!["token".into()],
                env: Vec::new(),
            }),
        };
        let blocked = crate::unsafe_features::UnsafeFeatures::default();
        let err = validate_token_source_unsafe(&source, &blocked).unwrap_err();
        assert!(err.contains("TokenSourceExec"), "{err}");

        let allowed = crate::unsafe_features::UnsafeFeatures::new(&[
            crate::unsafe_features::TOKEN_SOURCE_EXEC,
        ]);
        assert!(validate_token_source_unsafe(&source, &allowed).is_ok());
    }

    // --- Authentication timeout tests ---
    //
    // Go frp compat: token auth does NOT check timestamp freshness.
    // Go frp's VerifyLogin only checks MD5(token+timestamp) equality.
    // frp-rs matches Go behavior — the timestamp is part of the hash
    // itself, so replay protection relies on the server rejecting
    // duplicate timestamps, not on freshness.
    //
    // authentication_timeout now only applies to the OIDC auth path.

    #[test]
    fn test_auth_timeout_default_is_300() {
        let cfg = AuthConfig::default();
        assert_eq!(cfg.authentication_timeout, 300);
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
    fn test_token_auth_accepts_future_timestamp() {
        // Go frp compat: token auth does not check timestamp freshness.
        // A future timestamp with the correct token hash is accepted.
        let mut cfg = AuthConfig::with_token("secret");
        cfg.authentication_timeout = 15; // timeout ignored for token auth
        let far_future = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64
            + 60; // 60 seconds in the future
        let key = generate_token("secret", far_future);
        assert!(cfg.validate_login(Some(&key), Some(far_future)).is_ok());
    }

    #[test]
    fn test_token_auth_accepts_past_timestamp() {
        // Go frp compat: token auth does not check timestamp freshness.
        // A past timestamp with the correct token hash is accepted.
        let mut cfg = AuthConfig::with_token("secret");
        cfg.authentication_timeout = 15; // timeout ignored for token auth
        let far_past = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64
            - 60; // 60 seconds in the past
        let key = generate_token("secret", far_past);
        assert!(cfg.validate_login(Some(&key), Some(far_past)).is_ok());
    }

    #[test]
    fn test_token_auth_accepts_current_timestamp() {
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
    fn test_token_auth_accepts_far_future_timestamp() {
        // Go frp compat: any timestamp is accepted as long as the token hash matches.
        let mut cfg = AuthConfig::with_token("secret");
        cfg.authentication_timeout = 15; // timeout ignored for token auth
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let far_boundary = now + 3600; // 1 hour in the future
        let key = generate_token("secret", far_boundary);
        assert!(cfg.validate_login(Some(&key), Some(far_boundary)).is_ok());
    }

    #[test]
    fn test_token_auth_rejects_wrong_token() {
        // Replay protection: even with a valid timestamp, wrong token fails
        let mut cfg = AuthConfig::with_token("secret");
        cfg.authentication_timeout = 15;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let wrong_key = generate_token("wrong-secret", now);
        let result = cfg.validate_login(Some(&wrong_key), Some(now));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid authentication token"));
    }
}
