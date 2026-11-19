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
/// Called from the server Login handler (`frp-server/src/control/login.rs`)
/// when `token_auth_timeout` + `authentication_timeout` are enabled — NOT from
/// `AuthConfig::validate_login_with_token`: the token path matches Go frp and
/// checks only MD5(token+timestamp) equality, no freshness.
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
    ///
    /// The frpc login path does **not** set this: it resolves the source once
    /// at service construction and stores only the snapshot in `token`, so a
    /// login/ping/NewWorkConn cannot execute the source again — Go frp builds
    /// one auth runtime per client service (`client/service.go:168`) and
    /// reuses it (`:316`). `frps` does set it (`build_auth_config`), its
    /// verifier resolving per verification — a deliberate `frp-rs` divergence
    /// from Go's `BuildServerAuth`, which resolves the source once
    /// (`pkg/auth/auth.go:106`).
    pub token_source: Option<crate::config::ValueSource>,
    pub oidc_issuer: String,
    pub oidc_audience: String,
    pub oidc_skip_expiry: bool,
    pub oidc_skip_issuer: bool,
    pub oidc_skip_nbf: bool,
    /// Skip "aud" claim validation entirely.
    /// Go frp compat: when `oidc_audience` is empty, Go skips client-ID
    /// verification; this is the explicit frp-rs form.
    pub oidc_skip_audience: bool,
    /// Additional accepted audiences, unioned with `oidc_audience`.
    /// A token is accepted when its "aud" claim matches any of them.
    pub oidc_additional_audience: Vec<String>,
    /// Path to a custom CA certificate PEM file for verifying the OIDC
    /// provider's TLS certificate (server side, for discovery + JWKS fetches).
    pub oidc_tls_trusted_ca_file: String,
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
    /// Default: 90s in frps (the serde default — see
    /// `config::default_authentication_timeout`); 0 disables. This struct's
    /// `Default` mirrors that serde default. Go frp has no
    /// `authentication_timeout` equivalent (timestamp freshness is not
    /// checked in the token auth path); when set, OIDC uses this for JWT
    /// expiry validation. Go frp compat: authentication_timeout.
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
            oidc_skip_audience: false,
            oidc_additional_audience: Vec::new(),
            oidc_tls_trusted_ca_file: String::new(),
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
            oidc_skip_audience: false,
            oidc_additional_audience: Vec::new(),
            oidc_tls_trusted_ca_file: String::new(),
            additional_data: None,
            oidc_proxy_url: String::new(),
            additional_auth_scopes: Vec::new(),
            // Matches the frps serde default (`default_authentication_timeout`).
            authentication_timeout: 90,
            token_auth_timeout: true,
            use_encryption: false,
        }
    }
}

/// Supported authentication methods.
#[derive(Debug, Clone, PartialEq)]
pub enum AuthMethod {
    Token,
    /// OIDC (JWT) auth.
    ///
    /// Deliberately **not** feature-gated, unlike the config parses that
    /// construct it (each dependent crate builds it only under its own `oidc`
    /// feature): `frp-core` can be compiled with `feature = "oidc"` on while a
    /// dependent crate's own `oidc` is off (Cargo feature unification — e.g.
    /// `frp-server`'s dev-dependency on `frp-client` pulls `frp-core/oidc`
    /// in), and a variant that exists only in the feature-on build makes every
    /// `match` in such a dependent crate non-exhaustive in the feature-off
    /// build. That is exactly the E0004 at `frp-server/src/dashboard.rs` that
    /// `cargo check -p frp-server --no-default-features --features dashboard
    /// --all-targets` used to hit; do not "tidy" the `#[cfg]` back on. Same
    /// shape as `ConnectionType::WebSocket` in
    /// `frp-core/src/transport/mod.rs`.
    ///
    /// Only ever constructed when the *dependent* crate's `oidc` feature is on.
    /// A dependent whose own `oidc` is off **refuses** an `auth.method = "oidc"`
    /// configuration when its service is constructed — server startup and the
    /// server's SIGUSR1 reload, and `frpc run` — and in `frpc verify`, so an
    /// OIDC-configured server or client never silently runs token auth. (The
    /// client's admin-triggered reload does not re-derive auth at all; auth is
    /// startup-only there.) With frp-core's `oidc` off the runtime OIDC entry
    /// points are the stubs below, so a hand-built `Oidc` still fails closed.
    Oidc,
}

/// Error for a configuration that requests OIDC in a build compiled without the
/// `oidc` feature. One constant so the server builder, the client builder and
/// `frpc verify` refuse the same configuration with the same text — the failure
/// mode this prevents is a silent downgrade to token auth.
pub const OIDC_FEATURE_REQUIRED: &str =
    "auth.method = \"oidc\" requires the \"oidc\" feature, which this build was compiled \
     without — rebuild with it or set auth.method = \"token\"";

/// The two method names Go frp v0.71.0 accepts, in the order Go prints them
/// (`pkg/config/v1/validation/validation.go:37-40`). Used only by the unit test
/// that pins [`INVALID_AUTH_METHOD`]'s bracket rendering, so it is `#[cfg(test)]`.
#[cfg(test)]
const SUPPORTED_AUTH_METHODS: [&str; 2] = ["token", "oidc"];

/// The load-error text for an unrecognised `auth.method`, byte-for-byte Go
/// v0.71.0's (`pkg/config/v1/validation/server.go:32`, `client.go:102`):
/// `fmt.Errorf("invalid auth method, optional values are %v", SupportedAuthMethods)`
/// over a `[]v1.AuthMethod{"token", "oidc"}` prints the slice in Go's bracket
/// form.
///
/// Measured on the real binaries (v0.71.0 darwin/arm64, own config and free
/// port per case, stdout/stderr redirected to separate files and `rc` read from
/// `wait` on the direct child): `frps -c <method = "OIDC">` → **rc 1,
/// 54 B stdout, 0 B stderr**, whole stdout exactly
/// `invalid auth method, optional values are [token oidc]\n` — the 53-byte
/// message plus one `\n` (`xxd` on the captured file: the last byte is `0a`),
/// which is what `println!("{e}")` produces. `frpc` prints the same 54 B on
/// stdout with rc 1.
pub const INVALID_AUTH_METHOD: &str = "invalid auth method, optional values are [token oidc]";

/// The one `auth.method` parse policy, mirroring Go frp v0.71.0.
///
/// Go compares the method **exactly** against `SupportedAuthMethods`
/// (`slices.Contains`, `pkg/config/v1/validation/server.go:31` and
/// `client.go:101`): case-sensitive, no trimming, and an unrecognised value is
/// a **load error** — not a fallback to token auth. Two measured consequences
/// of that exactness, both reproduced against the real v0.71.0 binaries:
/// `method = "OIDC"` and `method = " oidc"` each exit **1** with
/// [`INVALID_AUTH_METHOD`] on stdout, while `method = ""` completes to `token`
/// (Go's `AuthServerConfig.Complete`, `pkg/config/v1/server.go:136-139`, and
/// `AuthClientConfig.Complete`, `client.go:206-209`, both
/// `util.EmptyOr(c.Method, "token")`) and starts.
///
/// **`""` is accepted here and maps to `Token`** so that this function is the
/// whole policy: every caller must first run [`complete_auth_method`] (Go's
/// `Complete` step), which is the only way the empty string reaches
/// `parse_auth_method`. Doing the fill here instead would make an
/// explicit-empty method indistinguishable from a typo at the call site, and
/// the fill is *not* the validation (Go's ordering is Complete → Validate, so
/// `""` is a valid value only because Complete already replaced it).
///
/// Callers were previously inconsistent (see `TODO.md`, the two items closed by
/// this change): the server lowercased the method, so `"OIDC"` selected OIDC
/// while `" oidc"`/`"tokenn"` selected **token** — a silent downgrade of an
/// operator's auth intent; the client compared `== "oidc"` exactly, so
/// `"OIDC"` selected **token** against a server that (at the pre-change head)
/// selected OIDC; and the client-credentials validation skipped anything that
/// was not exactly `"oidc"`.
pub fn parse_auth_method(method: &str) -> Result<AuthMethod, String> {
    match method {
        "token" => Ok(AuthMethod::Token),
        "oidc" => Ok(AuthMethod::Oidc),
        // Not the empty string: that is completed to "token" by
        // `complete_auth_method` before this runs (Go's Complete→Validate
        // order). Reaching this arm with "" means a caller skipped the fill;
        // `auth_method_error()` is still the right text because Go's validator
        // would reject "" too if Complete had not run.
        _ => Err(auth_method_error()),
    }
}

/// Go's `util.EmptyOr(c.Method, "token")` — the completion step of Go's
/// `AuthServerConfig.Complete` / `AuthClientConfig.Complete`
/// (`pkg/config/v1/server.go:136-139`, `client.go:206-209`). Fills an **empty**
/// method with `token` and returns whether anything was filled.
///
/// Only the empty string is filled: Go's `EmptyOr` tests the type's zero value,
/// and for a string that is `""`. An explicit `method = "token"` is unchanged.
pub fn complete_auth_method(method: &mut String) -> bool {
    if method.is_empty() {
        *method = "token".into();
        return true;
    }
    false
}

/// The load-error text for a method Go does not accept — one function for every
/// site, so all four report the same string.
pub fn auth_method_error() -> String {
    INVALID_AUTH_METHOD.to_string()
}

impl AuthConfig {
    /// Resolve the current auth token.
    ///
    /// When `token_source` is configured, the source is re-read / re-executed
    /// so the latest value is used for each Login, Ping, or NewWorkConn auth
    /// operation. Otherwise the static `token` is returned.
    ///
    /// That per-operation refresh is a deliberate **`frp-rs` divergence** kept
    /// for `frps` (it re-verifies each operation against a rotated token);
    /// Go's `BuildServerAuth` (`pkg/auth/auth.go:106`) resolves the source
    /// once instead. The `frpc` login path leaves `token_source` unset and
    /// passes the construction-time snapshot in `token`, matching Go's
    /// one-auth-runtime-per-service client (`client/service.go:168` / `:316`),
    /// so a login cannot re-run the source a second time.
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
        let token = ZeroizingString::new(self.resolve_token()?);
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
                    // Audit C3: byte-match Go frp v0.71.0 pkg/auth/token.go:66
                    // ("token in login doesn't match token from configuration") —
                    // in detailed_errors_to_client mode the server sends
                    // err.Error() verbatim (util.go GenerateResponseErrorString).
                    return Err("token in login doesn't match token from configuration".into());
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
        let token = ZeroizingString::new(self.resolve_token()?);
        if token.as_str().is_empty() {
            return Err(
                "authentication token is empty. When auth.method = 'token', \
                 you must set auth.token or auth.tokenSource in the config file."
                    .into(),
            );
        }
        match self.method {
            AuthMethod::Token => Ok(generate_token(token.as_str(), timestamp)),
            AuthMethod::Oidc => Err("OIDC auth does not use token login keys".into()),
        }
    }

    /// Check for critical security misconfigurations at startup.
    /// Call this at server startup to reject dangerously insecure configurations.
    pub fn check_startup(&self) -> Result<(), String> {
        if self.method == AuthMethod::Token {
            let token = ZeroizingString::new(self.resolve_token()?);
            if token.as_str().is_empty() {
                return Err("CRITICAL: [auth].token / auth.tokenSource resolved empty with token auth method — server would accept ALL connections. Set a strong token in the config file.".into());
            }
        }
        // OIDC configuration validation. Not feature-gated: the `Oidc` variant is
        // always present and the runtime OIDC entry points are feature-gated, so
        // validating whenever the method is `Oidc` is the fail-closed direction
        // (with the feature off the variant is unconstructible from config, but a
        // manually built one must still be rejected on an incomplete issuer).
        if self.method == AuthMethod::Oidc {
            if self.oidc_issuer.is_empty() {
                return Err(
                    "CRITICAL: [auth].oidc_issuer is empty with OIDC auth method. \
                     Set oidc_issuer to your OIDC provider URL."
                        .into(),
                );
            }
            if !self.oidc_skip_audience
                && self.oidc_audience.is_empty()
                && self.oidc_additional_audience.iter().all(|a| a.is_empty())
            {
                return Err(
                    "CRITICAL: [auth].oidc_audience is empty (and no oidc_additional_audience \
                     entries) with OIDC auth method. Set oidc_audience to the expected \
                     audience claim (or oidc_additional_audience), or set \
                     oidc_skip_audience = true to disable audience validation."
                        .into(),
                );
            }
            if self.oidc_skip_audience {
                tracing::warn!(
                    "SECURITY WARNING: oidc_skip_audience is true — the token's 'aud' \
                     claim is NOT validated. Any validly-signed JWT will be accepted \
                     regardless of audience. This should only be used in development \
                     environments."
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
mod oidc_jwt;

#[cfg(feature = "oidc")]
mod oidc_impl {
    use super::oidc_jwt;
    use super::oidc_jwt::base64url_decode;

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
    #[derive(Debug)]
    struct OidcVerifyError {
        message: String,
        refresh_warranted: bool,
    }

    pub(crate) fn is_key_related_error(err: &oidc_jwt::Error) -> bool {
        oidc_jwt::is_key_related_error(err)
    }

    /// Hard cap on the replay-protection cache entry count. Lazy 24h-TTL
    /// pruning alone cannot bound memory when a holder of valid signed tokens
    /// submits many unique jtis (login throttling was removed); at capacity the
    /// soonest-expiring entry is evicted to make room for the new jti.
    const MAX_SEEN_JTIS: usize = 100_000;

    /// Byte cap on a single jti claim (round 10 LOW): the count cap above
    /// does not bound entry BYTES. Real jtis are UUIDs (36 bytes); 4 KiB is
    /// orders of magnitude beyond any legitimate IdP.
    const MAX_JTI_LEN_BYTES: usize = 4 * 1024;

    /// Minimum interval between attacker-triggered JWKS refreshes on the
    /// `refresh_warranted` retry path. A forged JWT (valid kid, garbage
    /// signature) fails with a key-related error and would otherwise trigger
    /// one outbound JWKS GET (TLS handshake + HTTPS request to the IdP) per
    /// attempt with no cooldown. The per-IP login throttle bounds the attempt
    /// rate; this gate bounds the outbound fetch rate globally (F1). The
    /// 3600s stale-cache refresh (`CachedJwks::refresh_after`) is a separate,
    /// naturally rate-limited path and is untouched.
    const JWKS_FORCED_REFRESH_MIN_INTERVAL: std::time::Duration =
        std::time::Duration::from_secs(60);

    /// Server-side OIDC verifier. Discovers JWKS from issuer, verifies JWT tokens,
    /// and enforces subject binding for ping/NewWorkConn.
    pub struct OidcVerifier {
        audience: String,
        additional_audience: Vec<String>,
        issuer: String,
        jwks_uri: String,
        jwks: tokio::sync::RwLock<Option<CachedJwks>>,
        skip_expiry: bool,
        skip_issuer: bool,
        skip_nbf: bool,
        skip_audience: bool,
        http: crate::http_client::HttpClient,
        /// Replay-protection cache: jti → (subject, deadline_unix_seconds).
        /// A jti seen with a different subject is rejected; the same jti with
        /// the same subject is allowed (frpc reconnects reuse the cached token).
        seen_jtis: std::sync::Mutex<std::collections::HashMap<String, (String, i64)>>,
        /// Unix-seconds timestamp of the last full expired-entry sweep of
        /// `seen_jtis` (audit round 3, LOW). A full `retain` is O(entries) —
        /// up to `MAX_SEEN_JTIS` — so sweeping on every replay check would
        /// burn CPU per cheap rejection under a multi-IP replay flood
        /// against a large live table. The sweep is gated to once per 60s;
        /// expired entries between sweeps are harmless (replay semantics
        /// read the subject match identically and memory stays bounded by
        /// the cap eviction, which removes soonest-expiring entries first).
        last_replay_sweep: std::sync::atomic::AtomicI64,
        /// Background JWKS refresh task (started via `start_background_refresh`),
        /// aborted via `stop_background_refresh` (audit round 5, LOW 2.4).
        refresh_task: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
        /// Timestamp of the last attacker-triggered JWKS refresh (the
        /// `refresh_warranted` retry path). Gates that path so forged-token
        /// floods cannot force more than one outbound IdP fetch per
        /// `JWKS_FORCED_REFRESH_MIN_INTERVAL`. The 3600s stale-cache refresh
        /// (`CachedJwks::refresh_after`) is a separate, naturally rate-limited
        /// path and is untouched.
        last_forced_refresh: std::sync::Mutex<Option<std::time::Instant>>,
    }

    /// Decide the audience-validation mode for a verifier.
    ///
    /// Returns `Some(audiences)` when the token's "aud" claim must match one
    /// of the returned audiences; `None` when audience validation is skipped
    /// (either `skip_audience` is set, or no audience was configured at all —
    /// matching Go frp's behavior of skipping client-ID verification when the
    /// audience is empty). Empty strings are filtered from the list.
    pub(super) fn audience_validation<'a>(
        skip_audience: bool,
        audience: &'a str,
        additional_audience: &'a [String],
    ) -> Option<Vec<&'a str>> {
        if skip_audience {
            return None;
        }
        let mut audiences: Vec<&str> = Vec::new();
        if !audience.is_empty() {
            audiences.push(audience);
        }
        audiences.extend(
            additional_audience
                .iter()
                .map(String::as_str)
                .filter(|s| !s.is_empty()),
        );
        if audiences.is_empty() {
            None
        } else {
            Some(audiences)
        }
    }

    impl OidcVerifier {
        /// Create new OidcVerifier. Discovers JWKS URI from issuer's
        /// .well-known/openid-configuration and fetches initial keys.
        #[allow(clippy::too_many_arguments)]
        pub async fn new(
            issuer: String,
            audience: String,
            skip_expiry: bool,
            skip_issuer: bool,
            skip_nbf: bool,
            skip_audience: bool,
            additional_audience: Vec<String>,
            tls_ca_file: Option<String>,
            proxy_url: Option<String>,
        ) -> Result<Self, String> {
            // proxy_url routes OIDC HTTP requests through an HTTP CONNECT /
            // SOCKS5 proxy (Go frp `oidcProxyUrl` compat).

            // Go frp v0.70.1 compat: a custom CA certificate PEM file for the
            // OIDC provider's TLS (openid-configuration / JWKS fetches). Mirrors
            // the client-side OidcClient behavior.
            let ca_cert_pem = if let Some(ref ca_file) = tls_ca_file.filter(|f| !f.is_empty()) {
                Some(
                    std::fs::read(ca_file)
                        .map_err(|e| format!("OIDC: failed to read CA cert {ca_file}: {e}"))?,
                )
            } else {
                None
            };

            let http = crate::http_client::HttpClientBuilder::new()
                .timeout(std::time::Duration::from_secs(10))
                .tls_ca_cert_pem(ca_cert_pem)
                .proxy(proxy_url)
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
                additional_audience,
                issuer: issuer.trim_end_matches('/').to_string(),
                jwks_uri,
                jwks: tokio::sync::RwLock::new(None),
                skip_expiry,
                skip_issuer,
                skip_nbf,
                skip_audience,
                http,
                seen_jtis: std::sync::Mutex::new(std::collections::HashMap::new()),
                last_replay_sweep: std::sync::atomic::AtomicI64::new(0),
                refresh_task: std::sync::Mutex::new(None),
                last_forced_refresh: std::sync::Mutex::new(None),
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
            if verifier.skip_audience {
                tracing::warn!("OIDC: skip_audience is enabled — tokens with any audience will be accepted. This weakens authentication security.");
            }

            verifier.refresh_jwks().await?;
            Ok(verifier)
        }

        /// Start a background task that periodically refreshes JWKS keys.
        /// Prevents latency spikes on token verification when cache is stale.
        pub fn start_background_refresh(self: &std::sync::Arc<Self>) {
            let verifier = self.clone();
            let handle = tokio::spawn(async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
                    if let Err(e) = verifier.refresh_jwks().await {
                        tracing::warn!(error = %e, "OIDC background JWKS refresh failed: {}", e);
                    } else {
                        tracing::debug!("OIDC JWKS refreshed in background");
                    }
                }
            });
            *self.refresh_task.lock().unwrap_or_else(|e| e.into_inner()) = Some(handle);
        }

        /// Cancel the background JWKS refresh task, if one was started.
        /// Safe to call multiple times; no-op when nothing is running.
        pub fn stop_background_refresh(&self) {
            if let Some(h) = self
                .refresh_task
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take()
            {
                h.abort();
            }
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

        /// Build an [`oidc_jwt::Key`] from a JWKS key JSON value.
        pub(super) fn decoding_key_from_jwk(
            key: &serde_json::Value,
        ) -> Result<oidc_jwt::Key, String> {
            let kty = key["kty"].as_str().unwrap_or("");
            match kty {
                "RSA" => {
                    let n = key["n"].as_str().ok_or("OIDC: missing RSA n in JWK")?;
                    let e = key["e"].as_str().ok_or("OIDC: missing RSA e in JWK")?;
                    oidc_jwt::Key::from_rsa_components(n, e)
                }
                "EC" => {
                    let x = key["x"].as_str().ok_or("OIDC: missing EC x in JWK")?;
                    let y = key["y"].as_str().ok_or("OIDC: missing EC y in JWK")?;
                    oidc_jwt::Key::from_ec_components(x, y)
                }
                "oct" => {
                    let k = key["k"].as_str().ok_or("OIDC: missing oct k in JWK")?;
                    oidc_jwt::Key::from_base64_secret(k)
                }
                "OKP" => {
                    let crv = key["crv"].as_str().ok_or("OIDC: missing OKP crv in JWK")?;
                    if crv != "Ed25519" {
                        return Err(format!("OIDC: unsupported OKP curve: {crv}"));
                    }
                    let x = key["x"].as_str().ok_or("OIDC: missing OKP x in JWK")?;
                    oidc_jwt::Key::from_ed_components(x)
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
            let header = oidc_jwt::decode_header(token)
                .map_err(|e| format!("OIDC: failed to decode JWT header: {e}"))?;

            let alg = header.alg;
            let kid = header.kid.clone();

            // The `Algorithm` enum itself is the allowlist: every JOSE name it
            // can deserialize is accepted, and an unknown name (`none`,
            // `ES512`, ...) fails in `decode_header` before any key is read.
            // Algorithm confusion (HS256 vs RSA key, ...) is rejected by the
            // key-family check in `oidc_jwt::decode`.

            // Ensure JWKS cached, refresh if stale
            {
                let cache = self.jwks.read().await;
                if let Some(ref c) = *cache {
                    if c.fetched_at.elapsed() > c.refresh_after {
                        drop(cache);
                        // Best-effort refresh: keep serving from the stale
                        // cache, but surface the failure so operators can
                        // tell that key material may be out of date.
                        if let Err(e) = self.refresh_jwks().await {
                            tracing::warn!(
                                error = %e,
                                "OIDC: stale JWKS refresh failed (continuing with cached keys): {e}"
                            );
                        }
                    }
                } else {
                    drop(cache);
                    self.refresh_jwks().await?;
                }
            }

            let mut validation = oidc_jwt::Validation::new(alg);
            validation.validate_exp = !self.skip_expiry;
            validation.validate_nbf = !self.skip_nbf;
            if !self.skip_issuer {
                validation.set_issuer(&[&self.issuer]);
            }
            // Audience ("aud" claim) validation: skipped when oidc_skip_audience
            // is set or no audience is configured; otherwise the token's aud
            // (String or Vec<String>) must match oidc_audience OR any entry of
            // oidc_additional_audience (jsonwebtoken's set_audience checks all
            // entries against both forms of the aud claim).
            match audience_validation(
                self.skip_audience,
                &self.audience,
                &self.additional_audience,
            ) {
                Some(expected) => validation.set_audience(&expected),
                None => validation.validate_aud = false,
            }
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
                    // Cooldown (F1): this retry path is reachable by an
                    // unauthenticated attacker — a forged JWT (valid kid,
                    // garbage signature) verifies against the cached key,
                    // fails, and classifies as key-related. Gate the outbound
                    // JWKS GET so the IdP sees at most one attacker-triggered
                    // fetch per `JWKS_FORCED_REFRESH_MIN_INTERVAL`; within the
                    // window the login fails with the cached keys and no
                    // outbound fetch happens. The marker is set BEFORE the
                    // fetch so a failed fetch still counts against the window.
                    let refresh_due = {
                        let mut last = self
                            .last_forced_refresh
                            .lock()
                            .unwrap_or_else(|e| e.into_inner());
                        match *last {
                            Some(at) if at.elapsed() < JWKS_FORCED_REFRESH_MIN_INTERVAL => false,
                            _ => {
                                *last = Some(std::time::Instant::now());
                                true
                            }
                        }
                    };
                    if !refresh_due {
                        tracing::debug!(
                            "OIDC: JWKS refresh cooldown active; skipping outbound refresh (login fails with cached keys)"
                        );
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
            validation: &oidc_jwt::Validation,
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

                match oidc_jwt::decode::<serde_json::Value>(token, &decoding_key, validation) {
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
            // Round 10 (LOW): the cache caps entry COUNT, not bytes — IdPs
            // commonly echo a client-supplied jti, so a long one (tens of MB
            // would need to be rejected by JWT size limits first, but a 100 KB
            // jti is realistic) would grow the map toward gigabytes at the
            // 100k-entry cap. Real jtis are UUIDs; reject anything absurd.
            if jti.len() > MAX_JTI_LEN_BYTES {
                return Err("OIDC: jti claim too large".to_string());
            }

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
                // saturating_add (round 10 LOW): a hostile exp within 60 of
                // i64::MAX would wrap negative in release, land the deadline
                // in the past, and silently disable replay tracking.
                expiry.saturating_add(60).min(now + MAX_JTI_TTL_SECS)
            } else {
                now + 3600
            };

            let mut seen = self.seen_jtis.lock().unwrap_or_else(|e| e.into_inner());
            // Lazy pruning of expired entries prevents unbounded growth. The
            // full-table sweep is O(entries) — at most once per 60s (audit
            // round 3, LOW): a replay flood of cheap rejections must not pay
            // a 100k-entry retain on every login. Entries that expire between
            // sweeps are harmless — the subject match below reads them
            // identically, and the size cap bounds memory regardless.
            if now.saturating_sub(
                self.last_replay_sweep
                    .load(std::sync::atomic::Ordering::Relaxed),
            ) > 60
            {
                self.last_replay_sweep
                    .store(now, std::sync::atomic::Ordering::Relaxed);
                seen.retain(|_, (_, d)| *d > now);
            }

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

        /// Read-only replay pre-check: does the (jti, subject) pair already
        /// sit in the table with a DIFFERENT subject (i.e., would
        /// `check_replay` reject it)? Runs BEFORE the expensive
        /// `verify_login` (JWKS fetch on a stale cache + signature verify) —
        /// a replayed token is then rejected with an O(1) table hit instead
        /// of a full verify (S2 hardening). Same-subject reuse is allowed
        /// (frpc reconnects reuse the cached token). NEVER records — only
        /// fully verified tokens populate the table, so an unauthenticated
        /// peer cannot poison it or evict live entries. Expired entries are
        /// pruned lazily on the read, mirroring `check_replay`.
        pub fn check_replay_pending(&self, jti: Option<&str>, subject: &str) -> bool {
            let Some(jti) = jti else {
                return false;
            };
            // A jti past the size cap is rejected by verify_login anyway
            // (round 10 LOW); the pre-check cannot be stricter than the
            // authoritative path, so it just skips the lookup.
            if jti.len() > MAX_JTI_LEN_BYTES {
                return false;
            }
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            let mut seen = self.seen_jtis.lock().unwrap_or_else(|e| e.into_inner());
            // Same 60s-gated sweep as `check_replay` (audit round 3, LOW) —
            // this pre-check runs on every OIDC login BEFORE verification,
            // so it is the flood-reachable hot path; an ungated O(entries)
            // retain here would burn CPU per cheap replay rejection.
            if now.saturating_sub(
                self.last_replay_sweep
                    .load(std::sync::atomic::Ordering::Relaxed),
            ) > 60
            {
                self.last_replay_sweep
                    .store(now, std::sync::atomic::Ordering::Relaxed);
                seen.retain(|_, (_, d)| *d > now);
            }
            matches!(seen.get(jti), Some((stored, _)) if stored != subject)
        }

        /// Extract the (jti, subject, exp) claims from a JWT payload WITHOUT
        /// signature verification — base64url-decode the payload segment and
        /// parse the JSON. Feeds the `check_replay_pending` pre-check so a
        /// replayed token is rejected before `verify_login`'s expensive
        /// JWKS fetch + signature verify. Returns Err for any malformed
        /// input — the caller then falls through to `verify_login`, which
        /// reports the authoritative error.
        pub fn extract_claims_unverified(
            &self,
            token: &str,
        ) -> Result<(Option<String>, String, i64), String> {
            let mut parts = token.split('.');
            let _header = parts.next();
            let payload = parts
                .next()
                .ok_or_else(|| "OIDC: malformed JWT (missing payload)".to_string())?;
            if parts.next().is_none() {
                return Err("OIDC: malformed JWT (missing signature)".to_string());
            }
            #[derive(serde::Deserialize)]
            struct PayloadClaims {
                #[serde(default)]
                jti: Option<String>,
                #[serde(default)]
                sub: Option<String>,
                #[serde(default)]
                exp: Option<i64>,
            }
            let bytes = base64url_decode(payload)?;
            let claims: PayloadClaims = serde_json::from_slice(&bytes)
                .map_err(|e| format!("OIDC: payload not JSON: {e}"))?;
            Ok((
                claims.jti,
                claims.sub.unwrap_or_default(),
                claims.exp.unwrap_or_default(),
            ))
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

    /// Upper cap (seconds) for how long a fetched access token is cached.
    /// 24h far exceeds any real OIDC access-token lifetime (minutes to
    /// hours); Rust-only hardening — Go frp's oauth2 caches whatever the
    /// IdP declares and its int64 `expires_in` decode rejects oversized
    /// values, Rust's u64 parse accepts them.
    const OIDC_EXPIRES_IN_CAP_SECS: u64 = 24 * 60 * 60;

    /// Sanitize the IdP-declared `expires_in` (seconds) into a safe cache
    /// window: keep the 60s edge-of-expiry refresh margin (floor at 0 — a
    /// token that expires within the margin is simply not cached) and cap
    /// the result at [`OIDC_EXPIRES_IN_CAP_SECS`]. The value feeds
    /// `Instant::now() + Duration::from_secs(...)` when the fetched token is
    /// cached (get_token), and std `Instant` PANICS when the add overflows —
    /// under the release `panic=abort` profile a hostile/broken IdP
    /// answering `expires_in: u64::MAX` would abort frpc on the next OIDC
    /// login (audit finding S2). Capped, the worst case is a re-fetch every
    /// 24h — harmless.
    fn sanitize_expires_in(raw: u64) -> u64 {
        // 60s refresh buffer (edge-of-expiry failures), then the cache cap.
        raw.saturating_sub(60).min(OIDC_EXPIRES_IN_CAP_SECS)
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
            // proxy_url routes OIDC client HTTP requests through an HTTP
            // CONNECT / SOCKS5 proxy (Go frp `oidcProxyUrl` compat).

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
                .proxy(proxy_url)
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
                    // Sanitize the IdP-controlled value before it reaches the
                    // `Instant::now() + from_secs` cache write in get_token
                    // (audit finding S2): 60s refresh buffer + 24h cap.
                    Ok((token, sanitize_expires_in(secs)))
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
    mod tests;
}

#[cfg(feature = "oidc")]
pub use oidc_impl::{LoginOidcToken, OidcClient, OidcVerifier};

// Stub types for when the oidc feature is disabled. These exist so that
// type-level references (struct fields, function parameters, Option<Arc<...>>)
// compile without per-site #[cfg] gates. Actual OIDC logic paths are gated by
// the feature that *constructs* AuthMethod::Oidc (config parsing), not by the
// variant: the variant itself is always present so a dependent crate's `match`
// stays exhaustive (see the variant's doc comment).
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
    /// Stub — the oidc feature is disabled, so config parsing cannot construct
    /// AuthMethod::Oidc and this client is never reached through it.
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
    /// disabled (config parsing cannot construct AuthMethod::Oidc, so the
    /// verifier is always None on the login path).
    pub fn check_replay(
        &self,
        _jti: Option<&str>,
        _subject: &str,
        _expiry: i64,
    ) -> Result<(), String> {
        Ok(())
    }
    /// Stub — the jti replay pre-check (S2) is unreachable when the oidc
    /// feature is disabled (config parsing cannot construct AuthMethod::Oidc;
    /// the verifier is always None on the login path).
    pub fn extract_claims_unverified(
        &self,
        _token: &str,
    ) -> Result<(Option<String>, String, i64), String> {
        Err("OIDC feature disabled at compile time".into())
    }
    /// Stub — never reports a pending replay; `verify_login` rejects
    /// everything when the feature is off.
    pub fn check_replay_pending(&self, _jti: Option<&str>, _subject: &str) -> bool {
        false
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

/// RAII guard that wipes the wrapped `String`'s buffer on drop.
///
/// Used to zeroize the token temporaries resolved by
/// [`AuthConfig::resolve_token`] — without a guard, the resolved `String`
/// would be freed without wiping and the plaintext token would linger in
/// freed memory.
struct ZeroizingString(String);

impl ZeroizingString {
    fn new(s: String) -> Self {
        Self(s)
    }
    fn as_str(&self) -> &str {
        &self.0
    }
}

impl Drop for ZeroizingString {
    fn drop(&mut self) {
        zeroize_string(&mut self.0);
    }
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
    resolve_dynamic_token_inner(token, Some(unsafe_features)).map_err(|e| e.message)
}

/// A dynamic-token resolution failure, carrying both the redacted message and —
/// when the failure was a syscall — the errno that caused it.
///
/// # Why the errno is carried out of band
///
/// `message` is the user-visible text: it must never contain the command line,
/// the script path, or the script's captured stderr (that is why every error
/// below is reworded rather than passed through verbatim). Because the message
/// is deliberately redacted, human-readable prose, it is **not** a machine
/// channel: nothing may recover control-flow information (such as an errno) by
/// scanning it. The errno is captured next to the `io::Error` that produced it
/// and stays available structurally, so the ETXTBSY retry reads
/// `raw_os_error` instead of parsing `message`.
///
/// # Who consumes `raw_os_error` (read before deleting or "wiring up")
///
/// `raw_os_error` is consumed **only by the ETXTBSY retry in this file's
/// `#[cfg(test)] mod tests`** (see `retry_on_etxtbsy` /
/// `io_error_from_token_error`), which collapses the residual `exec://` timing
/// flake in `test_resolve_dynamic_token_exec_failure_redacts_stderr`.
///
/// Production deliberately does **not** retry ETXTBSY, and this is a decision,
/// not an oversight: the condition is another process holding the
/// operator-owned token script open for writing, which is a real, fixable
/// startup misconfiguration. Silently retrying it would add latency to a real
/// error and hide the misconfiguration from the operator.
/// `resolve_dynamic_token_checked` keeps its `Result<String, String>` public
/// signature and hands callers only the redacted message.
///
/// So the field is intentionally test-consumed. Do not delete it as unused (the
/// `From<TokenResolveError> for io::Error` impl below keeps it read), and do not
/// add a production retry without first revisiting the no-retry decision above —
/// this struct is not half-way to one.
#[derive(Debug)]
struct TokenResolveError {
    /// Redacted, user-facing error text.
    message: String,
    /// `raw_os_error()` of the failing syscall, or `None` for a non-syscall
    /// failure (bad config, non-zero exit status, timeout).
    raw_os_error: Option<i32>,
}

impl TokenResolveError {
    /// A failure with no syscall errno: bad configuration, a non-zero exit
    /// status, or a timeout.
    fn plain(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            raw_os_error: None,
        }
    }

    /// A failure caused by a syscall. Formats `context: {e}` for the redacted
    /// message and keeps `e.raw_os_error()` alongside it.
    fn from_io(context: &str, e: std::io::Error) -> Self {
        Self {
            message: format!("{context}: {e}"),
            raw_os_error: e.raw_os_error(),
        }
    }
}

/// Convert a resolution failure back into an [`std::io::Error`] for callers
/// that classify on errno. Uses the errno that was stored alongside the
/// message; the message text is never inspected.
///
/// This impl is what makes the stored errno useful to the test-only ETXTBSY
/// retry (see `retry_on_etxtbsy`) while keeping it read in every build, so the
/// field is not `dead_code`. It has no production caller by design — see the
/// `TokenResolveError` docs.
impl From<TokenResolveError> for std::io::Error {
    fn from(e: TokenResolveError) -> Self {
        match e.raw_os_error {
            Some(errno) => std::io::Error::from_raw_os_error(errno),
            None => std::io::Error::other(e.message),
        }
    }
}

// Test-only record of which `exec://` arm the most recent
// `resolve_dynamic_token_inner` call on this thread took. Thread-local so
// parallel tests cannot race on it; compiled out of every non-test build.
//
// It exists so the two arm tests can *distinguish* the arms: both arms report
// the same ENOENT for a missing command, so without this a test named for the
// async arm would still pass if a regression routed the call to the sync
// fallback. With it, a mis-routed call flips the flag and fails the test.
#[cfg(test)]
thread_local! {
    static LAST_EXEC_USED_ASYNC_ARM: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
}

fn resolve_dynamic_token_inner(
    token: &str,
    unsafe_features: Option<&crate::unsafe_features::UnsafeFeatures>,
) -> Result<String, TokenResolveError> {
    if let Some(path) = token.strip_prefix("file://") {
        // Go frp v0.70.1: only exec token sources require the unsafe-features
        // gate (validation/client.go validateOIDCConfig + token.go); file
        // sources are always allowed.
        let _ = unsafe_features;
        match std::fs::read_to_string(path) {
            Ok(content) => Ok(content.lines().next().unwrap_or("").trim().to_string()),
            // Redact the token-file path: this error is surfaced at startup
            // failure level and must not leak where the token file lives.
            // Only the error class (the io error) is retained.
            Err(e) => Err(TokenResolveError::from_io(
                "Failed to read dynamic token from file source",
                e,
            )),
        }
    } else if let Some(cmd) = token.strip_prefix("exec://") {
        if unsafe_features
            .is_some_and(|uf| !uf.is_enabled(crate::unsafe_features::TOKEN_SOURCE_EXEC))
        {
            return Err(TokenResolveError::plain(
                "exec:// token source blocked: TokenSourceExec not in UnsafeFeatures allowlist. \
                 Set [common].unsafe_features = [\"TokenSourceExec\"] to enable.",
            ));
        }
        let parts: Vec<&str> = cmd.split_whitespace().collect();
        if parts.is_empty() {
            return Err(TokenResolveError::plain(
                "Dynamic token exec:// with empty command",
            ));
        }
        // Prefer the async path (tokio::process::Command) when running on a
        // multi-thread tokio runtime so no worker thread is parked on
        // child-process wait. `block_in_place` hands the current worker back
        // to the runtime, then `Handle::block_on` drives the async spawn on
        // this thread (the pattern tokio documents for re-entering the async
        // context of a multi-thread runtime). The synchronous spawn remains
        // as a fallback for callers outside any runtime (unit tests) and for
        // current-thread runtimes, where `block_in_place` would panic.
        //
        // Both arms are bounded by EXEC_TIMEOUT (mirroring
        // `ValueSource::resolve`): a hung token command must fail startup
        // after 10 s instead of parking the process forever. The async arm
        // kills the child on drop (kill_on_drop); the sync arm SIGKILLs it
        // (Unix) after `recv_timeout` expires.
        const EXEC_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
        let output = match tokio::runtime::Handle::try_current() {
            Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
                #[cfg(test)]
                LAST_EXEC_USED_ASYNC_ARM.with(|arm| arm.set(true));
                tokio::task::block_in_place(|| {
                    handle.block_on(async {
                        tokio::time::timeout(EXEC_TIMEOUT, exec_token_command_async(&parts))
                            .await
                            .map_err(|_elapsed| {
                                std::io::Error::new(
                                    std::io::ErrorKind::TimedOut,
                                    format!(
                                        "dynamic token exec command timed out after {}s",
                                        EXEC_TIMEOUT.as_secs()
                                    ),
                                )
                            })?
                    })
                })
            }
            _ => {
                #[cfg(test)]
                LAST_EXEC_USED_ASYNC_ARM.with(|arm| arm.set(false));
                exec_token_command_sync_timeout(&parts, EXEC_TIMEOUT)
            }
        };
        match output {
            // Redact the command line and the script's captured stderr (both
            // may carry secrets): only the error class — the exit status, or
            // the spawn io error below — is surfaced to the startup log.
            Ok(o) => {
                let status = o.status;
                finish_exec_output(cmd, o).map_err(|_| {
                    TokenResolveError::plain(format!(
                        "Dynamic token exec command exited with {status}"
                    ))
                })
            }
            Err(e) => Err(TokenResolveError::from_io(
                "Failed to exec dynamic token command",
                e,
            )),
        }
    } else {
        Ok(token.to_string())
    }
}

/// Run the exec:// token command via `tokio::process`, so `wait_with_output`
/// parks the runtime's process driver instead of a worker thread. The child
/// is killed on drop, so the caller's `tokio::time::timeout` (10 s) bounds
/// the total runtime. Returns a `std::process::Output` so both paths share
/// `finish_exec_output`.
async fn exec_token_command_async(parts: &[&str]) -> std::io::Result<std::process::Output> {
    tokio::process::Command::new(parts[0])
        .args(&parts[1..])
        .kill_on_drop(true)
        .output()
        .await
}

/// Synchronous fallback used when no multi-thread tokio runtime is available.
/// Bounds the child's runtime to `timeout`; on expiry the child is SIGKILLed
/// (Unix) — the `ValueSource::resolve` sync-arm pattern — so a hung token
/// command cannot park the caller forever.
fn exec_token_command_sync_timeout(
    parts: &[&str],
    timeout: std::time::Duration,
) -> std::io::Result<std::process::Output> {
    let child = std::process::Command::new(parts[0])
        .args(&parts[1..])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;
    let pid = child.id();
    let (tx, rx) = std::sync::mpsc::channel();
    let waiter = std::thread::spawn(move || {
        let output = child.wait_with_output();
        let _ = tx.send(output);
    });
    match rx.recv_timeout(timeout) {
        Ok(output) => {
            let _ = waiter.join();
            output
        }
        Err(_) => {
            #[cfg(unix)]
            {
                let _ = std::process::Command::new("kill")
                    .args(["-9", &pid.to_string()])
                    .status();
            }
            let _ = waiter.join();
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!(
                    "dynamic token exec command timed out after {}s",
                    timeout.as_secs()
                ),
            ))
        }
    }
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
mod tests;
