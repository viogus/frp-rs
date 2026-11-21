use super::*;

#[test]
fn parse_auth_method_matches_go_exactly() {
    // The accepted spellings, exactly (Go `slices.Contains` over
    // `SupportedAuthMethods`, `pkg/config/v1/validation/server.go:31`).
    assert_eq!(parse_auth_method("token").unwrap(), AuthMethod::Token);
    assert_eq!(parse_auth_method("oidc").unwrap(), AuthMethod::Oidc);

    // Reproduced against Go v0.71.0 darwin/arm64, own config and free port
    // per case, streams separate, rc from `wait`: each of these exits 1 with
    // `invalid auth method, optional values are [token oidc]` on stdout and
    // 0 bytes on stderr. The Cyrillic-о case is a homoglyph, not a Unicode
    // normalisation question: Go does no normalisation either.
    for bad in [
        "OIDC",
        "Oidc",
        "TOKEN",
        "Token",
        " oidc",
        "oidc ",
        "oidc\t",
        "tokenn",
        "\u{043e}idc",
        // The empty string is not in this list: it is the one input
        // `complete_auth_method` fills (Go's `util.EmptyOr`), and reaching
        // `parse_auth_method` with it means a caller skipped the fill.
        "",
    ] {
        let err =
            parse_auth_method(bad).expect_err(&format!("{bad:?} must be rejected (Go rejects it)"));
        assert_eq!(
            err, INVALID_AUTH_METHOD,
            "{bad:?} must carry Go's exact text"
        );
    }
}

#[test]
fn invalid_auth_method_text_is_go_bracket_rendering() {
    // `fmt.Errorf("invalid auth method, optional values are %v", SupportedAuthMethods)`
    // (`pkg/config/v1/validation/server.go:32`) prints a `[]v1.AuthMethod`
    // as `[token oidc]` with single spaces and no quotes.
    assert_eq!(
        auth_method_error(),
        format!(
            "invalid auth method, optional values are [{}]",
            SUPPORTED_AUTH_METHODS.join(" ")
        )
    );
    // The measured Go stdout is these 53 bytes plus one `\n` (54 B total).
    assert_eq!(INVALID_AUTH_METHOD.len(), 53);
    assert!(!INVALID_AUTH_METHOD.ends_with('\n'));
}

#[test]
fn complete_auth_method_fills_only_the_empty_string() {
    let mut m = String::new();
    assert!(complete_auth_method(&mut m), "an empty method is filled");
    assert_eq!(m, "token");

    // Everything else is left byte-for-byte, including the spellings Go
    // rejects — the fill must not become a normaliser.
    for untouched in ["oidc", "OIDC", " oidc", "token"] {
        let mut m = untouched.to_string();
        assert!(!complete_auth_method(&mut m), "{untouched:?} is not filled");
        assert_eq!(m, untouched);
    }
}

#[test]
fn test_token_gen_and_verify() {
    let token = "my-secret-token";
    let ts = 1234567890i64;
    let gen = generate_token(token, ts);
    assert!(verify_token(token, ts, &gen));
    assert!(!verify_token(token, ts + 1, &gen));
}

#[test]
fn test_validate_timestamp_freshness_table() {
    use crate::auth::validate_timestamp_freshness;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    // timeout 关闭
    assert!(validate_timestamp_freshness(now, 0).is_ok());
    // 秒精度: 窗口内通过, 窗口外拒绝。边界选 ±1 / ±120 而不是紧贴
    // 60s 窗口: 测试进程与 `now` 捕获之间若有 >1s 调度停顿（加载 CI、
    // NTP 跳秒），±59/±62 会翻转到错误分支。±1 只在停顿 >59s 时误判
    // （等于挂死），±120 只在时钟跳变 >60s 时误判。
    assert!(validate_timestamp_freshness(now + 1, 60).is_ok());
    assert!(validate_timestamp_freshness(now - 1, 60).is_ok());
    assert!(validate_timestamp_freshness(now + 120, 60).is_err());
    assert!(validate_timestamp_freshness(now - 120, 60).is_err());
    // 毫秒精度时间戳: 任一解释入窗即通过
    let now_ms = now.saturating_mul(1000);
    assert!(validate_timestamp_freshness(now_ms + 30_000, 60).is_ok());
    assert!(validate_timestamp_freshness(now_ms - 30_000, 60).is_ok());
    assert!(validate_timestamp_freshness(now_ms + 70_000, 60).is_err());
    assert!(validate_timestamp_freshness(now_ms - 70_000, 60).is_err());
    // 溢出防线: 极端输入必须 Err, 永不 panic
    assert!(validate_timestamp_freshness(i64::MAX, 60).is_err());
    assert!(validate_timestamp_freshness(i64::MIN, 60).is_err());
}

#[test]
fn test_generate_token_golden_go_vector() {
    assert_eq!(
        generate_token("frp-golden-vector", 1234567890),
        "4f5c0efd73397dd75b0524aaff772dd4"
    );
}

/// Local capture server for OIDC token-endpoint requests. Parses the
/// application/x-www-form-urlencoded body and exposes the form fields.
///
/// Used only by the two `#[cfg(feature = "oidc")]` tests below.
#[cfg(feature = "oidc")]
struct TokenEndpointCapture {
    _addr: std::net::SocketAddr,
    /// oneshot receiver receiving the form fields when the server
    /// captures the token request.
    rx: tokio::sync::oneshot::Receiver<std::collections::HashMap<String, String>>,
}

#[cfg(feature = "oidc")]
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
        oidc_skip_audience: false,
        oidc_additional_audience: Vec::new(),
        oidc_tls_trusted_ca_file: String::new(),
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
    use crate::auth::oidc_jwt::test_compat as jsonwebtoken;
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
#[cfg(feature = "oidc")]
fn test_audience_validation_decision_matrix() {
    use super::oidc_impl::audience_validation;
    let add = |s: &[&str]| s.iter().map(|x| x.to_string()).collect::<Vec<_>>();

    // skip_audience → None (audience check disabled) regardless of config.
    assert!(audience_validation(true, "api-prod", &add(&["api-staging"])).is_none());
    assert!(audience_validation(true, "", &add(&[])).is_none());

    // Primary audience only.
    assert_eq!(
        audience_validation(false, "api-prod", &add(&[])),
        Some(vec!["api-prod"])
    );

    // Primary + additional audiences, union order preserved.
    assert_eq!(
        audience_validation(false, "api-prod", &add(&["api-staging", "api-dev"])),
        Some(vec!["api-prod", "api-staging", "api-dev"])
    );

    // Additional-only (primary audience empty) still validates.
    assert_eq!(
        audience_validation(false, "", &add(&["api-staging"])),
        Some(vec!["api-staging"])
    );

    // Empty strings are filtered out.
    assert_eq!(
        audience_validation(false, "", &add(&["", "api-dev", ""])),
        Some(vec!["api-dev"])
    );

    // All-empty audience list → None (Go frp skips client-ID verification
    // when the audience is empty).
    assert!(audience_validation(false, "", &add(&[])).is_none());
    assert!(audience_validation(false, "", &add(&[""])).is_none());
}

#[test]
#[cfg(feature = "oidc")]
fn test_oidc_audience_check_semantics() {
    // Verify the integration with jsonwebtoken: a token whose "aud" claim
    // is a single string or an array of strings is accepted when ANY
    // configured audience matches, and rejected otherwise. This is the
    // exact mechanism OidcVerifier::verify_login wires up via
    // `audience_validation` + `Validation::set_audience`.
    use crate::auth::oidc_jwt::test_compat as jsonwebtoken;
    use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};

    let encode_token = |claims: &serde_json::Value| {
        jsonwebtoken::encode(
            &Header::new(Algorithm::HS256),
            claims,
            &EncodingKey::from_secret(b"oidc-test-secret"),
        )
        .expect("encode token")
    };
    let decode_with = |token: &str, expected: &[&str], validate_aud: bool| {
        let mut v = Validation::new(Algorithm::HS256);
        v.validate_exp = false;
        // Mirror audience_validation()/verify_login: validate_aud=false
        // disables the claim check entirely (jsonwebtoken's Validation
        // defaults to validate_aud=true with an empty set, which rejects
        // any token carrying an "aud" claim).
        v.validate_aud = validate_aud;
        if validate_aud {
            v.set_audience(expected);
        }
        jsonwebtoken::decode::<serde_json::Value>(
            token,
            &DecodingKey::from_secret(b"oidc-test-secret"),
            &v,
        )
        .map(|_| ())
        .map_err(|e| e.to_string())
    };

    let future_exp = 4_102_444_800_u64;
    // Array-form "aud" claim (OIDC allows Vec<String>).
    let array_aud = encode_token(&serde_json::json!({
        "sub": "user-1", "aud": ["api-prod", "api-staging"], "exp": future_exp
    }));
    // Single-string "aud" claim.
    let single_aud = encode_token(&serde_json::json!({
        "sub": "user-1", "aud": "api-prod", "exp": future_exp
    }));

    // Main audience matches (both aud forms).
    assert!(decode_with(&array_aud, &["api-prod"], true).is_ok());
    assert!(decode_with(&single_aud, &["api-prod"], true).is_ok());
    // Non-matching audience is rejected.
    assert!(decode_with(&array_aud, &["api-other"], true).is_err());
    assert!(decode_with(&single_aud, &["api-other"], true).is_err());
    // Additional audience alone matches the array entry.
    assert!(decode_with(&array_aud, &["api-staging"], true).is_ok());
    // Union list (main + additional) accepts via the additional entry.
    assert!(decode_with(&array_aud, &["api-other", "api-staging"], true).is_ok());
    // Skip audience (validate_aud = false): accepted regardless of "aud".
    assert!(decode_with(&array_aud, &[], false).is_ok());
    assert!(decode_with(&single_aud, &[], false).is_ok());
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
        oidc_skip_audience: false,
        oidc_additional_audience: Vec::new(),
        oidc_tls_trusted_ca_file: String::new(),
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
    // Regression: the failure is a hard error, and the error class must
    // not leak the token-file path (the error is logged at startup
    // failure level).
    let err = result.unwrap_err();
    assert!(
        !err.contains("nonexistent/path/token.txt"),
        "error must not contain the token-file path: {err}"
    );
}

#[test]
fn test_resolve_dynamic_token_exec() {
    // Use /bin/echo on Unix — portable across macOS and Linux
    let uf =
        crate::unsafe_features::UnsafeFeatures::new(crate::unsafe_features::CLIENT_UNSAFE_FEATURES);
    let result = resolve_dynamic_token_checked("exec:///bin/echo dynamic-token-value", &uf);
    assert_eq!(result.unwrap(), "dynamic-token-value");
}

#[tokio::test(flavor = "multi_thread")]
async fn test_resolve_dynamic_token_exec_on_runtime() {
    // Executed from inside a spawned worker task (not the block_on entry
    // point) so the `block_in_place` + `Handle::block_on` async path is
    // exercised: the exec must resolve without blocking the worker.
    let uf =
        crate::unsafe_features::UnsafeFeatures::new(crate::unsafe_features::CLIENT_UNSAFE_FEATURES);
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
fn test_resolve_dynamic_token_exec_spawn_failure_redacts_command() {
    // Regression: a failing exec source must not leak the command line
    // into the error (the error is logged at startup failure level).
    let uf =
        crate::unsafe_features::UnsafeFeatures::new(crate::unsafe_features::CLIENT_UNSAFE_FEATURES);
    let result = resolve_dynamic_token_checked("exec:///nonexistent/frp-token-cmd-xyz", &uf);
    let err = result.expect_err("missing exec command must be an error");
    assert!(
        !err.contains("frp-token-cmd-xyz"),
        "error must not contain the exec command: {err}"
    );
}

/// `ETXTBSY` is errno 26 on Linux (it is 26 on the BSDs/macOS too, but only
/// Linux makes `execve` refuse a file another process holds open for
/// writing). Hardcode the number with this comment rather than importing
/// `libc`, so the helper compiles — and its unit tests run — on every
/// platform.
const ETXTBSY: i32 = 26;

/// Bound on ETXTBSY retries. The window is simply another process's writer
/// fd being closed, i.e. sub-millisecond in practice, so 5 attempts with a
/// 10 ms pause (worst case ~40 ms added latency) is far more than a real
/// transient needs while staying strictly bounded. A genuine spawn failure
/// (ENOENT/EACCES/…) is not ETXTBSY and is not retried at all — see
/// `retry_on_etxtbsy_does_not_retry_other_errors`.
const ETXTBSY_MAX_ATTEMPTS: u32 = 5;
const ETXTBSY_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(10);

/// Run `attempt` again while — and only while — it fails with ETXTBSY, up
/// to [`ETXTBSY_MAX_ATTEMPTS`] calls. Any other error is returned on the
/// first call, so the retry cannot mask a real spawn failure.
///
/// **Test-only, deliberately.** Production does not retry ETXTBSY: the
/// condition is an operator-owned token script held open for writing, which
/// is a real, fixable startup misconfiguration, and a silent retry would add
/// latency and hide it. This helper exists so the test that execs a script
/// it just wrote cannot flake on the Linux ETXTBSY window. See the
/// `TokenResolveError` docs for the full decision.
fn retry_on_etxtbsy<T>(mut attempt: impl FnMut() -> std::io::Result<T>) -> std::io::Result<T> {
    let mut attempt_no = 1;
    loop {
        match attempt() {
            Err(e) if e.raw_os_error() == Some(ETXTBSY) && attempt_no < ETXTBSY_MAX_ATTEMPTS => {
                attempt_no += 1;
                std::thread::sleep(ETXTBSY_RETRY_DELAY);
            }
            other => return other,
        }
    }
}

/// Build the classification-facing [`std::io::Error`] from a resolution
/// failure the same way the retry does: via the errno captured next to the
/// message, never by scanning the message text.
fn io_error_from_token_error(e: TokenResolveError) -> std::io::Error {
    e.into()
}

/// The ETXTBSY retry fires on errno 26, and the errno is read from the
/// error **structure** -- not recovered by scanning the redacted,
/// human-readable message. A string-matching classifier is exactly what
/// this test refuses to accept: it must break if classification ever
/// listens to the message text instead of the stored errno.
#[test]
fn io_error_from_token_error_classifies_etxtbsy_by_errno() {
    // Built exactly as the spawn path builds it: an ETXTBSY `io::Error`
    // wrapped in the redacted context message.
    let busy = TokenResolveError::from_io(
        "Failed to exec dynamic token command",
        std::io::Error::from_raw_os_error(ETXTBSY),
    );
    // The redacted message happens to still contain the marker the old
    // classifier looked for...
    assert!(
        busy.message.contains("(os error 26)"),
        "expected the errno marker in the redacted message, got: {}",
        busy.message
    );
    // ...but classification is by the errno kept alongside it.
    assert_eq!(busy.raw_os_error, Some(ETXTBSY));
    let classified = io_error_from_token_error(busy);
    assert_eq!(
        classified.raw_os_error(),
        Some(ETXTBSY),
        "ETXTBSY must survive into the error the retry classifies"
    );
}

/// The complementary direction: a failure that is *not* a syscall — hence
/// errno `None` — is not retryable, **even when its redacted message
/// mentions an errno**. `(os error 2)` and `(os error 260)` are the
/// near-misses that separate "only a real 26" from "any error whose text
/// mentions an errno" (note `(os error 260)` even contains `(os error 26`
/// as a prefix).
#[test]
fn io_error_from_token_error_ignores_errno_lookalikes_in_message() {
    for lookalike in ["(os error 2)", "(os error 260)"] {
        let e = TokenResolveError::plain(format!(
            "Failed to exec dynamic token command: Text file busy {lookalike}"
        ));
        assert!(
            e.message.contains(lookalike),
            "test fixture must mention {lookalike}"
        );
        assert_eq!(
            e.raw_os_error, None,
            "{lookalike} in a message must not become a syscall errno"
        );
        let classified = io_error_from_token_error(e);
        assert_eq!(
            classified.raw_os_error(),
            None,
            "{lookalike} must classify as non-retryable"
        );
    }
}

/// End-to-end property that actually matters: feed the classified errors
/// through the retry and show the ETXTBSY one is retried while every
/// non-ETXTBSY one — including the errno-text near-misses — is not.
#[test]
fn classified_errors_are_retried_only_when_etxtbsy() {
    // ETXTBSY: retried, then succeeds.
    let attempts = std::cell::Cell::new(0u32);
    let retried = retry_on_etxtbsy(|| {
        attempts.set(attempts.get() + 1);
        if attempts.get() < 3 {
            Err(io_error_from_token_error(TokenResolveError::from_io(
                "Failed to exec dynamic token command",
                std::io::Error::from_raw_os_error(ETXTBSY),
            )))
        } else {
            Ok("resolved")
        }
    });
    assert_eq!(retried.unwrap(), "resolved");
    assert_eq!(attempts.get(), 3, "ETXTBSY must be retried");

    // A lookalike message that is not a syscall failure: never retried.
    let attempts = std::cell::Cell::new(0u32);
    let not_retried = retry_on_etxtbsy::<()>(|| {
        attempts.set(attempts.get() + 1);
        Err(io_error_from_token_error(TokenResolveError::plain(
            "Failed to exec dynamic token command: Text file busy (os error 260)",
        )))
    });
    assert!(not_retried.is_err());
    assert_eq!(
        attempts.get(),
        1,
        "a message that merely mentions an errno must not be retried"
    );
}

/// The decisive pair: classification must follow the **stored errno**, never
/// the message text. A regression to `message.contains("(os error 26)")`
/// flips both halves of this test, so — unlike the `from_io`-built fixtures
/// above, whose messages also contain the marker — it cannot pass on the
/// outcome alone.
#[test]
fn etxtbsy_classification_follows_errno_not_message_text() {
    // (1) Stored errno 26, message carries NO marker: must still be
    // retryable. A prose scanner would return non-retryable here.
    let errno_only = TokenResolveError {
        message: "Failed to exec dynamic token command: file busy".into(),
        raw_os_error: Some(ETXTBSY),
    };
    assert!(
        !errno_only.message.contains("(os error 26)"),
        "discriminating fixture must have no marker in its message"
    );
    assert_eq!(
        io_error_from_token_error(errno_only).raw_os_error(),
        Some(ETXTBSY),
        "a stored ETXTBSY must stay retryable even without the marker text"
    );

    // (2) Message carries the exact marker, stored errno absent: must NOT be
    // retryable. A prose scanner would return retryable here.
    let prose_only = TokenResolveError {
        message: "Failed to exec dynamic token command: Text file busy (os error 26)".into(),
        raw_os_error: None,
    };
    assert!(prose_only.message.contains("(os error 26)"));
    assert_eq!(
        io_error_from_token_error(prose_only).raw_os_error(),
        None,
        "marker text alone must not be classified as ETXTBSY"
    );

    // And the retry itself follows that classification, both directions.
    let attempts = std::cell::Cell::new(0u32);
    let retried = retry_on_etxtbsy(|| {
        attempts.set(attempts.get() + 1);
        if attempts.get() < 2 {
            Err(io_error_from_token_error(TokenResolveError {
                message: "Failed to exec dynamic token command: file busy".into(),
                raw_os_error: Some(ETXTBSY),
            }))
        } else {
            Ok("resolved")
        }
    });
    assert_eq!(retried.unwrap(), "resolved");
    assert_eq!(attempts.get(), 2, "a stored ETXTBSY must be retried");

    let attempts = std::cell::Cell::new(0u32);
    let not_retried = retry_on_etxtbsy::<()>(|| {
        attempts.set(attempts.get() + 1);
        Err(io_error_from_token_error(TokenResolveError {
            message: "Failed to exec dynamic token command: Text file busy (os error 26)".into(),
            raw_os_error: None,
        }))
    });
    assert!(not_retried.is_err());
    assert_eq!(
        attempts.get(),
        1,
        "marker text without a stored errno must not be retried"
    );
}

/// The real production failure path must carry the errno out of band: a
/// missing exec command fails `execve` with ENOENT (2), and the structured
/// error must expose that, while the user-visible message stays redacted.
///
/// This covers the **synchronous fallback** arm: a plain `#[test]` has no
/// tokio runtime, so `Handle::try_current()` fails and the sync
/// `exec_token_command_sync_timeout` path runs — asserted via the test-only
/// arm record, so this fails if the call is mis-routed to the async arm. The
/// multi-thread async arm that frpc/frps actually use is covered by
/// `exec_spawn_failure_carries_real_errno_async_arm`.
#[test]
fn exec_spawn_failure_carries_real_errno_sync_arm() {
    let uf =
        crate::unsafe_features::UnsafeFeatures::new(crate::unsafe_features::CLIENT_UNSAFE_FEATURES);
    let e = resolve_dynamic_token_inner("exec:///nonexistent/frp-token-cmd-xyz", Some(&uf))
        .expect_err("missing exec command must fail");
    assert!(
        !LAST_EXEC_USED_ASYNC_ARM.with(|arm| arm.get()),
        "a plain #[test] must take the sync exec arm"
    );
    assert_eq!(
        e.raw_os_error,
        Some(2),
        "sync-arm spawn failure must carry the real errno (ENOENT=2), got: {e:?}"
    );
    assert!(
        !e.message.contains("frp-token-cmd-xyz"),
        "message must stay redacted: {}",
        e.message
    );
}

/// The same errno-capture guarantee on the **async arm** — the
/// `tokio::process::Command` path frpc/frps take at startup, since both run
/// on a multi-thread tokio runtime. Executed from a spawned worker (not the
/// `block_on` entry point) so `block_in_place` + `Handle::block_on` is the
/// arm exercised.
///
/// Crucially this compares the test-only arm record taken **on the same
/// thread immediately after the call**, so it fails if a regression routes
/// the multi-thread context to the sync fallback — both arms would otherwise
/// report the identical ENOENT.
#[tokio::test(flavor = "multi_thread")]
async fn exec_spawn_failure_carries_real_errno_async_arm() {
    let uf =
        crate::unsafe_features::UnsafeFeatures::new(crate::unsafe_features::CLIENT_UNSAFE_FEATURES);
    let (used_async_arm, e) = tokio::spawn(async move {
        let e = resolve_dynamic_token_inner("exec:///nonexistent/frp-token-cmd-xyz", Some(&uf))
            .expect_err("missing exec command must fail");
        // Read the arm back on this same worker before yielding.
        (LAST_EXEC_USED_ASYNC_ARM.with(|arm| arm.get()), e)
    })
    .await
    .expect("task must not panic");
    assert!(
        used_async_arm,
        "a spawned multi-thread runtime task must take the async exec arm"
    );
    assert_eq!(
        e.raw_os_error,
        Some(2),
        "async-arm spawn failure must carry the real errno (ENOENT=2), got: {e:?}"
    );
    assert!(
        !e.message.contains("frp-token-cmd-xyz"),
        "message must stay redacted: {}",
        e.message
    );
}

/// A script name unique **per invocation**. The pid alone is not enough: a
/// multi-threaded run, a shared `$TMPDIR` across CI jobs, and pid reuse can
/// each collide. The atomic sequence separates concurrent calls in this
/// process; nanoseconds separate processes and re-runs; the pid keeps two
/// processes that happen to sample the same instant apart.
fn unique_token_script_path() -> std::path::PathBuf {
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!(
        "frp-token-script-{}-{}-{}.sh",
        std::process::id(),
        seq,
        nanos
    ))
}

/// Remove the temporary token script on every exit path, including a panic
/// inside an assertion. The old code removed it before asserting; a guard
/// keeps that guarantee and also covers the retry path.
struct RemoveOnDrop(std::path::PathBuf);

impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[test]
fn retry_on_etxtbsy_retries_a_busy_script_and_succeeds() {
    // Deterministic stand-in for the Linux-only behaviour: the first two
    // attempts report a busy script file, the third succeeds. The helper
    // must retry rather than give up.
    let attempts = std::cell::Cell::new(0u32);
    let result = retry_on_etxtbsy(|| {
        attempts.set(attempts.get() + 1);
        if attempts.get() < 3 {
            Err(std::io::Error::from_raw_os_error(ETXTBSY))
        } else {
            Ok("resolved")
        }
    });
    assert_eq!(result.unwrap(), "resolved");
    assert_eq!(
        attempts.get(),
        3,
        "helper must retry ETXTBSY until the exec succeeds"
    );
}

#[test]
fn retry_on_etxtbsy_does_not_retry_other_errors() {
    // A real spawn failure must surface on the first call — the retry must
    // not be able to hide it.
    let attempts = std::cell::Cell::new(0u32);
    let result = retry_on_etxtbsy::<()>(|| {
        attempts.set(attempts.get() + 1);
        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "No such file or directory",
        ))
    });
    assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::NotFound);
    assert_eq!(
        attempts.get(),
        1,
        "only ETXTBSY may be retried; a genuine spawn error surfaces immediately"
    );
}

#[test]
fn retry_on_etxtbsy_is_bounded() {
    // A permanently busy script must not hang the test forever.
    let attempts = std::cell::Cell::new(0u32);
    let result = retry_on_etxtbsy::<()>(|| {
        attempts.set(attempts.get() + 1);
        Err(std::io::Error::from_raw_os_error(ETXTBSY))
    });
    assert_eq!(result.unwrap_err().raw_os_error(), Some(ETXTBSY));
    assert_eq!(
        attempts.get(),
        ETXTBSY_MAX_ATTEMPTS,
        "retry must be bounded, not infinite"
    );
}

#[test]
fn test_resolve_dynamic_token_exec_failure_redacts_stderr() {
    // Regression: a token script that fails must not leak its stderr
    // output (which may carry secrets) into the error — only the
    // exit-status error class is surfaced.
    let script = unique_token_script_path();
    std::fs::write(
        &script,
        "#!/bin/sh\necho SECRET_STDERR_MARKER_XYZ >&2\nexit 7\n",
    )
    .unwrap();
    let _guard = RemoveOnDrop(script.clone());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let token = format!("exec://{}", script.display());
    let uf =
        crate::unsafe_features::UnsafeFeatures::new(crate::unsafe_features::CLIENT_UNSAFE_FEATURES);
    // On Linux a concurrent writer holding the script open makes `execve`
    // fail with ETXTBSY. The per-invocation name above removes the known
    // collision source; the bounded retry absorbs a residual transient
    // ETXTBSY so the run cannot fail as a *spawn* error. It cannot mask a
    // real spawn failure (non-ETXTBSY → no retry), and the exit-status
    // assertion below is deliberately unchanged.
    let result = retry_on_etxtbsy(|| {
        resolve_dynamic_token_inner(&token, Some(&uf)).map_err(io_error_from_token_error)
    });
    let err = result
        .expect_err("failing token script must be an error")
        .to_string();
    assert!(
        !err.contains("SECRET_STDERR_MARKER_XYZ"),
        "error must not leak stderr: {err}"
    );
    assert!(
        !err.contains("frp-token-script"),
        "error must not leak the script path: {err}"
    );
    assert!(
        err.contains("exited with"),
        "error should retain the exit-status class: {err}"
    );
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
    let uf =
        crate::unsafe_features::UnsafeFeatures::new(&[crate::unsafe_features::TOKEN_SOURCE_FILE]);
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

    let allowed =
        crate::unsafe_features::UnsafeFeatures::new(&[crate::unsafe_features::TOKEN_SOURCE_EXEC]);
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
fn test_auth_timeout_default_matches_serde_default() {
    // AuthConfig::default() must mirror the frps serde default
    // (`default_authentication_timeout` in config/server.rs, 90s).
    // 0 disables the check.
    let cfg = AuthConfig::default();
    assert_eq!(cfg.authentication_timeout, 90);
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
    // Go frp v0.71.0 pkg/auth/token.go:66 literal (audit C3) — the
    // detailed-mode LoginResp.error is err.Error() verbatim.
    assert!(result
        .unwrap_err()
        .contains("token in login doesn't match token from configuration"));
}
