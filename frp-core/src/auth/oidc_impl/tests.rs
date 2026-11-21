use super::*;
use crate::auth::oidc_jwt::test_compat as jsonwebtoken;

/// Build an `OidcVerifier` without any network I/O. The real `new()`
/// fetches openid-configuration and JWKS; `check_replay` only touches
/// `seen_jtis`, so it is testable in isolation.
fn test_verifier() -> OidcVerifier {
    OidcVerifier {
        audience: String::new(),
        additional_audience: Vec::new(),
        issuer: String::new(),
        jwks_uri: String::new(),
        jwks: tokio::sync::RwLock::new(None),
        skip_expiry: false,
        skip_issuer: false,
        skip_nbf: false,
        skip_audience: false,
        http: crate::http_client::HttpClientBuilder::new()
            .tls_skip_verify(true)
            .build()
            .expect("test HTTP client"),
        seen_jtis: std::sync::Mutex::new(std::collections::HashMap::new()),
        last_replay_sweep: std::sync::atomic::AtomicI64::new(0),
        refresh_task: std::sync::Mutex::new(None),
        last_forced_refresh: std::sync::Mutex::new(None),
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

#[test]
fn check_replay_pending_matches_check_replay_without_recording() {
    // S2: the pre-verify replay pre-check must agree with the
    // post-verify `check_replay` rejection semantics (same jti +
    // same subject allowed, different subject → replay) and must
    // NEVER record — only fully verified tokens populate the table,
    // so an unauthenticated flood cannot poison it or evict live
    // entries.
    let v = test_verifier();
    let now = now();
    // Record j1 → alice (as a verified login would).
    assert!(v.check_replay(Some("j1"), "alice", now + 3600).is_ok());
    // Different subject → pending replay.
    assert!(v.check_replay_pending(Some("j1"), "bob"));
    // Same subject → allowed.
    assert!(!v.check_replay_pending(Some("j1"), "alice"));
    // Unknown jti → not pending.
    assert!(!v.check_replay_pending(Some("j2"), "alice"));
    // No jti / oversized jti → not pending (verify_login is the
    // authoritative judge for both).
    assert!(!v.check_replay_pending(None, "alice"));
    let long: String = "x".repeat(MAX_JTI_LEN_BYTES + 1);
    assert!(!v.check_replay_pending(Some(&long), "alice"));
    // The pre-check never records: table unchanged after the reads.
    let seen = v.seen_jtis.lock().unwrap();
    assert_eq!(seen.len(), 1, "pre-check must not record");
    assert!(seen.contains_key("j1"));
}

#[test]
fn extract_claims_unverified_reads_payload_without_signature() {
    // S2: claims come from the base64url payload segment alone — a
    // token with a BOGUS signature (which verify_login would reject)
    // still yields its claims, so the replay pre-check can run
    // before the expensive verify path.
    let v = test_verifier();
    let token = jsonwebtoken::encode(
        &jsonwebtoken::Header {
            alg: jsonwebtoken::Algorithm::HS256,
            ..jsonwebtoken::Header::default()
        },
        &serde_json::json!({"jti": "j1", "sub": "alice", "exp": 4_102_444_800_u64}),
        &jsonwebtoken::EncodingKey::from_secret(b"bogus-key"),
    )
    .expect("encode JWT");
    let (jti, sub, exp) = v.extract_claims_unverified(&token).expect("extract claims");
    assert_eq!(jti.as_deref(), Some("j1"));
    assert_eq!(sub, "alice");
    assert_eq!(exp, 4_102_444_800);
    // No jti claim → None (pre-check is a no-op for such tokens).
    let token2 = jsonwebtoken::encode(
        &jsonwebtoken::Header::default(),
        &serde_json::json!({"sub": "bob"}),
        &jsonwebtoken::EncodingKey::from_secret(b"bogus-key"),
    )
    .expect("encode JWT");
    let (jti2, sub2, _) = v
        .extract_claims_unverified(&token2)
        .expect("extract claims");
    assert!(jti2.is_none());
    assert_eq!(sub2, "bob");
    // Malformed tokens → Err (caller falls through to verify_login).
    assert!(v.extract_claims_unverified("not-a-jwt").is_err());
    assert!(v.extract_claims_unverified("a.b").is_err());
    assert!(v.extract_claims_unverified("a.b!c").is_err());
}

#[test]
fn base64url_decode_vectors() {
    assert_eq!(base64url_decode("").unwrap(), b"");
    assert_eq!(base64url_decode("Zg").unwrap(), b"f");
    assert_eq!(base64url_decode("Zm8").unwrap(), b"fo");
    assert_eq!(base64url_decode("Zm9v").unwrap(), b"foo");
    assert_eq!(base64url_decode("aGVsbG8").unwrap(), b"hello");
    // URL-safe chars decode where standard-alphabet decode would fail.
    assert_eq!(base64url_decode("_w").unwrap(), b"\xff");
    assert_eq!(base64url_decode("-_w").unwrap(), b"\xfb\xfc");
    // Rejects invalid characters and non-zero trailing bits
    // (RFC 4648 §3.2) — padding too (JWT payloads are unpadded).
    assert!(base64url_decode("ab=c").is_err());
    assert!(base64url_decode("Zh").is_err());
}

#[tokio::test]
async fn refresh_warranted_retry_skips_outbound_fetch_within_cooldown() {
    // A forged token (valid kid, signature that fails against the
    // cached key) classifies as key-related and would trigger one
    // outbound JWKS GET per attempt. The cooldown gate (F1) must
    // suppress the fetch inside the window and return the original
    // verification error instead.
    use jsonwebtoken::{Algorithm, EncodingKey, Header, Validation};

    let v = test_verifier();
    // Seed the JWKS cache with an oct key whose secret differs from
    // the signing secret → InvalidSignature (refresh_warranted=true).
    *v.jwks.write().await = Some(CachedJwks {
        keys: serde_json::json!({
            "keys": [{
                "kty": "oct",
                "kid": "k1",
                "k": crate::base64::encode(b"mock-jwks-secret"),
            }]
        }),
        fetched_at: std::time::Instant::now(),
        refresh_after: std::time::Duration::from_secs(3600),
    });
    let forged = jsonwebtoken::encode(
        &Header {
            alg: Algorithm::HS256,
            kid: Some("k1".into()),
        },
        &serde_json::json!({"sub": "attacker", "exp": 4_102_444_800_u64}),
        &EncodingKey::from_secret(b"attacker-secret"),
    )
    .expect("encode forged token");
    // Sanity: the forged signature really is a key-related failure.
    let e = v
        .try_verify_token(&forged, &Validation::new(Algorithm::HS256), Some("k1"))
        .await
        .expect_err("forged signature must fail");
    assert!(e.refresh_warranted, "forged signature must be key-related");

    // Cooldown active: the retry must skip the outbound fetch and
    // return the ORIGINAL verification error — not a fetch error.
    *v.last_forced_refresh.lock().unwrap() = Some(std::time::Instant::now());
    let err = v
        .verify_login(&forged)
        .await
        .expect_err("forged token must fail");
    assert!(
        err.contains("JWT verification failed"),
        "cooldown-active failure must be the original verify error, got: {err}"
    );
    assert!(
        !err.contains("fetch JWKS"),
        "no outbound fetch may happen inside the cooldown window: {err}"
    );

    // Cooldown elapsed: the retry performs the outbound fetch — which
    // fails against the test verifier's empty jwks_uri — proving the
    // gate (not something else) suppressed it.
    *v.last_forced_refresh.lock().unwrap() = Some(
        std::time::Instant::now()
            - JWKS_FORCED_REFRESH_MIN_INTERVAL
            - std::time::Duration::from_secs(1),
    );
    let err = v
        .verify_login(&forged)
        .await
        .expect_err("forged token must fail");
    assert!(
        err.contains("failed to fetch JWKS"),
        "cooldown-elapsed retry must attempt the outbound fetch, got: {err}"
    );
}

/// Seed the verifier's JWKS cache with the given keys JSON — same
/// no-network fixture pattern as
/// `refresh_warranted_retry_skips_outbound_fetch_within_cooldown`.
async fn test_verifier_with_jwks(keys: serde_json::Value) -> OidcVerifier {
    let v = test_verifier();
    *v.jwks.write().await = Some(CachedJwks {
        keys,
        fetched_at: std::time::Instant::now(),
        refresh_after: std::time::Duration::from_secs(3600),
    });
    v
}

/// Seed the JWKS cache AND set the config knobs under test (issuer /
/// audience / additional_audience / skip flags). `verify_login`
/// derives its jsonwebtoken `Validation` from exactly these fields
/// (frp-core/src/auth.rs:867-889: `validate_exp = !skip_expiry`,
/// `validate_nbf = !skip_nbf`, `set_issuer` when `!skip_issuer`,
/// `set_audience` when an audience is configured), so the semantic
/// rejection arms (expired / nbf-future / wrong issuer / wrong
/// audience) are only reachable through the right configuration —
/// `test_verifier` keeps issuer and audience EMPTY, which disables
/// both checks (tokens without `iss` pass; `audience_validation`
/// returns None → `validate_aud = false`).
#[allow(clippy::too_many_arguments)]
async fn verifier_with_config(
    issuer: &str,
    audience: &str,
    additional_audience: &[&str],
    skip_expiry: bool,
    skip_issuer: bool,
    skip_nbf: bool,
    skip_audience: bool,
    keys: serde_json::Value,
) -> OidcVerifier {
    let mut v = test_verifier();
    v.issuer = issuer.to_string();
    v.audience = audience.to_string();
    v.additional_audience = additional_audience.iter().map(|s| s.to_string()).collect();
    v.skip_expiry = skip_expiry;
    v.skip_issuer = skip_issuer;
    v.skip_nbf = skip_nbf;
    v.skip_audience = skip_audience;
    *v.jwks.write().await = Some(CachedJwks {
        keys,
        fetched_at: std::time::Instant::now(),
        refresh_after: std::time::Duration::from_secs(3600),
    });
    v
}

/// Single oct-key JWKS fixture (kid "k1") used by the semantic
/// rejection tests below.
fn oct_jwks(secret: &[u8]) -> serde_json::Value {
    serde_json::json!({
        "keys": [{
            "kty": "oct",
            "kid": "k1",
            "k": crate::base64::encode(secret),
        }]
    })
}

/// Encode an HS256 JWT with the given kid and claims.
fn encode_hs256(kid: &str, secret: &[u8], claims: &serde_json::Value) -> String {
    jsonwebtoken::encode(
        &jsonwebtoken::Header {
            alg: jsonwebtoken::Algorithm::HS256,
            kid: Some(kid.to_string()),
        },
        claims,
        &jsonwebtoken::EncodingKey::from_secret(secret),
    )
    .expect("encode HS256 token")
}

/// URL-safe base64 without padding (JWT segment form). The inline
/// `frp_core::base64` module is standard-alphabet with padding; the
/// two alphabets differ only in chars 62/63 and padding is dropped.
fn base64url_encode(data: &[u8]) -> String {
    crate::base64::encode(data)
        .replace('+', "-")
        .replace('/', "_")
        .trim_end_matches('=')
        .to_string()
}

/// Hand-roll a JWT whose header carries the given `alg` string.
/// jsonwebtoken's typed `Header`/encode API cannot emit an algorithm
/// outside its 12-variant enum, but the wire form can — and
/// `decode_header` parses the header segment alone, so the payload
/// and signature segments only need to be structurally present.
fn raw_jwt_with_alg(alg: &str) -> String {
    let header = serde_json::json!({"alg": alg, "kid": "k1"}).to_string();
    format!(
        "{}.{}.{}",
        base64url_encode(header.as_bytes()),
        base64url_encode(br#"{"sub":"alice","exp":4102444800}"#),
        base64url_encode(b"bogus-signature")
    )
}

#[tokio::test]
async fn oidc_verify_login_valid_hs256_token_extracts_claims() {
    // A VALID HS256 JWT (oct JWKS key, kid match) must verify through
    // the full verify_login path — algorithm allowlist, kid-key
    // selection, claim validation (sub/exp) — and yield the extracted
    // subject, expiry and jti (frp-core/src/auth.rs:982-997).
    const SECRET: &[u8] = b"oidc-jwks-hs256-secret";
    let v = test_verifier_with_jwks(serde_json::json!({
        "keys": [{
            "kty": "oct",
            "kid": "k1",
            "k": crate::base64::encode(SECRET),
        }]
    }))
    .await;
    let future = now() + 3600;
    let token = encode_hs256(
        "k1",
        SECRET,
        &serde_json::json!({"sub": "alice", "exp": future, "jti": "jti-1"}),
    );

    let ok = v
        .verify_login(&token)
        .await
        .expect("valid HS256 token must verify");
    assert_eq!(ok.subject, "alice", "sub claim extraction");
    assert_eq!(ok.expiry, future, "exp claim extraction");
    assert_eq!(ok.jti.as_deref(), Some("jti-1"), "jti claim extraction");
}

/// URL-safe base64 of a JWT segment (test fixture).
fn b64url(data: &[u8]) -> String {
    crate::auth::oidc_jwt::base64url_encode(data)
}

/// Header.payload for an HS256-less test token (the caller signs it).
fn signing_input(alg: &str, kid: &str, claims: &serde_json::Value) -> String {
    let header = serde_json::json!({"alg": alg, "kid": kid});
    format!(
        "{}.{}",
        b64url(&serde_json::to_vec(&header).expect("header JSON")),
        b64url(&serde_json::to_vec(claims).expect("claims JSON"))
    )
}

#[tokio::test]
async fn oidc_verify_login_rs256_static_vector_through_jwks() {
    // The dominant real-world IdP algorithm: the RSA JWK goes through
    // `decoding_key_from_jwk` and the token through the full
    // `verify_login` path (kid selection, signature, claims).
    const N: &str = "rrVOVI4qODpvIJMU8UyE84-l0v61s1CdIJWavn4FG04ahIwGsk2OvF3aOSBMy8A_CMqqzg08hSmg_CxF6NeLBczcAa30s1KY0I26NaKR-s44J0PedrgHPwPawZBnWsU7jsHjZ3r-FXCyHG_GcID1RHWN0kALeQkag_jf3dOtCNh4eN52xN0icq_M5XvPEKBqWV602Zd1PalLUPJvaHCmd3qZEoYG4y3CvupA1ZcbQzWJwUyfNuzfCb3J2QSwVcQaZJL8s3WVp4ar9w_Z02Ursy5_686sQF4GjaLesovHnh_D3REyI8_NylWwuUI4WOJyoy7oAiGYI6aUVdp1T4XnnQ";
    const E: &str = "AQAB";
    const RS256: &str = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImsxIn0.eyJzdWIiOiJhbGljZSIsImV4cCI6NDEwMjQ0NDgwMH0.XPCMTstpjMXM8Bc1jr95YAd0WLdmQfsEv-TVd-W0lJ9s4_pGKPJwIL_6Wy75fm1b8va4hqUt5RdKgDbRWprWBqBLoHTf8nszRMbZUApJVEOIed25Sg-_8x-77CFYpTTHbpEcZ3dByMxBQWwKEgDuIy7m4v2Ku6KtWpepLUYJFGw0mXw8l7ZDbdLawHCR3DQJMGKEqdeX9agCP5UepFW2HTTVI7-S6vV-XkS_tGe1awu3o_wJmunKH6mTwZ-RP-j7DpXfRqhWTXjM22feOCkNSBjYH9JdZupMwIG96gIrfH4RYWLzkYiMKCJZEu5NgIGnDQbiIazEw1vX7IrQxqaWBw";
    let v = test_verifier_with_jwks(serde_json::json!({
        "keys": [{"kty": "RSA", "kid": "k1", "n": N, "e": E, "alg": "RS256", "use": "sig"}]
    }))
    .await;
    let ok = v
        .verify_login(RS256)
        .await
        .expect("RS256 token through the full verify_login path");
    assert_eq!(ok.subject, "alice");
    assert_eq!(ok.expiry, 4_102_444_800);
}

#[tokio::test]
async fn oidc_verify_login_ec_and_eddsa_jwks() {
    use ring::rand::SystemRandom;
    use ring::signature::{EcdsaKeyPair, Ed25519KeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};

    let rng = SystemRandom::new();
    let claims = serde_json::json!({"sub": "key-user", "exp": now() + 3600});

    // ES256: JWK x/y must come out of the uncompressed public point.
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
    let pair =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng).unwrap();
    let point = pair.public_key().as_ref();
    let input = signing_input("ES256", "ec1", &claims);
    let signature = pair.sign(&rng, input.as_bytes()).unwrap();
    let token = format!("{input}.{}", b64url(signature.as_ref()));
    let v = test_verifier_with_jwks(serde_json::json!({
        "keys": [{
            "kty": "EC", "kid": "ec1", "crv": "P-256",
            "x": b64url(&point[1..33]), "y": b64url(&point[33..]),
        }]
    }))
    .await;
    let ok = v.verify_login(&token).await.expect("ES256 via JWKS");
    assert_eq!(ok.subject, "key-user");

    // EdDSA: OKP/Ed25519 JWK.
    let ed_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let ed = Ed25519KeyPair::from_pkcs8(ed_pkcs8.as_ref()).unwrap();
    let input = signing_input("EdDSA", "ed1", &claims);
    let signature = ed.sign(input.as_bytes());
    let token = format!("{input}.{}", b64url(signature.as_ref()));
    let v = test_verifier_with_jwks(serde_json::json!({
        "keys": [{
            "kty": "OKP", "kid": "ed1", "crv": "Ed25519",
            "x": b64url(ed.public_key().as_ref()),
        }]
    }))
    .await;
    let ok = v.verify_login(&token).await.expect("EdDSA via JWKS");
    assert_eq!(ok.subject, "key-user");
}

#[tokio::test]
async fn oidc_verify_login_token_with_unknown_kid_rejected() {
    // kid-selection (frp-core/src/auth.rs:965-969): a token whose kid is not
    // present in the JWKS must fail WITHOUT trying any key — and
    // because no key was tried the failure is not key-related, so no
    // refresh-warranted retry (and no outbound JWKS fetch) happens.
    const SECRET: &[u8] = b"oidc-jwks-hs256-secret";
    let v = test_verifier_with_jwks(serde_json::json!({
        "keys": [{
            "kty": "oct",
            "kid": "k1",
            "k": crate::base64::encode(SECRET),
        }]
    }))
    .await;
    let token = encode_hs256(
        "missing-kid",
        SECRET,
        &serde_json::json!({"sub": "alice", "exp": now() + 3600}),
    );

    let err = v
        .verify_login(&token)
        .await
        .expect_err("token with an unknown kid must be rejected");
    assert!(
        err.contains("JWT verification failed"),
        "unexpected error: {err}"
    );
    assert!(
        !err.contains("fetch JWKS"),
        "kid-skip must not trigger an outbound JWKS refresh: {err}"
    );
}

#[tokio::test]
async fn oidc_try_verify_token_kid_selects_matching_jwks_key() {
    // Two JWKS keys with distinct secrets: kid-selection must skip
    // the non-matching key — a token signed with secret B verifies
    // when presented with kid kB, and fails (InvalidSignature, not a
    // successful kB decode) when presented with kid kA.
    const SECRET_A: &[u8] = b"oidc-test-hs256-secret";
    const SECRET_B: &[u8] = b"oidc-verifier-secret";
    let v = test_verifier_with_jwks(serde_json::json!({
        "keys": [
            {"kty": "oct", "kid": "kA", "k": crate::base64::encode(SECRET_A)},
            {"kty": "oct", "kid": "kB", "k": crate::base64::encode(SECRET_B)},
        ]
    }))
    .await;
    let validation = {
        let mut val = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
        val.required_spec_claims.insert("sub".to_string());
        val
    };
    let claims = serde_json::json!({"sub": "alice", "exp": now() + 3600});

    // kid kB + secret B → selects the kB key → verifies.
    let token_b = encode_hs256("kB", SECRET_B, &claims);
    let ok = v
        .try_verify_token(&token_b, &validation, Some("kB"))
        .await
        .expect("kid kB must select the kB key");
    assert_eq!(ok.subject, "alice");

    // kid kA + secret B → kid-selection picks kA whose secret
    // differs; the kB key must NOT be tried, so this is a key-related
    // signature failure (refresh_warranted).
    let wrong_kid = encode_hs256("kA", SECRET_B, &claims);
    let e = v
        .try_verify_token(&wrong_kid, &validation, Some("kA"))
        .await
        .expect_err("wrong key selected for the kid must fail");
    assert!(
        e.refresh_warranted,
        "signature failure with the selected key is key-related"
    );
}

#[tokio::test]
async fn oidc_try_verify_token_rejects_empty_subject() {
    // "sub" is a required claim (presence is enforced by
    // jsonwebtoken), but an EMPTY subject must still be rejected —
    // subject-based proxy routing would otherwise be bypassable
    // (frp-core/src/auth.rs:986-990).
    const SECRET: &[u8] = b"oidc-jwks-hs256-secret";
    let v = test_verifier_with_jwks(serde_json::json!({
        "keys": [{
            "kty": "oct",
            "kid": "k1",
            "k": crate::base64::encode(SECRET),
        }]
    }))
    .await;
    let validation = {
        let mut val = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
        val.required_spec_claims.insert("sub".to_string());
        val
    };
    // Signed correctly (kid k1 + matching secret) — only sub is empty,
    // so the rejection must come from the empty-sub check.
    let token = encode_hs256(
        "k1",
        SECRET,
        &serde_json::json!({"sub": "", "exp": now() + 3600}),
    );

    let e = v
        .try_verify_token(&token, &validation, Some("k1"))
        .await
        .expect_err("empty subject must be rejected");
    assert!(
        e.message.contains("subject (sub) is empty"),
        "unexpected error: {}",
        e.message
    );
    assert!(
        !e.refresh_warranted,
        "empty-sub is a semantic error, not key-related"
    );
}

#[tokio::test]
async fn oidc_verify_login_rejects_expired_token_when_expiry_enforced() {
    // Coverage gap D: the EXPIRED-token rejection arm (ExpiredSignature
    // from jsonwebtoken's validate_exp — the e2e suite always sets
    // oidc_skip_expiry=true) is fed adversarially. Expiry is enforced
    // by default (skip_expiry=false → validate_exp=true, frp-core/src/auth.rs:868),
    // the signature is VALID against the cached oct key (kid k1), so
    // the rejection must come from the expiry check — and being a
    // semantic error it must NOT warrant a JWKS refetch.
    const SECRET: &[u8] = b"oidc-jwks-hs256-secret";
    // Far enough in the past to clear jsonwebtoken's 60s leeway.
    let expired = now() - 3600;
    let v = verifier_with_config("", "", &[], false, false, false, false, oct_jwks(SECRET)).await;
    let token = encode_hs256(
        "k1",
        SECRET,
        &serde_json::json!({"sub": "alice", "exp": expired}),
    );

    let err = v
        .verify_login(&token)
        .await
        .expect_err("expired token must be rejected with expiry enforced");
    assert_eq!(
        err, "OIDC: JWT verification failed: ExpiredSignature",
        "expiry rejection must surface the ExpiredSignature marker"
    );
    assert!(
        v.last_forced_refresh.lock().unwrap().is_none(),
        "a semantic rejection must not arm the refresh-warranted path"
    );
    // Direct seam: the decode error is classified not key-related.
    let mut val = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
    val.required_spec_claims.insert("sub".to_string());
    let e = v
        .try_verify_token(&token, &val, Some("k1"))
        .await
        .expect_err("expired token must fail the direct seam too");
    assert!(
        !e.refresh_warranted,
        "expired is semantic (no JWKS refresh), not key-related"
    );

    // Control: the very same token is ACCEPTED with oidc_skip_expiry
    // = true — proves the rejection above is the expiry arm and the
    // flag plumbing (skip_expiry → validate_exp) works end to end.
    let v_skip =
        verifier_with_config("", "", &[], true, false, false, false, oct_jwks(SECRET)).await;
    let ok = v_skip
        .verify_login(&token)
        .await
        .expect("skip_expiry must accept the expired token");
    assert_eq!(ok.subject, "alice");
    assert_eq!(
        ok.expiry, expired,
        "exp claim extraction on the accepted token"
    );
}

#[tokio::test]
async fn oidc_verify_login_rejects_future_nbf_when_nbf_enforced() {
    // Coverage gap D: the nbf-future rejection arm (ImmatureSignature).
    // validate_nbf is off in jsonwebtoken's default Validation and only
    // fires via frp-core/src/auth.rs:869 (`validate_nbf = !self.skip_nbf`), so the
    // rejection proves the flag reaches the Validation builder. The
    // signature is valid; the token is not yet valid per its own nbf.
    const SECRET: &[u8] = b"oidc-jwks-hs256-secret";
    let v = verifier_with_config("", "", &[], false, false, false, false, oct_jwks(SECRET)).await;
    let token = encode_hs256(
        "k1",
        SECRET,
        &serde_json::json!({
            "sub": "alice",
            "exp": now() + 3600,
            // Far enough in the future to clear the 60s leeway.
            "nbf": now() + 3600,
        }),
    );

    let err = v
        .verify_login(&token)
        .await
        .expect_err("future nbf must be rejected with nbf enforced");
    assert_eq!(
        err, "OIDC: JWT verification failed: ImmatureSignature",
        "nbf rejection must surface the ImmatureSignature marker"
    );
    assert!(
        v.last_forced_refresh.lock().unwrap().is_none(),
        "a semantic rejection must not arm the refresh-warranted path"
    );
    // Direct seam: not key-related.
    let mut val = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
    val.required_spec_claims.insert("sub".to_string());
    val.validate_nbf = true;
    let e = v
        .try_verify_token(&token, &val, Some("k1"))
        .await
        .expect_err("future-nbf token must fail the direct seam too");
    assert!(
        !e.refresh_warranted,
        "immature is semantic (no JWKS refresh), not key-related"
    );

    // Control: same token ACCEPTED with oidc_skip_nbf = true.
    let v_skip =
        verifier_with_config("", "", &[], false, false, true, false, oct_jwks(SECRET)).await;
    let ok = v_skip
        .verify_login(&token)
        .await
        .expect("skip_nbf must accept the future-nbf token");
    assert_eq!(ok.subject, "alice");
}

#[tokio::test]
async fn oidc_verify_login_rejects_wrong_issuer_when_issuer_enforced() {
    // Coverage gap D: the wrong-issuer rejection arm (InvalidIssuer).
    // The issuer check fires only when skip_issuer=false (frp-core/src/auth.rs:870)
    // AND the token carries an `iss` claim; the signature is valid, so
    // a mismatch between the token's iss and the verifier's configured
    // issuer must surface InvalidIssuer — a semantic error.
    const SECRET: &[u8] = b"oidc-jwks-hs256-secret";
    const ISSUER: &str = "https://issuer.example";
    let v = verifier_with_config(
        ISSUER,
        "",
        &[],
        false,
        false,
        false,
        false,
        oct_jwks(SECRET),
    )
    .await;
    let token = encode_hs256(
        "k1",
        SECRET,
        &serde_json::json!({
            "sub": "alice",
            "exp": now() + 3600,
            "iss": "https://evil.example",
        }),
    );

    let err = v
        .verify_login(&token)
        .await
        .expect_err("token from a wrong issuer must be rejected");
    assert_eq!(
        err, "OIDC: JWT verification failed: InvalidIssuer",
        "issuer rejection must surface the InvalidIssuer marker"
    );
    assert!(
        v.last_forced_refresh.lock().unwrap().is_none(),
        "a semantic rejection must not arm the refresh-warranted path"
    );
    // Direct seam: not key-related.
    let mut val = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
    val.required_spec_claims.insert("sub".to_string());
    val.set_issuer(&[ISSUER]);
    let e = v
        .try_verify_token(&token, &val, Some("k1"))
        .await
        .expect_err("wrong-issuer token must fail the direct seam too");
    assert!(
        !e.refresh_warranted,
        "wrong issuer is semantic (no JWKS refresh), not key-related"
    );

    // Controls on the same verifier: a matching iss is ACCEPTED with
    // enforcement on; the wrong-issuer token is ACCEPTED with
    // oidc_skip_issuer = true.
    let good = encode_hs256(
        "k1",
        SECRET,
        &serde_json::json!({
            "sub": "alice",
            "exp": now() + 3600,
            "iss": ISSUER,
        }),
    );
    let ok = v
        .verify_login(&good)
        .await
        .expect("matching issuer must verify with enforcement on");
    assert_eq!(ok.subject, "alice");
    let v_skip =
        verifier_with_config(ISSUER, "", &[], false, true, false, false, oct_jwks(SECRET)).await;
    let ok = v_skip
        .verify_login(&token)
        .await
        .expect("skip_issuer must accept the wrong-issuer token");
    assert_eq!(ok.subject, "alice");
}

#[tokio::test]
async fn oidc_verify_login_rejects_wrong_audience_when_audience_configured() {
    // Coverage gap D: the wrong-audience rejection arm (InvalidAudience).
    // Audience validation fires when an audience is configured and
    // skip_audience=false (frp-core/src/auth.rs:873-885); the token's `aud` claim
    // must contain the configured audience. The signature is valid, so
    // a mismatch must surface InvalidAudience — a semantic error.
    const SECRET: &[u8] = b"oidc-jwks-hs256-secret";
    const AUDIENCE: &str = "api-prod";
    let v = verifier_with_config(
        "",
        AUDIENCE,
        &[],
        false,
        false,
        false,
        false,
        oct_jwks(SECRET),
    )
    .await;
    let token = encode_hs256(
        "k1",
        SECRET,
        &serde_json::json!({
            "sub": "alice",
            "exp": now() + 3600,
            "aud": "other-app",
        }),
    );

    let err = v
        .verify_login(&token)
        .await
        .expect_err("token for a different audience must be rejected");
    assert_eq!(
        err, "OIDC: JWT verification failed: InvalidAudience",
        "audience rejection must surface the InvalidAudience marker"
    );
    assert!(
        v.last_forced_refresh.lock().unwrap().is_none(),
        "a semantic rejection must not arm the refresh-warranted path"
    );
    // Direct seam: not key-related.
    let mut val = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
    val.required_spec_claims.insert("sub".to_string());
    val.set_audience(&[AUDIENCE]);
    let e = v
        .try_verify_token(&token, &val, Some("k1"))
        .await
        .expect_err("wrong-audience token must fail the direct seam too");
    assert!(
        !e.refresh_warranted,
        "wrong audience is semantic (no JWKS refresh), not key-related"
    );

    // Controls: matching aud (and a matching aud inside an array-form
    // claim) is ACCEPTED on the same verifier; the wrong-aud token is
    // ACCEPTED with oidc_skip_audience = true.
    let good = encode_hs256(
        "k1",
        SECRET,
        &serde_json::json!({
            "sub": "alice",
            "exp": now() + 3600,
            "aud": AUDIENCE,
        }),
    );
    let ok = v
        .verify_login(&good)
        .await
        .expect("matching audience must verify");
    assert_eq!(ok.subject, "alice");
    let good_array = encode_hs256(
        "k1",
        SECRET,
        &serde_json::json!({
            "sub": "alice",
            "exp": now() + 3600,
            "aud": ["unrelated", AUDIENCE],
        }),
    );
    let ok = v
        .verify_login(&good_array)
        .await
        .expect("audience array containing the configured value must verify");
    assert_eq!(ok.subject, "alice");
    let v_skip = verifier_with_config(
        "",
        AUDIENCE,
        &[],
        false,
        false,
        false,
        true,
        oct_jwks(SECRET),
    )
    .await;
    let ok = v_skip
        .verify_login(&token)
        .await
        .expect("skip_audience must accept the wrong-audience token");
    assert_eq!(ok.subject, "alice");
}

#[tokio::test]
async fn oidc_verify_login_rejects_alg_outside_allowlist_before_verification() {
    // Coverage gap D: the algorithm rejection surface. The Algorithm
    // enum (frp-core/src/auth/oidc_jwt.rs:31-44) is the allowlist: it
    // has exactly the 12 JOSE names OIDC uses, and serde rejects any
    // other at header decode — "none" (unsigned-JWT attack) or
    // "ES512" (a real JOSE name the verifier does not implement) —
    // BEFORE signature verification and before any JWKS access. Both
    // shapes must fail closed with the header-decode marker and arm
    // nothing.
    const SECRET: &[u8] = b"oidc-jwks-hs256-secret";
    let v = verifier_with_config("", "", &[], false, false, false, false, oct_jwks(SECRET)).await;
    for alg in ["none", "ES512"] {
        let token = raw_jwt_with_alg(alg);
        let err = v
            .verify_login(&token)
            .await
            .expect_err("a token with a disallowed alg must be rejected");
        assert!(
            err.starts_with("OIDC: failed to decode JWT header: JSON error: "),
            "disallowed alg must fail at header decode, got: {err}"
        );
        assert!(
            err.contains(&format!("unknown variant `{alg}`")),
            "the rejection must name the offending alg, got: {err}"
        );
        assert!(
            !err.contains("fetch JWKS") && !err.contains("JWT verification failed"),
            "no JWKS access or signature attempt may precede the alg rejection: {err}"
        );
    }
    assert!(
        v.last_forced_refresh.lock().unwrap().is_none(),
        "alg rejection must not arm the refresh-warranted path"
    );
}

/// Counting token endpoint for OidcClient caching tests: serves every
/// request with a fixed JSON body and counts how many requests
/// arrived. Unlike `TokenEndpointCapture` (which handles exactly one
/// request and captures its form body), this variant accepts an
/// arbitrary number of connections so cache-hit vs re-fetch behavior
/// can be asserted via the request count.
struct CountingTokenEndpoint {
    _addr: std::net::SocketAddr,
    served: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl CountingTokenEndpoint {
    /// Response includes `expires_in` → the client may cache the token.
    async fn with_expires_in() -> CountingTokenEndpoint {
        Self::start(r#"{"access_token":"tok-1","expires_in":3600}"#)
    }

    /// Response omits `expires_in` → the client must switch to
    /// non-caching mode (Go frp nonCachingTokenSource parity).
    async fn without_expires_in() -> CountingTokenEndpoint {
        Self::start(r#"{"access_token":"tok-1"}"#)
    }

    fn start(body: &'static str) -> CountingTokenEndpoint {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let served = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let served_for_thread = served.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = match stream {
                    Ok(s) => s,
                    Err(_) => break,
                };
                served_for_thread.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let mut buf = [0u8; 16384];
                let _ = std::io::Read::read(&mut stream, &mut buf);
                // Connection: close makes hyper open a fresh connection
                // per request, so the counter is per-request exact.
                let _ = std::io::Write::write_all(
                    &mut stream,
                    format!(
                        "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}",
                        body.len(),
                        body
                    )
                    .as_bytes(),
                );
            }
        });
        CountingTokenEndpoint {
            _addr: addr,
            served,
        }
    }

    fn count(&self) -> usize {
        self.served.load(std::sync::atomic::Ordering::SeqCst)
    }
}

async fn test_oidc_client_with_endpoint(endpoint: &str) -> OidcClient {
    OidcClient::new(
        "client-1".into(),
        "secret".into(),
        "api-prod".into(),
        Some(endpoint.to_string()),
        "openid".into(),
        None,
        &std::collections::HashMap::new(),
        None,
        false,
        None,
        None,
    )
    .await
    .expect("OidcClient::new")
}

#[tokio::test]
async fn test_oidc_client_fetches_fresh_token_when_expires_in_omitted() {
    // Go frp parity (nonCachingTokenSource): when the token endpoint
    // omits `expires_in` the client cannot know when the token
    // expires, so every get_token call must hit the network again
    // instead of serving from the cache (frp-core/src/auth.rs:1461-1464).
    let endpoint = CountingTokenEndpoint::without_expires_in().await;
    let client = test_oidc_client_with_endpoint(&format!("http://{}/token", endpoint._addr)).await;

    let t1 = client.get_token().await.expect("first fetch");
    let t2 = client.get_token().await.expect("second fetch");
    assert_eq!(t1, "tok-1");
    assert_eq!(t2, "tok-1");
    assert_eq!(
        endpoint.count(),
        2,
        "missing expires_in must force a fresh fetch per call"
    );
}

#[tokio::test]
async fn test_oidc_client_caches_token_until_expiry() {
    // With expires_in present, the second call inside the expiry
    // window must be served from the cache — exactly one HTTP fetch
    // total (frp-core/src/auth.rs:1467-1471).
    let endpoint = CountingTokenEndpoint::with_expires_in().await;
    let client = test_oidc_client_with_endpoint(&format!("http://{}/token", endpoint._addr)).await;

    let t1 = client.get_token().await.expect("first fetch");
    let t2 = client.get_token().await.expect("cached token");
    assert_eq!(t1, "tok-1");
    assert_eq!(t2, "tok-1");
    assert_eq!(endpoint.count(), 1, "second call must hit the cache");
}

#[test]
fn test_sanitize_expires_in() {
    // 60s refresh margin floors the cache window: a token expiring
    // within the margin (or already declared expired) is never
    // cached — every get_token call refetches, exactly the margin's
    // purpose of avoiding edge-of-expiry failures.
    assert_eq!(sanitize_expires_in(0), 0);
    assert_eq!(sanitize_expires_in(59), 0);
    assert_eq!(sanitize_expires_in(60), 0);
    // Normal provider lifetimes pass through, minus the margin.
    assert_eq!(sanitize_expires_in(61), 1);
    assert_eq!(sanitize_expires_in(300), 240);
    assert_eq!(sanitize_expires_in(3600), 3540);
    // Cap boundary: 24h + margin lands exactly on the cap; 24h alone
    // passes through minus the margin (still under the cap).
    assert_eq!(
        sanitize_expires_in(OIDC_EXPIRES_IN_CAP_SECS + 60),
        OIDC_EXPIRES_IN_CAP_SECS
    );
    assert_eq!(
        sanitize_expires_in(OIDC_EXPIRES_IN_CAP_SECS),
        OIDC_EXPIRES_IN_CAP_SECS - 60
    );
    // Hostile/broken IdP values are capped — the cached-token write
    // `Instant::now() + from_secs(expires_in)` must never overflow.
    assert_eq!(sanitize_expires_in(u64::MAX), OIDC_EXPIRES_IN_CAP_SECS);
}
