//! In-tree JWT/JWS verification for OIDC.
//!
//! Replaces the `jsonwebtoken` crate for the one job the server needs: verify a
//! compact JWS signed by an IdP and validate its registered claims. The
//! algorithm surface is the same 12-name allowlist `jsonwebtoken` 9.x accepted
//! (HS/RS/PS/ES/EdDSA); the key material comes from the JWKS in the same four
//! `kty` shapes (`RSA`, `EC`, `oct`, `OKP`/Ed25519).
//!
//! The error surface deliberately mirrors `jsonwebtoken`'s: the variant names
//! are its `ErrorKind` names (`ExpiredSignature`, `ImmatureSignature`,
//! `InvalidIssuer`, `InvalidAudience`, `InvalidSignature`, …), JSON failures
//! print as `JSON error: …`, and an unknown `alg` fails during header
//! deserialization with serde's `unknown variant` text. Existing OIDC tests and
//! operator-facing messages keep their shape.
//!
//! Why hand-rolled: `jsonwebtoken` 11 has no `ring` backend (the banned
//! `aws-lc-rs` is the alternative), so staying on 9.3.1 kept an unmaintained
//! dependency line alive. Verification on `ring` is small: HMAC, RSA
//! PKCS#1/PSS from raw `(n, e)`, ECDSA P-256/P-384, and Ed25519 — all
//! primitives `ring` already provides.

use serde::de::DeserializeOwned;
use serde::Deserialize;
use std::collections::HashSet;

use ring::signature;

/// JWS algorithms accepted by the OIDC verifier. Variant names are the exact
/// JOSE `alg` strings; serde rejects anything else during header decode.
#[allow(non_camel_case_types, clippy::upper_case_acronyms)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub(crate) enum Algorithm {
    HS256,
    HS384,
    HS512,
    ES256,
    ES384,
    RS256,
    RS384,
    RS512,
    PS256,
    PS384,
    PS512,
    EdDSA,
}

#[derive(Debug, PartialEq, Eq)]
enum AlgorithmFamily {
    Hmac,
    Rsa,
    Ec,
    Ed,
}

impl Algorithm {
    fn family(self) -> AlgorithmFamily {
        match self {
            Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => AlgorithmFamily::Hmac,
            Algorithm::RS256
            | Algorithm::RS384
            | Algorithm::RS512
            | Algorithm::PS256
            | Algorithm::PS384
            | Algorithm::PS512 => AlgorithmFamily::Rsa,
            Algorithm::ES256 | Algorithm::ES384 => AlgorithmFamily::Ec,
            Algorithm::EdDSA => AlgorithmFamily::Ed,
        }
    }
}

/// Decoded JWS header. Fields other than `alg`/`kid` are ignored, as OIDC
/// providers routinely add `typ`, `cty`, `x5c`, … .
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct Header {
    pub alg: Algorithm,
    #[serde(default)]
    pub kid: Option<String>,
}

/// A verification key. Mirrors the four JWK shapes the verifier accepts.
#[derive(Clone)]
pub(crate) enum Key {
    /// HMAC secret (`oct`).
    Hmac(Vec<u8>),
    /// RSA modulus/exponent (`RSA`); ring verifies from the raw components, so
    /// no DER re-encoding is needed.
    Rsa { n: Vec<u8>, e: Vec<u8> },
    /// Uncompressed SEC1 point `0x04 || x || y` (`EC`).
    Ec(Vec<u8>),
    /// Ed25519 public key (`OKP`, `crv = Ed25519`).
    Ed(Vec<u8>),
}

impl Key {
    fn family(&self) -> AlgorithmFamily {
        match self {
            Key::Hmac(_) => AlgorithmFamily::Hmac,
            Key::Rsa { .. } => AlgorithmFamily::Rsa,
            Key::Ec(_) => AlgorithmFamily::Ec,
            Key::Ed(_) => AlgorithmFamily::Ed,
        }
    }

    /// HMAC key from a raw secret. Used by tests; JWKS `oct` keys go through
    /// [`Key::from_base64_secret`] to keep `jsonwebtoken`'s standard-base64
    /// acceptance rule.
    #[cfg(test)]
    pub(crate) fn from_secret(secret: &[u8]) -> Self {
        Key::Hmac(secret.to_vec())
    }

    /// `jsonwebtoken::DecodingKey::from_base64_secret`: the `oct` JWK `k` is
    /// **standard** base64 (with padding), not JOSE base64url.
    pub(crate) fn from_base64_secret(secret: &str) -> Result<Self, String> {
        let bytes =
            crate::base64::decode(secret).map_err(|e| format!("OIDC: invalid oct JWK: {e}"))?;
        Ok(Key::Hmac(bytes))
    }

    pub(crate) fn from_rsa_components(modulus: &str, exponent: &str) -> Result<Self, String> {
        let n = base64url_decode(modulus).map_err(|e| format!("OIDC: invalid RSA JWK: {e}"))?;
        let e = base64url_decode(exponent).map_err(|e| format!("OIDC: invalid RSA JWK: {e}"))?;
        Ok(Key::Rsa { n, e })
    }

    pub(crate) fn from_ec_components(x: &str, y: &str) -> Result<Self, String> {
        let x = base64url_decode(x).map_err(|e| format!("OIDC: invalid EC JWK: {e}"))?;
        let y = base64url_decode(y).map_err(|e| format!("OIDC: invalid EC JWK: {e}"))?;
        let mut point = Vec::with_capacity(1 + x.len() + y.len());
        point.push(0x04);
        point.extend_from_slice(&x);
        point.extend_from_slice(&y);
        Ok(Key::Ec(point))
    }

    pub(crate) fn from_ed_components(x: &str) -> Result<Self, String> {
        let bytes =
            base64url_decode(x).map_err(|e| format!("OIDC: invalid OKP/Ed25519 JWK: {e}"))?;
        Ok(Key::Ed(bytes))
    }
}

/// Validation rules applied after the signature verifies. Field names and
/// defaults match `jsonwebtoken::Validation` for the subset OIDC uses.
pub(crate) struct Validation {
    pub required_spec_claims: HashSet<String>,
    pub validate_exp: bool,
    pub validate_nbf: bool,
    pub validate_aud: bool,
    pub leeway: u64,
    iss: Option<HashSet<String>>,
    aud: Option<HashSet<String>>,
    algorithms: Vec<Algorithm>,
}

impl Validation {
    pub(crate) fn new(alg: Algorithm) -> Self {
        let mut required_spec_claims = HashSet::with_capacity(1);
        required_spec_claims.insert("exp".to_string());
        Self {
            required_spec_claims,
            validate_exp: true,
            validate_nbf: false,
            validate_aud: true,
            leeway: 60,
            iss: None,
            aud: None,
            algorithms: vec![alg],
        }
    }

    pub(crate) fn set_issuer(&mut self, issuers: &[&str]) {
        self.iss = Some(issuers.iter().map(|s| s.to_string()).collect());
    }

    pub(crate) fn set_audience(&mut self, audiences: &[&str]) {
        self.aud = Some(audiences.iter().map(|s| s.to_string()).collect());
    }
}

/// Successful decode result; same shape as `jsonwebtoken::TokenData`.
#[derive(Debug)]
pub(crate) struct TokenData<T> {
    #[allow(dead_code)] // read by tests; the server only consumes `claims`
    pub header: Header,
    pub claims: T,
}

#[derive(Debug)]
pub(crate) struct Error {
    kind: ErrorKind,
}

#[derive(Debug)]
pub(crate) enum ErrorKind {
    InvalidToken,
    InvalidSignature,
    InvalidAlgorithm,
    InvalidKeyFormat,
    MissingRequiredClaim(String),
    ExpiredSignature,
    ImmatureSignature,
    InvalidIssuer,
    InvalidAudience,
    /// Base64/decoding failure. `jsonwebtoken` stores a `base64::DecodeError`
    /// here; this in-tree decoder only produces text.
    Base64(String),
    Json(serde_json::Error),
}

impl Error {
    fn new(kind: ErrorKind) -> Self {
        Self { kind }
    }

    pub(crate) fn kind(&self) -> &ErrorKind {
        &self.kind
    }

    fn invalid_signature() -> Self {
        Self::new(ErrorKind::InvalidSignature)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.kind {
            ErrorKind::MissingRequiredClaim(claim) => {
                write!(f, "Missing required claim: {claim}")
            }
            ErrorKind::Json(err) => write!(f, "JSON error: {err}"),
            ErrorKind::Base64(msg) => write!(f, "Base64 error: {msg}"),
            other => write!(f, "{other:?}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Self {
        Self::new(kind)
    }
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Self::new(ErrorKind::Json(err))
    }
}

/// Whether a verification failure could be fixed by refreshed JWKS key
/// material (signature/key-family errors) rather than a semantic token problem
/// (expired, wrong issuer/audience, missing claim).
pub(crate) fn is_key_related_error(err: &Error) -> bool {
    matches!(
        err.kind(),
        ErrorKind::InvalidSignature | ErrorKind::InvalidKeyFormat | ErrorKind::InvalidAlgorithm
    )
}

/// Decode the JOSE header segment alone. Mirrors `jsonwebtoken::decode_header`:
/// an unknown `alg` string fails here, before any key or payload is touched.
pub(crate) fn decode_header(token: &str) -> Result<Header, Error> {
    let header_b64 = token
        .split('.')
        .next()
        .ok_or_else(|| Error::new(ErrorKind::InvalidToken))?;
    let bytes = base64url_decode(header_b64).map_err(ErrorKind::Base64)?;
    Ok(serde_json::from_slice(&bytes)?)
}

/// Decode and verify a compact JWS.
pub(crate) fn decode<T: DeserializeOwned>(
    token: &str,
    key: &Key,
    validation: &Validation,
) -> Result<TokenData<T>, Error> {
    let mut parts = token.split('.');
    let header_b64 = parts
        .next()
        .ok_or_else(|| Error::new(ErrorKind::InvalidToken))?;
    let payload_b64 = parts
        .next()
        .ok_or_else(|| Error::new(ErrorKind::InvalidToken))?;
    let signature_b64 = parts
        .next()
        .ok_or_else(|| Error::new(ErrorKind::InvalidToken))?;
    if parts.next().is_some() {
        return Err(Error::new(ErrorKind::InvalidToken));
    }

    let header_bytes = base64url_decode(header_b64).map_err(ErrorKind::Base64)?;
    let header: Header = serde_json::from_slice(&header_bytes)?;
    if !validation.algorithms.contains(&header.alg) {
        return Err(Error::new(ErrorKind::InvalidAlgorithm));
    }
    if key.family() != header.alg.family() {
        return Err(Error::new(ErrorKind::InvalidAlgorithm));
    }

    let signature = base64url_decode(signature_b64).map_err(ErrorKind::Base64)?;
    let signing_input_len = header_b64.len() + 1 + payload_b64.len();
    let signing_input: &[u8] = &token.as_bytes()[..signing_input_len];
    verify_signature(header.alg, key, signing_input, &signature)?;

    let payload_bytes = base64url_decode(payload_b64).map_err(ErrorKind::Base64)?;
    let claims_value: serde_json::Value = serde_json::from_slice(&payload_bytes)?;
    validate_claims(&claims_value, validation)?;
    let claims = serde_json::from_value(claims_value)?;
    Ok(TokenData { header, claims })
}

fn verify_signature(
    alg: Algorithm,
    key: &Key,
    message: &[u8],
    signature: &[u8],
) -> Result<(), Error> {
    use ring::hmac;

    match (alg, key) {
        (Algorithm::HS256, Key::Hmac(secret)) => {
            let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
            hmac::verify(&key, message, signature).map_err(|_| Error::invalid_signature())
        }
        (Algorithm::HS384, Key::Hmac(secret)) => {
            let key = hmac::Key::new(hmac::HMAC_SHA384, secret);
            hmac::verify(&key, message, signature).map_err(|_| Error::invalid_signature())
        }
        (Algorithm::HS512, Key::Hmac(secret)) => {
            let key = hmac::Key::new(hmac::HMAC_SHA512, secret);
            hmac::verify(&key, message, signature).map_err(|_| Error::invalid_signature())
        }
        (
            Algorithm::RS256
            | Algorithm::RS384
            | Algorithm::RS512
            | Algorithm::PS256
            | Algorithm::PS384
            | Algorithm::PS512,
            Key::Rsa { n, e },
        ) => {
            let params = rsa_parameters(alg);
            let components = signature::RsaPublicKeyComponents { n, e };
            components
                .verify(params, message, signature)
                .map_err(|_| Error::invalid_signature())
        }
        (Algorithm::ES256, Key::Ec(point)) => {
            let point = ecdsa_point(point, 32)?;
            signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, point)
                .verify(message, signature)
                .map_err(|_| Error::invalid_signature())
        }
        (Algorithm::ES384, Key::Ec(point)) => {
            let point = ecdsa_point(point, 48)?;
            signature::UnparsedPublicKey::new(&signature::ECDSA_P384_SHA384_FIXED, point)
                .verify(message, signature)
                .map_err(|_| Error::invalid_signature())
        }
        (Algorithm::EdDSA, Key::Ed(public_key)) => {
            if public_key.len() != 32 {
                return Err(Error::new(ErrorKind::InvalidKeyFormat));
            }
            signature::UnparsedPublicKey::new(&signature::ED25519, public_key)
                .verify(message, signature)
                .map_err(|_| Error::invalid_signature())
        }
        _ => Err(Error::new(ErrorKind::InvalidAlgorithm)),
    }
}

fn rsa_parameters(alg: Algorithm) -> &'static signature::RsaParameters {
    match alg {
        Algorithm::RS256 => &signature::RSA_PKCS1_2048_8192_SHA256,
        Algorithm::RS384 => &signature::RSA_PKCS1_2048_8192_SHA384,
        Algorithm::RS512 => &signature::RSA_PKCS1_2048_8192_SHA512,
        Algorithm::PS256 => &signature::RSA_PSS_2048_8192_SHA256,
        Algorithm::PS384 => &signature::RSA_PSS_2048_8192_SHA384,
        Algorithm::PS512 => &signature::RSA_PSS_2048_8192_SHA512,
        _ => unreachable!("rsa_parameters called for a non-RSA algorithm"),
    }
}

/// Validate that `point` is `0x04 || x || y` with the curve's coordinate size.
/// A mismatched JWK (e.g. a P-384 point with an `ES256` header) is a key
/// problem, not a signature mismatch.
fn ecdsa_point(point: &[u8], coordinate_len: usize) -> Result<&[u8], Error> {
    if point.len() != 1 + 2 * coordinate_len || point.first() != Some(&0x04) {
        return Err(Error::new(ErrorKind::InvalidKeyFormat));
    }
    Ok(point)
}

fn validate_claims(claims: &serde_json::Value, validation: &Validation) -> Result<(), Error> {
    let exp = claims.get("exp").and_then(serde_json::Value::as_u64);
    let nbf = claims.get("nbf").and_then(serde_json::Value::as_u64);
    let sub = claims.get("sub").and_then(serde_json::Value::as_str);
    let iss = claims.get("iss").and_then(string_or_string_array);
    let aud = claims.get("aud").and_then(string_or_string_array);

    for required in &validation.required_spec_claims {
        let present = match required.as_str() {
            "exp" => exp.is_some(),
            "nbf" => nbf.is_some(),
            "sub" => sub.is_some(),
            "iss" => iss.is_some(),
            "aud" => aud.is_some(),
            // jsonwebtoken ignores anything outside the five registered names.
            _ => continue,
        };
        if !present {
            return Err(Error::new(ErrorKind::MissingRequiredClaim(
                required.clone(),
            )));
        }
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if validation.validate_exp {
        if let Some(exp) = exp {
            if i128::from(exp) < i128::from(now) - i128::from(validation.leeway) {
                return Err(Error::new(ErrorKind::ExpiredSignature));
            }
        }
    }
    if validation.validate_nbf {
        if let Some(nbf) = nbf {
            if i128::from(nbf) > i128::from(now) + i128::from(validation.leeway) {
                return Err(Error::new(ErrorKind::ImmatureSignature));
            }
        }
    }

    if let (Some(iss), Some(expected)) = (iss, validation.iss.as_ref()) {
        if !iss.iter().any(|candidate| expected.contains(*candidate)) {
            return Err(Error::new(ErrorKind::InvalidIssuer));
        }
    }

    if !validation.validate_aud {
        return Ok(());
    }
    match (aud, validation.aud.as_ref()) {
        // A token with an audience but no configured expectation: no principal
        // can claim it, so reject (jsonwebtoken's `(Parsed, None)` arm).
        (Some(_), None) => Err(Error::new(ErrorKind::InvalidAudience)),
        (Some(aud), Some(expected)) => {
            if !aud.iter().any(|candidate| expected.contains(*candidate)) {
                Err(Error::new(ErrorKind::InvalidAudience))
            } else {
                Ok(())
            }
        }
        // No `aud` claim: jsonwebtoken only enforces presence via
        // `required_spec_claims`, which this verifier does not set.
        (None, _) => Ok(()),
    }
}

fn string_or_string_array(value: &serde_json::Value) -> Option<Vec<&str>> {
    if let Some(s) = value.as_str() {
        return Some(vec![s]);
    }
    let array = value.as_array()?;
    array.iter().map(serde_json::Value::as_str).collect()
}

/// Decode a base64url segment (RFC 4648 §5, URL-safe alphabet, padding
/// optional — JWT payloads are emitted unpadded). Rejects non-zero trailing
/// bits per RFC 4648 §3.2.
pub(crate) fn base64url_decode(input: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(input.len() / 4 * 3);
    let mut acc: u32 = 0;
    let mut nbits: u32 = 0;
    for c in input.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' | b'+' => 62,
            b'_' | b'/' => 63,
            _ => return Err(format!("OIDC: invalid base64url char {c:#x}")),
        };
        acc = (acc << 6) | v as u32;
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            out.push((acc >> nbits) as u8);
        }
    }
    if nbits != 0 && (acc & ((1u32 << nbits) - 1)) != 0 {
        return Err("OIDC: invalid base64url trailing bits".to_string());
    }
    Ok(out)
}

/// URL-safe base64 without padding (JWT segment form). The inline
/// `frp_core::base64` module is standard-alphabet with padding; the two
/// alphabets differ only in chars 62/63 and padding is dropped.
#[cfg(test)]
pub(crate) fn base64url_encode(data: &[u8]) -> String {
    crate::base64::encode(data)
        .replace('+', "-")
        .replace('/', "_")
        .trim_end_matches('=')
        .to_string()
}

/// Sign an HS256 token with the given claims. Test-only fixture for the OIDC
/// tests; the server never signs tokens.
#[cfg(test)]
pub(crate) fn test_sign_hs256(
    kid: Option<&str>,
    secret: &[u8],
    claims: &serde_json::Value,
) -> String {
    let header = match kid {
        Some(kid) => serde_json::json!({"alg": "HS256", "kid": kid}),
        None => serde_json::json!({"alg": "HS256"}),
    };
    let header = base64url_encode(&serde_json::to_vec(&header).expect("header JSON"));
    let payload = base64url_encode(&serde_json::to_vec(claims).expect("claims JSON"));
    let signing_input = format!("{header}.{payload}");
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret);
    let signature = ring::hmac::sign(&key, signing_input.as_bytes());
    format!("{signing_input}.{}", base64url_encode(signature.as_ref()))
}

/// Test-only shim exposing the small slice of `jsonwebtoken`'s API the OIDC
/// tests use: an HS256 signer plus the decode/validation types. Production code
/// never signs a token, so none of this ships in a release build.
#[cfg(test)]
pub(crate) mod test_compat {
    use super::*;

    pub(crate) use super::{decode, Algorithm, Key as DecodingKey, Validation};

    pub struct EncodingKey(Vec<u8>);

    impl EncodingKey {
        pub fn from_secret(secret: &[u8]) -> Self {
            Self(secret.to_vec())
        }
    }

    pub struct Header {
        pub alg: Algorithm,
        pub kid: Option<String>,
    }

    impl Default for Header {
        fn default() -> Self {
            Self {
                alg: Algorithm::HS256,
                kid: None,
            }
        }
    }

    impl Header {
        pub fn new(alg: Algorithm) -> Self {
            Self { alg, kid: None }
        }
    }

    pub fn encode<T: serde::Serialize>(
        header: &Header,
        claims: &T,
        key: &EncodingKey,
    ) -> Result<String, Error> {
        if header.alg != Algorithm::HS256 {
            return Err(Error::new(ErrorKind::InvalidAlgorithm));
        }
        let header = serde_json::json!({"alg": "HS256", "kid": header.kid});
        let header = base64url_encode(&serde_json::to_vec(&header)?);
        let payload = base64url_encode(&serde_json::to_vec(claims)?);
        let signing_input = format!("{header}.{payload}");
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &key.0);
        let signature = ring::hmac::sign(&key, signing_input.as_bytes());
        Ok(format!(
            "{signing_input}.{}",
            base64url_encode(signature.as_ref())
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::KeyPair;

    fn claims(exp: i64) -> serde_json::Value {
        serde_json::json!({"sub": "alice", "exp": exp})
    }

    #[test]
    fn hs256_roundtrip_and_claim_validation() {
        let secret = b"oidc-jwks-hs256-secret";
        let future = 4_102_444_800_u64;
        let token = test_sign_hs256(Some("k1"), secret, &claims(future as i64));
        let mut validation = Validation::new(Algorithm::HS256);
        validation.required_spec_claims.insert("sub".into());
        let key = Key::from_secret(secret);
        let data: TokenData<serde_json::Value> =
            decode(&token, &key, &validation).expect("valid HS256 token");
        assert_eq!(data.header.kid.as_deref(), Some("k1"));
        assert_eq!(data.claims["sub"], "alice");
        assert_eq!(data.claims["exp"], future);

        let wrong = Key::from_secret(b"wrong");
        let err = decode::<serde_json::Value>(&token, &wrong, &validation)
            .expect_err("wrong key must fail");
        assert!(is_key_related_error(&err), "{err}");
        assert_eq!(err.to_string(), "InvalidSignature");
    }

    #[test]
    fn expired_and_immature_follow_the_leeway() {
        let secret = b"s";
        let key = Key::from_secret(secret);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let mut validation = Validation::new(Algorithm::HS256);
        validation.required_spec_claims.insert("sub".into());

        let expired = test_sign_hs256(None, secret, &claims(now - 3_600));
        let err = decode::<serde_json::Value>(&expired, &key, &validation).unwrap_err();
        assert_eq!(err.to_string(), "ExpiredSignature");
        assert!(!is_key_related_error(&err));

        // Within the 60 s leeway, still accepted.
        let recent = test_sign_hs256(None, secret, &claims(now - 30));
        decode::<serde_json::Value>(&recent, &key, &validation).expect("inside leeway");

        let mut with_nbf = claims(now + 3_600);
        with_nbf["nbf"] = serde_json::json!(now + 3_600);
        let immature = test_sign_hs256(None, secret, &with_nbf);
        validation.validate_nbf = true;
        let err = decode::<serde_json::Value>(&immature, &key, &validation).unwrap_err();
        assert_eq!(err.to_string(), "ImmatureSignature");
    }

    #[test]
    fn issuer_audience_and_required_claim_are_enforced() {
        let secret = b"s";
        let key = Key::from_secret(secret);
        let future = 4_102_444_800_u64;
        let mut validation = Validation::new(Algorithm::HS256);
        validation.required_spec_claims.insert("sub".into());
        validation.set_issuer(&["https://issuer.example"]);
        validation.set_audience(&["api-prod"]);

        let good = test_sign_hs256(
            None,
            secret,
            &serde_json::json!({
                "sub": "alice",
                "exp": future,
                "iss": "https://issuer.example",
                "aud": ["other", "api-prod"],
            }),
        );
        decode::<serde_json::Value>(&good, &key, &validation).expect("valid claims");

        let bad_iss = test_sign_hs256(
            None,
            secret,
            &serde_json::json!({
                "sub": "alice", "exp": future,
                "iss": "https://evil.example", "aud": "api-prod",
            }),
        );
        let err = decode::<serde_json::Value>(&bad_iss, &key, &validation).unwrap_err();
        assert_eq!(err.to_string(), "InvalidIssuer");

        let bad_aud = test_sign_hs256(
            None,
            secret,
            &serde_json::json!({
                "sub": "alice", "exp": future,
                "iss": "https://issuer.example", "aud": "other",
            }),
        );
        let err = decode::<serde_json::Value>(&bad_aud, &key, &validation).unwrap_err();
        assert_eq!(err.to_string(), "InvalidAudience");

        let no_sub = test_sign_hs256(
            None,
            secret,
            &serde_json::json!({
                "exp": future, "iss": "https://issuer.example", "aud": "api-prod",
            }),
        );
        let err = decode::<serde_json::Value>(&no_sub, &key, &validation).unwrap_err();
        assert!(matches!(err.kind(), ErrorKind::MissingRequiredClaim(c) if c == "sub"));
    }

    #[test]
    fn unknown_algorithm_fails_during_header_decode() {
        let secret = b"s";
        let key = Key::from_secret(secret);
        let header = base64url_encode(br#"{"alg":"none","kid":"k1"}"#);
        let payload = base64url_encode(br#"{"sub":"alice","exp":4102444800}"#);
        let token = format!("{header}.{payload}.{}", base64url_encode(b"sig"));
        let validation = Validation::new(Algorithm::HS256);
        let err = decode::<serde_json::Value>(&token, &key, &validation).unwrap_err();
        let text = err.to_string();
        assert!(
            text.starts_with(
                "JSON error: unknown variant `none`, expected one of `HS256`, `HS384`, `HS512`, \
                 `ES256`, `ES384`, `RS256`, `RS384`, `RS512`, `PS256`, `PS384`, `PS512`, `EdDSA`"
            ),
            "{text}"
        );
    }

    #[test]
    fn rs256_and_ps256_verify_static_vectors() {
        // Generated once with OpenSSL 4.1.0: a 2048-bit RSA key, the JOSE
        // header/payload below, and one PKCS#1-v1.5 (RS256) plus one PSS
        // (PS256, salt = digest length) signature. Static so the test needs
        // no signing dependency.
        const N: &str = "rrVOVI4qODpvIJMU8UyE84-l0v61s1CdIJWavn4FG04ahIwGsk2OvF3aOSBMy8A_CMqqzg08hSmg_CxF6NeLBczcAa30s1KY0I26NaKR-s44J0PedrgHPwPawZBnWsU7jsHjZ3r-FXCyHG_GcID1RHWN0kALeQkag_jf3dOtCNh4eN52xN0icq_M5XvPEKBqWV602Zd1PalLUPJvaHCmd3qZEoYG4y3CvupA1ZcbQzWJwUyfNuzfCb3J2QSwVcQaZJL8s3WVp4ar9w_Z02Ursy5_686sQF4GjaLesovHnh_D3REyI8_NylWwuUI4WOJyoy7oAiGYI6aUVdp1T4XnnQ";
        const E: &str = "AQAB";
        // {"alg":"RS256","kid":"k1"}.{"sub":"alice","exp":4102444800}.<sig>
        const RS256: &str = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImsxIn0.eyJzdWIiOiJhbGljZSIsImV4cCI6NDEwMjQ0NDgwMH0.XPCMTstpjMXM8Bc1jr95YAd0WLdmQfsEv-TVd-W0lJ9s4_pGKPJwIL_6Wy75fm1b8va4hqUt5RdKgDbRWprWBqBLoHTf8nszRMbZUApJVEOIed25Sg-_8x-77CFYpTTHbpEcZ3dByMxBQWwKEgDuIy7m4v2Ku6KtWpepLUYJFGw0mXw8l7ZDbdLawHCR3DQJMGKEqdeX9agCP5UepFW2HTTVI7-S6vV-XkS_tGe1awu3o_wJmunKH6mTwZ-RP-j7DpXfRqhWTXjM22feOCkNSBjYH9JdZupMwIG96gIrfH4RYWLzkYiMKCJZEu5NgIGnDQbiIazEw1vX7IrQxqaWBw";
        // Same header with alg=PS256 and a PSS signature over the same input.
        const PS256: &str = "eyJhbGciOiJQUzI1NiIsImtpZCI6ImsxIn0.eyJzdWIiOiJhbGljZSIsImV4cCI6NDEwMjQ0NDgwMH0.HeP9KPqh0ttR8UQhQ5o3CMBYde_qZt_1C730GdM_HrWYaM8I5LHTfzMQBFuyKSzothY0NieX66ERtxKc2H9qQ4XPJRkW8pVmZe-TWf51qPZ-1cAGpSR3vjTarrZUhXqFi2NZw-xjU1NolnqS3naSYMe1-tXerg-Bf1tZbSWKBJvcH-vPDBrTTCH7fvxw5jrz5ins3pCnKO2pJUbSKO2x6Yj4P6qPhdkP1RRPc7Semc4GJW8u-pUyk76ilw7sEW54nN59nxAJWITqTp3g7lng1X1LbZNF8bSulNNvPCsXfX0v-4qYKNmwmcQFXCLtuETbnaj8aB_uXyQ-MDEF0wXJ7A";
        let key = Key::from_rsa_components(N, E).expect("RSA JWK");
        let mut validation = Validation::new(Algorithm::RS256);
        validation.required_spec_claims.insert("sub".into());
        let data: TokenData<serde_json::Value> =
            decode(RS256, &key, &validation).expect("RS256 vector");
        assert_eq!(data.claims["sub"], "alice");

        let mut validation = Validation::new(Algorithm::PS256);
        validation.required_spec_claims.insert("sub".into());
        decode::<serde_json::Value>(PS256, &key, &validation).expect("PS256 vector");

        // Flip the last signature byte: verification must fail as a key error.
        let mut tampered = RS256.to_string();
        let last = tampered.pop().unwrap();
        tampered.push(if last == 'A' { 'B' } else { 'A' });
        let err = decode::<serde_json::Value>(&tampered, &key, &validation)
            .expect_err("tampered signature must fail");
        assert!(is_key_related_error(&err), "{err}");
    }

    #[test]
    fn base64url_decode_vectors() {
        assert_eq!(base64url_decode("").unwrap(), b"");
        assert_eq!(base64url_decode("Zg").unwrap(), b"f");
        assert_eq!(base64url_decode("Zm8").unwrap(), b"fo");
        assert_eq!(base64url_decode("Zm9v").unwrap(), b"foo");
        assert_eq!(base64url_decode("aGVsbG8").unwrap(), b"hello");
        assert_eq!(base64url_decode("_w").unwrap(), b"\xff");
        assert_eq!(base64url_decode("-_w").unwrap(), b"\xfb\xfc");
        assert!(base64url_decode("ab=c").is_err());
        assert!(base64url_decode("Zh").is_err());
    }

    #[test]
    fn ec_and_eddsa_verify_with_ring_generated_keys() {
        // EC P-256.
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = ring::signature::EcdsaKeyPair::generate_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            &rng,
        )
        .expect("generate P-256 key");
        let pair = ring::signature::EcdsaKeyPair::from_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            pkcs8.as_ref(),
            &rng,
        )
        .expect("load P-256 key");
        let point = pair.public_key().as_ref();
        let mut key = Key::Ec(point.to_vec());
        let message = b"header.payload";
        let signed = pair.sign(&rng, message).expect("sign P-256");
        let mut sig = signed.as_ref().to_vec();
        assert!(verify_signature(Algorithm::ES256, &key, message, &sig).is_ok());
        sig[0] ^= 1;
        assert!(verify_signature(Algorithm::ES256, &key, message, &sig).is_err());

        // A P-256 point with an ES384 header is a key-format failure.
        assert!(matches!(
            verify_signature(Algorithm::ES384, &key, message, &sig),
            Err(Error {
                kind: ErrorKind::InvalidKeyFormat
            })
        ));

        // Ed25519.
        let ed_pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).expect("generate Ed");
        let ed = ring::signature::Ed25519KeyPair::from_pkcs8(ed_pkcs8.as_ref()).expect("load Ed");
        let ed_key = Key::Ed(ed.public_key().as_ref().to_vec());
        let ed_sig = ed.sign(message);
        assert!(verify_signature(Algorithm::EdDSA, &ed_key, message, ed_sig.as_ref()).is_ok());
        let mut bad = ed_sig.as_ref().to_vec();
        bad[0] ^= 1;
        assert!(verify_signature(Algorithm::EdDSA, &ed_key, message, &bad).is_err());

        key = Key::Ec(vec![0x04; 64]);
        assert!(verify_signature(Algorithm::ES256, &key, message, &sig).is_err());
    }
}
