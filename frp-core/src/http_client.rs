//! Minimal HTTP client for OIDC and HTTP plugin operations.
//!
//! Uses hyper + hyper-rustls directly instead of reqwest to avoid pulling
//! the url / idna / ICU dependency stack (~1-2 MB embedded data in release
//! binaries). All call sites use simple GET/POST with full-body reads —
//! streaming, multipart, and cookies are not needed.
//!
//! Feature-gated behind `http-client` so `micro`/`tiny` builds can omit it.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::header::{CONTENT_TYPE, LOCATION};
use http::{HeaderMap, HeaderValue, Method, Request, StatusCode, Uri};
use http_body_util::{BodyExt, Full};
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use rustls::pki_types::CertificateDer;

/// Default timeout for OIDC HTTP requests (10 seconds).
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum number of redirect hops before giving up.
const MAX_REDIRECTS: usize = 10;

type HttpsClient = Client<HttpsConnector<HttpConnector>, Full<Bytes>>;

// ── TLS helpers ────────────────────────────────────────────────────────

/// TLS certificate verifier that accepts any certificate.
/// Used when `tls_insecure_skip_verify` is set (dev only).
#[derive(Debug)]
struct NoCertificateVerification;

impl rustls::client::danger::ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

fn build_tls_config(
    skip_verify: bool,
    ca_cert_pem: Option<&[u8]>,
) -> Result<rustls::ClientConfig, String> {
    if skip_verify {
        let config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
            .with_no_client_auth();
        return Ok(config);
    }

    let mut root_store = rustls::RootCertStore::empty();
    // Load webpki-roots (Mozilla CA store). ~150 embedded CA certs,
    // ~200 KB in release binaries — far less than the ICU data reqwest
    // pulled in via url → idna.
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    // If a custom CA cert was provided, add it (extends the store; does not
    // replace it — matching reqwest's add_root_certificate semantics).
    if let Some(pem) = ca_cert_pem {
        let certs = rustls_pemfile::certs(&mut std::io::Cursor::new(pem))
            .collect::<Result<Vec<CertificateDer<'_>>, _>>()
            .map_err(|e| format!("OIDC: failed to parse CA certificate PEM: {e}"))?;
        if certs.is_empty() {
            return Err("OIDC: no certificates found in CA certificate PEM — \
                 check the file format (expecting PEM-encoded X.509)"
                .into());
        }
        for cert in certs {
            root_store
                .add(cert)
                .map_err(|e| format!("OIDC: invalid CA certificate: {e}"))?;
        }
    }

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    Ok(config)
}

// ── HttpClient ──────────────────────────────────────────────────────────

/// A minimal HTTP client wrapping hyper with TLS support.
///
/// Provides just enough API for OIDC (GET + POST-form) and HTTP
/// plugin notification (POST-JSON). All requests use HTTP/1.1, full-body
/// reads, and follow up to 10 redirects.
pub struct HttpClient {
    inner: HttpsClient,
    timeout: Duration,
}

impl std::fmt::Debug for HttpClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpClient")
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl Clone for HttpClient {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            timeout: self.timeout,
        }
    }
}

/// Builder for [`HttpClient`].
pub struct HttpClientBuilder {
    timeout: Duration,
    skip_verify: bool,
    ca_cert_pem: Option<Vec<u8>>,
}

impl HttpClientBuilder {
    pub fn new() -> Self {
        Self {
            timeout: DEFAULT_TIMEOUT,
            skip_verify: false,
            ca_cert_pem: None,
        }
    }

    /// Set the per-request timeout. Applies to connect + send + body read
    /// (equivalent to reqwest's total-request deadline semantics).
    pub fn timeout(mut self, d: Duration) -> Self {
        self.timeout = d;
        self
    }

    /// Skip TLS certificate verification (dev only, insecure).
    pub fn tls_skip_verify(mut self, skip: bool) -> Self {
        self.skip_verify = skip;
        self
    }

    /// Add a custom CA certificate in PEM format.
    /// This extends the root store; webpki-roots built-in CAs are
    /// still trusted.
    pub fn tls_ca_cert_pem(mut self, pem: Option<Vec<u8>>) -> Self {
        self.ca_cert_pem = pem;
        self
    }

    /// Build the HTTP client.
    pub fn build(self) -> Result<HttpClient, String> {
        let tls_config = build_tls_config(self.skip_verify, self.ca_cert_pem.as_deref())?;

        let https_connector = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(tls_config)
            .https_or_http()
            .enable_http1()
            .build();

        let client: HttpsClient = Client::builder(TokioExecutor::new()).build(https_connector);

        Ok(HttpClient {
            inner: client,
            timeout: self.timeout,
        })
    }
}

impl Default for HttpClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ── Response ────────────────────────────────────────────────────────────

/// An HTTP response with status code and body bytes.
pub struct HttpResponse {
    status: StatusCode,
    body: Bytes,
}

impl HttpResponse {
    /// HTTP status code.
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// True for 2xx status codes.
    pub fn is_success(&self) -> bool {
        self.status.is_success()
    }

    /// Consume the response and return the body as a UTF-8 string.
    pub async fn text(self) -> Result<String, String> {
        String::from_utf8(self.body.to_vec())
            .map_err(|e| format!("response body is not valid UTF-8: {e}"))
    }
}

// ── Request methods ─────────────────────────────────────────────────────

impl HttpClient {
    /// Send a GET request and return the response.
    /// Follows up to `MAX_REDIRECTS` redirects.
    pub async fn get(&self, url: &str) -> Result<HttpResponse, String> {
        let uri: Uri = url
            .parse()
            .map_err(|e| format!("invalid URL '{url}': {e}"))?;
        self.request(Method::GET, uri, HeaderMap::new(), Full::new(Bytes::new()))
            .await
    }

    /// Send a POST request with `application/x-www-form-urlencoded` body.
    /// `params` is a slice of key-value pairs; they are manually url-encoded.
    pub async fn post_form(
        &self,
        url: &str,
        params: &[(&str, &str)],
    ) -> Result<HttpResponse, String> {
        let uri: Uri = url
            .parse()
            .map_err(|e| format!("invalid URL '{url}': {e}"))?;
        let body = urlencode(params);
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        );
        self.request(Method::POST, uri, headers, Full::new(Bytes::from(body)))
            .await
    }

    /// Send a POST request with a pre-serialized body and custom headers.
    /// Used by HTTP plugin notifications (JSON body + `X-Frp-Reqid` header).
    pub async fn post_with_headers(
        &self,
        url: &str,
        headers: HeaderMap,
        body: String,
    ) -> Result<HttpResponse, String> {
        let uri: Uri = url
            .parse()
            .map_err(|e| format!("invalid URL '{url}': {e}"))?;
        self.request(Method::POST, uri, headers, Full::new(Bytes::from(body)))
            .await
    }

    /// Low-level request with redirect following and timeout.
    ///
    /// The timeout covers the full request lifecycle: connect, send headers,
    /// body read, and redirects (matching reqwest's total-deadline semantics).
    /// A zero timeout disables the deadline entirely; the plugin path uses
    /// this and wraps the call in its own `tokio::time::timeout`.
    async fn request(
        &self,
        method: Method,
        uri: Uri,
        headers: HeaderMap,
        body: Full<Bytes>,
    ) -> Result<HttpResponse, String> {
        let deadline = self.timeout;

        // Wrap the entire request+redirect loop in a timeout so body reads
        // and redirect hops are covered, matching reqwest's total-deadline
        // semantics.
        let fut = self.request_inner(method, uri, headers, body);
        match deadline {
            d if d.is_zero() => fut.await,
            d => tokio::time::timeout(d, fut)
                .await
                .unwrap_or_else(|_| Err("HTTP request timed out".into())),
        }
    }

    /// Inner request loop — body reads and redirect hops are included in
    /// the caller's timeout.
    async fn request_inner(
        &self,
        method: Method,
        uri: Uri,
        headers: HeaderMap,
        body: Full<Bytes>,
    ) -> Result<HttpResponse, String> {
        let mut current_uri = uri;
        let mut current_method = method;
        let mut current_headers = headers;
        let mut current_body = body;

        for _hop in 0..=MAX_REDIRECTS {
            let mut req = Request::builder()
                .method(&current_method)
                .uri(&current_uri)
                .body(current_body)
                .map_err(|e| format!("failed to build request: {e}"))?;
            *req.headers_mut() = current_headers;

            let resp = self
                .inner
                .request(req)
                .await
                .map_err(|e| format!("HTTP request to {current_uri} failed: {e}"))?;

            if !is_redirect(resp.status()) {
                let status = resp.status();
                let body = resp
                    .collect()
                    .await
                    .map_err(|e| format!("failed to read response body: {e}"))?
                    .to_bytes();
                return Ok(HttpResponse { status, body });
            }

            // Follow redirect: read the Location header.
            let loc = resp
                .headers()
                .get(LOCATION)
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| format!("redirect without Location header at {current_uri}"))?
                .to_owned();

            // Drain the redirect response body before following.
            let _ = resp.collect().await;

            // Resolve relative Location against the current URI.
            current_uri = resolve_uri(&current_uri, &loc)?;

            // Switch to GET after any redirect. OIDC / plugin paths never
            // POST to endpoints that redirect, so preserving the POST body
            // across redirects is unnecessary. This also prevents credential
            // replay across hosts (security improvement over reqwest).
            current_method = Method::GET;
            current_headers = HeaderMap::new();
            current_body = Full::new(Bytes::new());
        }

        Err(format!(
            "too many redirects (max {MAX_REDIRECTS}) at {current_uri}"
        ))
    }
}

// ── Redirect helpers ────────────────────────────────────────────────────

/// Follow 301, 302, 303, 307, 308. Pass through 300, 304, 305, 306
/// (matching reqwest's redirect policy).
fn is_redirect(status: StatusCode) -> bool {
    matches!(status.as_u16(), 301 | 302 | 303 | 307 | 308)
}

/// Resolve a redirect `Location` against the current URI.
/// If `location` is absolute it is used directly; otherwise it is
/// resolved relative to `current` (base URI).
fn resolve_uri(current: &Uri, location: &str) -> Result<Uri, String> {
    // Try absolute first.
    if let Ok(uri) = location.parse::<Uri>() {
        if uri.scheme().is_some() {
            return Ok(uri);
        }
    }

    // Relative redirect — resolve against current.
    let scheme = current.scheme_str().unwrap_or("https");
    let authority = current
        .authority()
        .map(|a| a.as_str())
        .unwrap_or("localhost");

    // If location starts with '/', it's path-absolute; otherwise it's
    // relative to the current path.
    let resolved = if location.starts_with('/') {
        format!("{scheme}://{authority}{location}")
    } else {
        // Relative to current path: strip the last path segment.
        let base_path = current.path();
        let base_dir = match base_path.rfind('/') {
            Some(pos) => &base_path[..=pos],
            None => "/",
        };
        format!("{scheme}://{authority}{base_dir}{location}")
    };

    resolved
        .parse()
        .map_err(|e| format!("invalid redirect Location '{location}': {e}"))
}

// ── Helpers ─────────────────────────────────────────────────────────────

/// Manual `application/x-www-form-urlencoded` encoding.
/// Avoids pulling in `url` / `form_urlencoded` crates for a single call site
/// (OIDC `fetch_token` POST with 4-8 key-value pairs).
fn urlencode(params: &[(&str, &str)]) -> String {
    let mut out = String::with_capacity(256);
    for (i, (k, v)) in params.iter().enumerate() {
        if i > 0 {
            out.push('&');
        }
        percent_encode(k, &mut out);
        out.push('=');
        percent_encode(v, &mut out);
    }
    out
}

fn percent_encode(s: &str, out: &mut String) {
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push('%');
                out.push(HEX_CHARS[(b >> 4) as usize] as char);
                out.push(HEX_CHARS[(b & 0x0f) as usize] as char);
            }
        }
    }
}

const HEX_CHARS: &[u8; 16] = b"0123456789ABCDEF";

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urlencode_basic() {
        let params = &[
            ("grant_type", "client_credentials"),
            ("client_id", "my-client"),
            ("client_secret", "secret!@#"),
            ("scope", "openid profile"),
        ];
        let encoded = urlencode(params);
        assert!(encoded.contains("grant_type=client_credentials"));
        assert!(encoded.contains("client_id=my-client"));
        assert!(encoded.contains("client_secret=secret%21%40%23"));
        assert!(encoded.contains("scope=openid%20profile"));
    }

    #[test]
    fn urlencode_empty() {
        assert_eq!(urlencode(&[]), "");
    }

    #[test]
    fn urlencode_single() {
        let encoded = urlencode(&[("key", "value")]);
        assert_eq!(encoded, "key=value");
    }

    #[test]
    fn is_redirect_only_follows_301_302_303_307_308() {
        assert!(is_redirect(StatusCode::MOVED_PERMANENTLY)); // 301
        assert!(is_redirect(StatusCode::FOUND)); // 302
        assert!(is_redirect(StatusCode::SEE_OTHER)); // 303
        assert!(is_redirect(StatusCode::TEMPORARY_REDIRECT)); // 307
        assert!(is_redirect(StatusCode::PERMANENT_REDIRECT)); // 308
        assert!(!is_redirect(StatusCode::MULTIPLE_CHOICES)); // 300
        assert!(!is_redirect(StatusCode::NOT_MODIFIED)); // 304
        assert!(!is_redirect(StatusCode::USE_PROXY)); // 305
        assert!(!is_redirect(StatusCode::OK)); // 200
    }

    #[test]
    fn resolve_absolute_location() {
        let current: Uri = "https://example.com/.well-known/openid-configuration"
            .parse()
            .unwrap();
        let resolved = resolve_uri(&current, "https://other.example.com/jwks").unwrap();
        assert_eq!(resolved.scheme_str().unwrap(), "https");
        assert_eq!(resolved.authority().unwrap().as_str(), "other.example.com");
        assert_eq!(resolved.path(), "/jwks");
    }

    #[test]
    fn resolve_path_absolute_location() {
        let current: Uri = "https://example.com/.well-known/openid-configuration"
            .parse()
            .unwrap();
        let resolved = resolve_uri(&current, "/jwks").unwrap();
        assert_eq!(resolved.scheme_str().unwrap(), "https");
        assert_eq!(resolved.authority().unwrap().as_str(), "example.com");
        assert_eq!(resolved.path(), "/jwks");
    }

    #[test]
    fn resolve_path_relative_location() {
        let current: Uri = "https://example.com/.well-known/openid-configuration"
            .parse()
            .unwrap();
        let resolved = resolve_uri(&current, "jwks").unwrap();
        assert_eq!(resolved.scheme_str().unwrap(), "https");
        assert_eq!(resolved.authority().unwrap().as_str(), "example.com");
        assert_eq!(resolved.path(), "/.well-known/jwks");
    }
}
