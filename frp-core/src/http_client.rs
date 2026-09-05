//! Minimal HTTP client for OIDC and HTTP plugin operations.
//!
//! Uses hyper + tokio-rustls (a custom connector) instead of reqwest to avoid
//! pulling the url / idna / ICU dependency stack (~1-2 MB embedded data in
//! release binaries). All call sites use simple GET/POST with full-body reads
//! — streaming, multipart, and cookies are not needed.
//!
//! Feature-gated behind `http-client` so `micro`/`tiny` builds can omit it.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::header::{CONTENT_TYPE, LOCATION};
use http::{HeaderMap, HeaderValue, Method, Request, StatusCode, Uri};
use http_body_util::{BodyExt, Full, Limited};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use rustls::pki_types::CertificateDer;

/// Default timeout for OIDC HTTP requests (10 seconds).
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum number of redirect hops before giving up.
const MAX_REDIRECTS: usize = 10;

/// Upper bound on a single HTTP response body read by `http_client`
/// (OIDC discovery/JWKS, plugin backends, proxyURL JWT fetch). Prevents an
/// unbounded `collect()` from streaming arbitrary data into memory (OOM
/// under panic=abort). 1 MiB far exceeds any legitimate payload.
// Response body cap for http_client's OIDC/plugin/proxyURL endpoints. Go frp
// reads these with an unbounded `ioutil.ReadAll`; frp-rs bounds them so a
// hostile endpoint cannot stream arbitrary data into memory (OOM under
// panic=abort kills the whole process). 16 MiB is deliberately generous —
// multi-tenant OIDC JWKS documents can exceed 1 MiB, and the fail-closed
// error must not break real logins (round-17 review LOW: the original 1 MiB
// diverged from Go for large JWKS / plugin responses). Still far under any
// memory limit, so the OOM bound is intact.
const MAX_RESPONSE_BODY_SIZE: usize = 16 * 1024 * 1024;

type HttpsClient = Client<HttpConnect, Full<Bytes>>;

// ── Connector: direct or via HTTP CONNECT / SOCKS5 proxy ─────────────────

/// A tunneled stream: plain TCP (http target or http-proxy CONNECT) or
/// TLS-wrapped (https target). `IoStream` is the transport crate's
/// type-erased AsyncRead+AsyncWrite stream.
enum TunnelStream {
    Plain(crate::transport::IoStream),
    Tls(Box<dyn crate::transport::AsyncReadWrite>),
}

impl tokio::io::AsyncRead for TunnelStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            TunnelStream::Plain(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            TunnelStream::Tls(s) => std::pin::Pin::new(&mut **s).poll_read(cx, buf),
        }
    }
}

// hyper's runtime IO trait (used by hyper-util's legacy connect::Connect).
// The ReadBufCursor → tokio ReadBuf bridge mirrors hyper-util's own
// TokioIo implementation.
impl hyper::rt::Read for TunnelStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        mut buf: hyper::rt::ReadBufCursor<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        let n = unsafe {
            let mut tbuf = tokio::io::ReadBuf::uninit(buf.as_mut());
            // SAFETY: hyper's ReadBufCursor exposes the same
            // init/unfilled-region semantics as tokio's ReadBuf; this is
            // exactly the bridge hyper-util's TokioIo performs.
            std::task::ready!(tokio::io::AsyncRead::poll_read(self, cx, &mut tbuf))?;
            tbuf.filled().len()
        };
        // SAFETY: `advance(n)` is safe because exactly `n` bytes were filled
        // by the poll_read above (n ≤ the unfilled capacity we exposed via
        // `buf.as_mut()`); ReadBufCursor permits advancing within the
        // initialized region, mirroring hyper-util's TokioIo bridge.
        unsafe {
            buf.advance(n);
        }
        std::task::Poll::Ready(Ok(()))
    }
}

impl hyper::rt::Write for TunnelStream {
    // hyper's runtime Write has identical signatures to tokio's AsyncWrite;
    // delegate instead of duplicating the Plain/Tls dispatch.
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        tokio::io::AsyncWrite::poll_write(self, cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        tokio::io::AsyncWrite::poll_flush(self, cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        tokio::io::AsyncWrite::poll_shutdown(self, cx)
    }
}

impl hyper_util::client::legacy::connect::Connection for TunnelStream {
    fn connected(&self) -> hyper_util::client::legacy::connect::Connected {
        hyper_util::client::legacy::connect::Connected::new()
    }
}

impl tokio::io::AsyncWrite for TunnelStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut() {
            TunnelStream::Plain(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            TunnelStream::Tls(s) => std::pin::Pin::new(&mut **s).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            TunnelStream::Plain(s) => std::pin::Pin::new(s).poll_flush(cx),
            TunnelStream::Tls(s) => std::pin::Pin::new(&mut **s).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            TunnelStream::Plain(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            TunnelStream::Tls(s) => std::pin::Pin::new(&mut **s).poll_shutdown(cx),
        }
    }
}

/// hyper connector that dials each request URI — directly, or through an
/// HTTP CONNECT / SOCKS5 proxy when `proxy_url` is set (reuses
/// `transport::connect_via_proxy`, the same proxy path as frpc↔frps
/// connections, so proxy auth and scheme handling stay consistent).
#[derive(Clone)]
struct HttpConnect {
    proxy_url: Option<String>,
    tls_config: Arc<rustls::ClientConfig>,
    dial_timeout: Duration,
}

impl tower_service::Service<Uri> for HttpConnect {
    type Response = TunnelStream;
    type Error = std::io::Error;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let proxy_url = self.proxy_url.clone();
        let tls_config = self.tls_config.clone();
        let dial_timeout = self.dial_timeout;
        Box::pin(async move {
            let host = uri
                .host()
                .ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::InvalidInput, "URI without host")
                })?
                .to_string();
            let port = uri
                .port_u16()
                .unwrap_or(if uri.scheme_str() == Some("https") {
                    443
                } else {
                    80
                });
            let is_tls = uri.scheme_str() == Some("https");

            // host may be an IPv6 literal; hyper's Uri::host() strips the
            // brackets from "[::1]" (the authority keeps them). Normalize
            // both forms: strip brackets for SNI, re-add them for the
            // connect address so both direct dials and proxy CONNECT
            // targets parse.
            let host_bare = host.trim_start_matches('[').trim_end_matches(']');
            let connect_host = if host_bare.contains(':') {
                format!("[{host_bare}]")
            } else {
                host_bare.to_string()
            };
            let connect_addr = format!("{connect_host}:{port}");

            let io = match &proxy_url {
                Some(p) => {
                    // dial_timeout of 0 means "no deadline" (request() and
                    // the plugin path rely on this); fall back to the
                    // default rather than clamping to a 1 s dial.
                    let timeout_secs = if dial_timeout.is_zero() {
                        10
                    } else {
                        dial_timeout.as_secs().min(60)
                    };
                    crate::transport::connect_via_proxy(
                        p,
                        &connect_host,
                        port,
                        timeout_secs,
                        0, // keepalive 0: OIDC/plugin requests are short-lived
                    )
                    .await
                    .map_err(std::io::Error::other)?
                }
                None => {
                    let tcp = tokio::net::TcpStream::connect(&connect_addr).await?;
                    crate::transport::set_nodelay(&tcp);
                    crate::transport::IoStream::Tcp(tcp)
                }
            };

            if is_tls {
                let server_name = rustls::pki_types::ServerName::try_from(host_bare.to_string())
                    .map_err(std::io::Error::other)?;
                let connector = tokio_rustls::TlsConnector::from(tls_config);
                let tls = connector
                    .connect(server_name, io)
                    .await
                    .map_err(std::io::Error::other)?;
                Ok(TunnelStream::Tls(Box::new(tls)))
            } else {
                Ok(TunnelStream::Plain(io))
            }
        })
    }
}

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
) -> Result<Arc<rustls::ClientConfig>, String> {
    if skip_verify {
        let config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
            .with_no_client_auth();
        return Ok(Arc::new(config));
    }

    let mut root_store = rustls::RootCertStore::empty();
    // Load webpki-roots (Mozilla CA store). ~150 embedded CA certs,
    // ~200 KB in release binaries — far less than the ICU data reqwest
    // pulled in via url → idna.
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    // If a custom CA cert was provided, add it (extends the store; does not
    // replace it — matching reqwest's add_root_certificate semantics).
    if let Some(pem) = ca_cert_pem {
        let certs = rustls::pki_types::pem::PemObject::pem_slice_iter(pem)
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
    Ok(Arc::new(config))
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
    proxy_url: Option<String>,
}

impl HttpClientBuilder {
    pub fn new() -> Self {
        Self {
            timeout: DEFAULT_TIMEOUT,
            skip_verify: false,
            ca_cert_pem: None,
            proxy_url: None,
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

    /// Route requests through an HTTP CONNECT or SOCKS5 proxy (Go frp
    /// `oidcProxyUrl` compat). An empty/None value connects directly.
    pub fn proxy(mut self, url: Option<String>) -> Self {
        self.proxy_url = url.filter(|u| !u.is_empty());
        self
    }

    /// Build the HTTP client.
    pub fn build(self) -> Result<HttpClient, String> {
        let mut tls_config = build_tls_config(self.skip_verify, self.ca_cert_pem.as_deref())?;
        // Force HTTP/1.1 ALPN: hyper-util's legacy client speaks HTTP/1.1
        // here (http1-only), and without ALPN some servers fail to
        // negotiate. The old HttpsConnectorBuilder set this implicitly.
        Arc::make_mut(&mut tls_config).alpn_protocols = vec![b"http/1.1".to_vec()];

        let connector = HttpConnect {
            proxy_url: self.proxy_url,
            tls_config,
            dial_timeout: self.timeout,
        };
        let client: HttpsClient = Client::builder(TokioExecutor::new()).build(connector);

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
                // Bound the response body: an unbounded `collect()` lets a
                // malicious/compromised endpoint (OIDC discovery, plugin
                // backends, proxyURL JWT fetch) stream arbitrary data into
                // memory — OOM under panic=abort kills the whole process
                // (MED: http_client unbounded response body). The cap is 16
                // MiB — see `MAX_RESPONSE_BODY_SIZE` for the Go-divergence
                // rationale (large JWKS must not fail-closed).
                let body = Limited::new(resp.into_body(), MAX_RESPONSE_BODY_SIZE)
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

            // Drain the redirect response body before following (bounded —
            // a hostile endpoint must not force us to buffer more than the
            // cap we would accept as a real response).
            let _ = Limited::new(resp.into_body(), MAX_RESPONSE_BODY_SIZE)
                .collect()
                .await;

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

    /// End-to-end: a request through an HTTP CONNECT proxy reaches the
    /// target and the reply comes back through the tunnel. Exercises the
    /// HttpConnect connector's proxy branch + transport::connect_via_proxy.
    #[tokio::test]
    async fn http_client_routes_through_http_connect_proxy() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Target origin server.
        let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();
        let target_task = tokio::spawn(async move {
            let (mut sock, _) = target.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let n = sock.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]);
            assert!(
                req.starts_with("GET /hello"),
                "expected GET /hello, got: {req:?}"
            );
            sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await
                .unwrap();
        });

        // Minimal HTTP CONNECT proxy: answer CONNECT then splice bytes.
        let proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let proxy_task = tokio::spawn(async move {
            let (mut client, _) = proxy.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let n = client.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]);
            assert!(
                req.starts_with("CONNECT 127.0.0.1:"),
                "expected CONNECT to target, got: {req:?}"
            );
            client
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await
                .unwrap();
            let mut target = tokio::net::TcpStream::connect(&target_addr).await.unwrap();
            tokio::io::copy_bidirectional_with_sizes(
                &mut client,
                &mut target,
                32 * 1024,
                32 * 1024,
            )
            .await
            .unwrap();
        });

        let http_client = HttpClientBuilder::new()
            .timeout(Duration::from_secs(5))
            .proxy(Some(format!("http://{proxy_addr}")))
            .build()
            .unwrap();
        let resp = http_client
            .get(&format!("http://{target_addr}/hello"))
            .await
            .unwrap();
        assert!(resp.status().is_success());
        assert_eq!(resp.text().await.unwrap(), "ok");

        target_task.await.unwrap();
        proxy_task.await.unwrap();
    }

    /// HTTPS target through an HTTP CONNECT proxy: the TLS handshake must
    /// happen *inside* the tunnel (the proxy only splices bytes), with SNI
    /// for the target host. Uses a self-signed cert + tls_skip_verify.
    /// gated on `tls`: rcgen (cert generation) is a tls-feature dep, and
    /// this test needs tokio-rustls server-side too.
    #[cfg(feature = "tls")]
    #[tokio::test]
    async fn https_via_proxy_tls_in_tunnel() {
        use rcgen::{CertificateParams, KeyPair};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

        // Self-signed cert for "localhost".
        let key = KeyPair::generate().unwrap();
        let params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let cert = params.self_signed(&key).unwrap();
        let cert_der = CertificateDer::from(cert.der().to_vec());
        let key_der = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key.serialize_der()));

        // Local HTTPS origin. Custom cert resolver asserts the SNI is the
        // target hostname (guards against the connector sending the proxy
        // address or an IP as SNI) before delegating to SNI-based lookup.
        let tcp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = tcp_listener.local_addr().unwrap();

        #[derive(Debug)]
        struct AssertSniResolver {
            inner: tokio_rustls::rustls::server::ResolvesServerCertUsingSni,
        }
        impl tokio_rustls::rustls::server::ResolvesServerCert for AssertSniResolver {
            fn resolve(
                &self,
                client_hello: tokio_rustls::rustls::server::ClientHello<'_>,
            ) -> Option<std::sync::Arc<tokio_rustls::rustls::sign::CertifiedKey>> {
                assert_eq!(
                    client_hello.server_name(),
                    Some("localhost"),
                    "SNI must be the target hostname, not the proxy/IP"
                );
                self.inner.resolve(client_hello)
            }
        }

        let provider = std::sync::Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
        let certified =
            tokio_rustls::rustls::sign::CertifiedKey::from_der(vec![cert_der], key_der, &provider)
                .unwrap();
        let mut sni = tokio_rustls::rustls::server::ResolvesServerCertUsingSni::new();
        sni.add("localhost", certified).unwrap();
        let server_cfg = tokio_rustls::rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(std::sync::Arc::new(AssertSniResolver { inner: sni }));
        let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(server_cfg));
        let origin_task = tokio::spawn(async move {
            let (tcp, _) = tcp_listener.accept().await.unwrap();
            let mut tls = acceptor.accept(tcp).await.expect("TLS handshake in tunnel");
            let mut buf = [0u8; 1024];
            let n = tls.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]);
            assert!(
                req.starts_with("GET /secure"),
                "expected GET /secure over TLS, got: {req:?}"
            );
            tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nok!!")
                .await
                .unwrap();
            // Flush + send close_notify so the client reads a clean EOF.
            tls.flush().await.unwrap();
            tls.shutdown().await.unwrap();
        });

        // Local HTTP CONNECT proxy (byte splice).
        let proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let proxy_task = tokio::spawn(async move {
            let (mut client, _) = proxy.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let n = client.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]);
            assert!(
                req.starts_with("CONNECT localhost:"),
                "expected CONNECT to localhost, got: {req:?}"
            );
            client
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await
                .unwrap();
            let mut origin = tokio::net::TcpStream::connect(&origin_addr).await.unwrap();
            tokio::io::copy_bidirectional_with_sizes(
                &mut client,
                &mut origin,
                32 * 1024,
                32 * 1024,
            )
            .await
            .unwrap();
        });

        let http_client = HttpClientBuilder::new()
            .timeout(Duration::from_secs(5))
            .tls_skip_verify(true)
            .proxy(Some(format!("http://{proxy_addr}")))
            .build()
            .unwrap();
        let resp = http_client
            .get(&format!("https://localhost:{}/secure", origin_addr.port()))
            .await
            .unwrap();
        assert!(resp.status().is_success());
        assert_eq!(resp.text().await.unwrap(), "ok!!");

        origin_task.await.unwrap();
        proxy_task.await.unwrap();
    }
}
