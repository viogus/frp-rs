//! TLS transport: [`TlsTransport`] wraps a type-erased TLS stream (any
//! TLS-wrapped transport — plain TCP, PreRead, KCP) plus the peer address
//! recorded at accept/dial time. All TLS config builders live here too.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use rustls_platform_verifier::BuilderVerifierExt;
use rustls_platform_verifier::ConfigVerifierExt;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::TlsConnector;

use crate::TransportError;

use super::{AsyncReadWrite, BoxedReadHalf, BoxedWriteHalf, Transport};

/// TLS-wrapped transport. Holds a type-erased inner stream (any TLS-wrapped
/// transport — plain TCP, PreRead, KCP) plus the peer address recorded at
/// accept/dial time.
pub struct TlsTransport {
    inner: Box<dyn AsyncReadWrite>,
    peer_addr: SocketAddr,
}

impl TlsTransport {
    pub fn new(inner: Box<dyn AsyncReadWrite>, peer_addr: SocketAddr) -> Self {
        Self { inner, peer_addr }
    }
}

impl AsyncRead for TlsTransport {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for TlsTransport {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl Transport for TlsTransport {
    fn debug_name(&self) -> &'static str {
        "IoStream::Tls"
    }
    fn peer_addr(&self) -> Option<SocketAddr> {
        Some(self.peer_addr)
    }
    fn into_tls(self: Box<Self>) -> Option<TlsTransport> {
        Some(*self)
    }
    fn into_split(self: Box<Self>) -> io::Result<(BoxedReadHalf, BoxedWriteHalf)> {
        let TlsTransport { inner, .. } = *self;
        let (r, w) = tokio::io::split(inner);
        Ok((Box::new(r), Box::new(w)))
    }
}

/// TLS configuration.
#[derive(Debug, Clone)]
pub struct TlsConfig {
    pub enable: bool,
    pub cert_file: Option<String>,
    pub key_file: Option<String>,
    pub ca_file: Option<String>,
}

/// Build a [`rustls::ServerConfig`] from PEM-encoded cert and key files.
/// If `ca_file` is provided, client certificates are required and verified (mTLS).
pub fn build_tls_server_config(
    cert_file: &str,
    key_file: &str,
    ca_file: Option<&str>,
) -> Result<rustls::ServerConfig, crate::Error> {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};

    let cert_bytes = std::fs::read(cert_file).map_err(|e| {
        crate::Error::Transport(TransportError::Other(format!("open cert file: {e}")))
    })?;
    let certs = CertificateDer::pem_slice_iter(&cert_bytes)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| crate::Error::Transport(TransportError::Other(format!("read certs: {e}"))))?;

    let key_bytes = std::fs::read(key_file).map_err(|e| {
        crate::Error::Transport(TransportError::Other(format!("open key file: {e}")))
    })?;
    let key = PrivateKeyDer::from_pem_slice(&key_bytes).map_err(|e| {
        crate::Error::Transport(TransportError::Other(format!("read private key: {e}")))
    })?;

    // Build server config with optional client certificate verification (mTLS)
    let config = if let Some(ca_path) = ca_file {
        if !ca_path.is_empty() {
            let mut roots = rustls::RootCertStore::empty();
            let ca_bytes = std::fs::read(ca_path).map_err(|e| {
                crate::Error::Transport(TransportError::Other(format!("open CA file: {e}")))
            })?;
            let ca_certs = CertificateDer::pem_slice_iter(&ca_bytes)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| {
                    crate::Error::Transport(TransportError::Other(format!("read CA certs: {e}")))
                })?;
            roots.add_parsable_certificates(ca_certs);

            let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
                .build()
                .map_err(|e| {
                    crate::Error::Transport(TransportError::Other(format!(
                        "build client cert verifier: {e}"
                    )))
                })?;

            rustls::ServerConfig::builder()
                .with_client_cert_verifier(verifier)
                .with_single_cert(certs, key)
                .map_err(|e| {
                    crate::Error::Transport(TransportError::Other(format!(
                        "build mTLS config: {e}"
                    )))
                })?
        } else {
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .map_err(|e| {
                    crate::Error::Transport(TransportError::Other(format!("build TLS config: {e}")))
                })?
        }
    } else {
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| {
                crate::Error::Transport(TransportError::Other(format!("build TLS config: {e}")))
            })?
    };

    Ok(config)
}

/// Create a TLS acceptor from PEM-encoded cert and key files.
/// If ca_file is provided, client certificates will be verified against it (mTLS).
pub fn build_tls_acceptor(
    cert_file: &str,
    key_file: &str,
    ca_file: Option<&str>,
) -> Result<TlsAcceptor, crate::Error> {
    build_tls_acceptor_with_alpn(cert_file, key_file, ca_file, &[])
}

/// Like [`build_tls_acceptor`], but advertises the given ALPN protocols to
/// clients (e.g. `b"h2"`, `b"http/1.1"`). An empty slice leaves the
/// `rustls::ServerConfig` ALPN list untouched (no ALPN advertised).
pub fn build_tls_acceptor_with_alpn(
    cert_file: &str,
    key_file: &str,
    ca_file: Option<&str>,
    alpn: &[&[u8]],
) -> Result<TlsAcceptor, crate::Error> {
    let mut config = build_tls_server_config(cert_file, key_file, ca_file)?;
    if !alpn.is_empty() {
        config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    }
    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// Generate a self-signed TLS certificate and build a [`rustls::ServerConfig`].
///
/// Matches Go frp's `newRandomTLSKeyPair()` behavior: when no cert/key files
/// are configured, frps auto-generates a self-signed cert so it can always
/// accept TLS connections (Go frpc sends TLS ClientHello by default).
///
/// Uses ECDSA P-256 (ring backend) — Go frp uses RSA 2048 but the algorithm
/// difference is irrelevant for TLS compatibility.
fn generate_self_signed_cert_and_key() -> Result<
    (
        rustls::pki_types::CertificateDer<'static>,
        rustls::pki_types::PrivateKeyDer<'static>,
    ),
    crate::Error,
> {
    use rcgen::{CertificateParams, DistinguishedName, DnType, IsCa, KeyPair};

    let key_pair = KeyPair::generate().map_err(|e| {
        crate::Error::Transport(TransportError::Other(format!("generate TLS key pair: {e}")))
    })?;

    let mut params = CertificateParams::new(vec!["frp".to_string()]).map_err(|e| {
        crate::Error::Transport(TransportError::Other(format!(
            "create TLS cert params: {e}"
        )))
    })?;

    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "frp");
    dn.push(DnType::OrganizationName, "frp-rs auto-generated");
    params.distinguished_name = dn;
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::DigitalSignature,
        rcgen::KeyUsagePurpose::KeyEncipherment,
    ];
    // Uses rcgen's default validity (now → now + 365 days).
    // Go frp uses 10 years but the auto-generated cert is regenerated on every
    // frps restart, so a shorter validity is acceptable.

    let cert = params.self_signed(&key_pair).map_err(|e| {
        crate::Error::Transport(TransportError::Other(format!("self-sign TLS cert: {e}")))
    })?;

    let cert_der = cert.der().clone();
    let key_der: rustls::pki_types::PrivateKeyDer<'static> =
        rustls::pki_types::PrivatePkcs8KeyDer::from(key_pair.serialize_der()).into();

    Ok((cert_der, key_der))
}

pub fn generate_self_signed_tls_config() -> Result<rustls::ServerConfig, crate::Error> {
    let (cert_der, key_der) = generate_self_signed_cert_and_key()?;
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .map_err(|e| {
            crate::Error::Transport(TransportError::Other(format!(
                "build TLS config from generated cert: {e}"
            )))
        })?;

    Ok(config)
}

/// Build a self-signed server identity, optionally requiring and verifying
/// client certificates against `ca_file` (mTLS). Go frp does this whenever
/// `trustedCaFile` is set, even with a generated server certificate.
pub fn generate_self_signed_tls_config_with_ca(
    ca_file: Option<&str>,
) -> Result<rustls::ServerConfig, crate::Error> {
    let (cert_der, key_der) = generate_self_signed_cert_and_key()?;
    match ca_file {
        Some(ca_path) if !ca_path.is_empty() => {
            let roots = build_root_store(Some(ca_path))?.ok_or_else(|| {
                crate::Error::Transport(TransportError::Other("empty client CA store".into()))
            })?;
            let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
                .build()
                .map_err(|e| {
                    crate::Error::Transport(TransportError::Other(format!(
                        "build client cert verifier: {e}"
                    )))
                })?;
            rustls::ServerConfig::builder()
                .with_client_cert_verifier(verifier)
                .with_single_cert(vec![cert_der], key_der)
                .map_err(|e| {
                    crate::Error::Transport(TransportError::Other(format!(
                        "build mTLS config from generated cert: {e}"
                    )))
                })
        }
        _ => rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .map_err(|e| {
                crate::Error::Transport(TransportError::Other(format!(
                    "build TLS config from generated cert: {e}"
                )))
            }),
    }
}

/// Build a [`TlsAcceptor`] from cert/key files, or auto-generate a self-signed
/// cert when no files are configured (matching Go frp behavior).
///
/// When both `cert_file` and `key_file` are non-empty, this delegates to
/// [`build_tls_acceptor`]. When `ca_file` is non-empty, the acceptor always
/// requires and verifies client certificates (mTLS), even when the server
/// identity is a generated self-signed certificate (Go frp compat).
/// Providing exactly one of cert/key is a startup error.
pub fn build_tls_acceptor_or_generate(
    cert_file: &str,
    key_file: &str,
    ca_file: Option<&str>,
) -> Result<TlsAcceptor, crate::Error> {
    let cert_set = !cert_file.is_empty();
    let key_set = !key_file.is_empty();
    if cert_set != key_set {
        return Err(crate::Error::Transport(TransportError::Other(
            "TLS requires both cert_file and key_file to be set; got only one".into(),
        )));
    }
    if cert_set {
        return build_tls_acceptor(cert_file, key_file, ca_file);
    }
    tracing::info!("No TLS cert files configured — auto-generating self-signed certificate");
    let config = generate_self_signed_tls_config_with_ca(ca_file)?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// Build a `RootCertStore` from a custom CA file path.
/// Returns `None` when no custom CA is specified (caller should use
/// the platform verifier instead).
pub fn build_root_store(
    ca_file: Option<&str>,
) -> Result<Option<rustls::RootCertStore>, crate::Error> {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::CertificateDer;

    match ca_file {
        Some(ca_path) if !ca_path.is_empty() => {
            let mut root_store = rustls::RootCertStore::empty();
            let ca_bytes = std::fs::read(ca_path).map_err(|e| {
                crate::Error::Transport(TransportError::Other(format!("open CA file: {e}")))
            })?;
            let certs = CertificateDer::pem_slice_iter(&ca_bytes)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| {
                    crate::Error::Transport(TransportError::Other(format!("read CA certs: {e}")))
                })?;
            root_store.add_parsable_certificates(certs);
            Ok(Some(root_store))
        }
        _ => Ok(None),
    }
}

/// Create a TLS connector with platform certificate verification.
///
/// Uses the OS platform trust store for certificate verification (safe default).
/// Used by plugin backends connecting to user-specified HTTPS servers.
///
/// If ca_file is provided, verifies against that custom root store instead.
/// If cert_file/key_file are provided, present client certificate to server (mTLS).
pub fn build_tls_connector(
    ca_file: Option<&str>,
    cert_file: Option<&str>,
    key_file: Option<&str>,
) -> Result<TlsConnector, crate::Error> {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};

    let root_store = build_root_store(ca_file)?;

    let config = if let Some(store) = root_store {
        // Custom CA: verify against the provided root store.
        if let (Some(cert_path), Some(key_path)) = (cert_file, key_file) {
            if !cert_path.is_empty() && !key_path.is_empty() {
                let cert_bytes = std::fs::read(cert_path).map_err(|e| {
                    crate::Error::Transport(TransportError::Other(format!(
                        "open client cert file: {e}"
                    )))
                })?;
                let client_certs = CertificateDer::pem_slice_iter(&cert_bytes)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| {
                        crate::Error::Transport(TransportError::Other(format!(
                            "read client certs: {e}"
                        )))
                    })?;
                let key_bytes = std::fs::read(key_path).map_err(|e| {
                    crate::Error::Transport(TransportError::Other(format!(
                        "open client key file: {e}"
                    )))
                })?;
                let client_key = PrivateKeyDer::from_pem_slice(&key_bytes).map_err(|e| {
                    crate::Error::Transport(TransportError::Other(format!("read client key: {e}")))
                })?;
                rustls::ClientConfig::builder()
                    .with_root_certificates(Arc::new(store))
                    .with_client_auth_cert(client_certs, client_key)
                    .map_err(|e| {
                        crate::Error::Transport(TransportError::Other(format!(
                            "build mTLS client config: {e}"
                        )))
                    })?
            } else {
                rustls::ClientConfig::builder()
                    .with_root_certificates(Arc::new(store))
                    .with_no_client_auth()
            }
        } else {
            rustls::ClientConfig::builder()
                .with_root_certificates(Arc::new(store))
                .with_no_client_auth()
        }
    } else {
        // No custom CA: use platform verifier for OS trust store (default safe behavior).
        // Used by plugin backends connecting to user-specified HTTPS servers.
        if let (Some(cert_path), Some(key_path)) = (cert_file, key_file) {
            if !cert_path.is_empty() && !key_path.is_empty() {
                let cert_bytes = std::fs::read(cert_path).map_err(|e| {
                    crate::Error::Transport(TransportError::Other(format!(
                        "open client cert file: {e}"
                    )))
                })?;
                let client_certs = CertificateDer::pem_slice_iter(&cert_bytes)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| {
                        crate::Error::Transport(TransportError::Other(format!(
                            "read client certs: {e}"
                        )))
                    })?;
                let key_bytes = std::fs::read(key_path).map_err(|e| {
                    crate::Error::Transport(TransportError::Other(format!(
                        "open client key file: {e}"
                    )))
                })?;
                let client_key = PrivateKeyDer::from_pem_slice(&key_bytes).map_err(|e| {
                    crate::Error::Transport(TransportError::Other(format!("read client key: {e}")))
                })?;
                rustls::ClientConfig::builder()
                    .with_platform_verifier()
                    .map_err(|e| {
                        crate::Error::Transport(TransportError::Other(format!(
                            "platform verifier: {e}"
                        )))
                    })?
                    .with_client_auth_cert(client_certs, client_key)
                    .map_err(|e| {
                        crate::Error::Transport(TransportError::Other(format!(
                            "build mTLS client config: {e}"
                        )))
                    })?
            } else {
                rustls::ClientConfig::builder()
                    .with_platform_verifier()
                    .map_err(|e| {
                        crate::Error::Transport(TransportError::Other(format!(
                            "platform verifier: {e}"
                        )))
                    })?
                    .with_no_client_auth()
            }
        } else {
            <rustls::ClientConfig as ConfigVerifierExt>::with_platform_verifier().map_err(|e| {
                crate::Error::Transport(TransportError::Other(format!("platform verifier: {e}")))
            })?
        }
    };

    Ok(TlsConnector::from(Arc::new(config)))
}

/// Process-local "last connector" cache for [`build_tls_connector_skip_verify`].
///
/// Rebuilding a connector re-reads and re-parses PEM files and constructs a
/// verifier — repeated per dial even though the config is identical. Cache
/// the most recent one keyed by (path, mtime): a reload that changes the CA
/// or client-cert files yields a different mtime, so the entry self-invalidates.
/// `tokio_rustls::TlsConnector` is an `Arc<ClientConfig>` — sharing is free.
struct ConnectorKey {
    // (path, mtime, size) — mtime None means "configured but file missing",
    // which must stay distinct from "not configured" (None) for cache
    // correctness. Size is included so a content rewrite that lands inside
    // the filesystem mtime granularity window (1s FAT 2s) still invalidates
    // when the length changes.
    ca: Option<(String, Option<std::time::SystemTime>, u64)>,
    cert: Option<(String, Option<std::time::SystemTime>, u64)>,
    key: Option<(String, Option<std::time::SystemTime>, u64)>,
}

impl PartialEq for ConnectorKey {
    fn eq(&self, other: &Self) -> bool {
        self.ca == other.ca && self.cert == other.cert && self.key == other.key
    }
}

fn file_stat(path: &str) -> Option<(std::time::SystemTime, u64)> {
    std::fs::metadata(path)
        .ok()
        .and_then(|m| m.modified().ok().map(|t| (t, m.len())))
}

fn non_empty(p: Option<&str>) -> Option<&str> {
    match p {
        Some(s) if !s.is_empty() => Some(s),
        _ => None,
    }
}

fn connector_key(
    ca_file: Option<&str>,
    cert_file: Option<&str>,
    key_file: Option<&str>,
) -> ConnectorKey {
    ConnectorKey {
        ca: non_empty(ca_file).map(|p| {
            let (t, len) = file_stat(p).map_or((None, 0), |(t, len)| (Some(t), len));
            (p.to_string(), t, len)
        }),
        cert: non_empty(cert_file).map(|p| {
            let (t, len) = file_stat(p).map_or((None, 0), |(t, len)| (Some(t), len));
            (p.to_string(), t, len)
        }),
        key: non_empty(key_file).map(|p| {
            let (t, len) = file_stat(p).map_or((None, 0), |(t, len)| (Some(t), len));
            (p.to_string(), t, len)
        }),
    }
}

static CONNECTOR_CACHE: std::sync::Mutex<Option<(ConnectorKey, TlsConnector)>> =
    std::sync::Mutex::new(None);

/// Number of actual connector builds (cache misses). Test-only — lets tests
/// assert a cache hit did not rebuild.
#[cfg(test)]
static CONNECTOR_BUILD_COUNT: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// Test-only accessor: how many times the connector was actually rebuilt.
#[cfg(test)]
fn connector_build_count() -> usize {
    CONNECTOR_BUILD_COUNT.load(std::sync::atomic::Ordering::Relaxed)
}

/// Build a TLS client connector with certificate verification skipped when no
/// CA file is given (InsecureSkipVerify=true, matching Go frp's default for
/// auto-generated self-signed certs). With `ca_file`, verify against it
/// (mTLS when client cert/key are also provided). The most recent connector
/// is cached per (path, mtime) — see [`ConnectorKey`].
pub fn build_tls_connector_skip_verify(
    ca_file: Option<&str>,
    cert_file: Option<&str>,
    key_file: Option<&str>,
) -> Result<TlsConnector, crate::Error> {
    let key = connector_key(ca_file, cert_file, key_file);
    if let Some((cached_key, cached)) = CONNECTOR_CACHE
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
    {
        if *cached_key == key {
            return Ok(cached.clone());
        }
    }

    let connector = build_tls_connector_skip_verify_inner(ca_file, cert_file, key_file)?;
    #[cfg(test)]
    CONNECTOR_BUILD_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    *CONNECTOR_CACHE.lock().unwrap_or_else(|e| e.into_inner()) = Some((key, connector.clone()));
    Ok(connector)
}

fn build_tls_connector_skip_verify_inner(
    ca_file: Option<&str>,
    cert_file: Option<&str>,
    key_file: Option<&str>,
) -> Result<TlsConnector, crate::Error> {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};

    let root_store = build_root_store(ca_file)?;

    let config = if let Some(store) = root_store {
        // Custom CA provided: verify against it normally.
        if let (Some(cert_path), Some(key_path)) = (cert_file, key_file) {
            if !cert_path.is_empty() && !key_path.is_empty() {
                let cert_bytes = std::fs::read(cert_path).map_err(|e| {
                    crate::Error::Transport(TransportError::Other(format!(
                        "open client cert file: {e}"
                    )))
                })?;
                let client_certs = CertificateDer::pem_slice_iter(&cert_bytes)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| {
                        crate::Error::Transport(TransportError::Other(format!(
                            "read client certs: {e}"
                        )))
                    })?;
                let key_bytes = std::fs::read(key_path).map_err(|e| {
                    crate::Error::Transport(TransportError::Other(format!(
                        "open client key file: {e}"
                    )))
                })?;
                let client_key = PrivateKeyDer::from_pem_slice(&key_bytes).map_err(|e| {
                    crate::Error::Transport(TransportError::Other(format!("read client key: {e}")))
                })?;
                rustls::ClientConfig::builder()
                    .with_root_certificates(Arc::new(store))
                    .with_client_auth_cert(client_certs, client_key)
                    .map_err(|e| {
                        crate::Error::Transport(TransportError::Other(format!(
                            "build mTLS client config: {e}"
                        )))
                    })?
            } else {
                rustls::ClientConfig::builder()
                    .with_root_certificates(Arc::new(store))
                    .with_no_client_auth()
            }
        } else {
            rustls::ClientConfig::builder()
                .with_root_certificates(Arc::new(store))
                .with_no_client_auth()
        }
    } else {
        // No CA file: skip certificate verification (InsecureSkipVerify=true).
        // Matches Go frp's default — auto-generated self-signed certs.
        // PRODUCTION WARNING: this means TLS connections are vulnerable to
        // man-in-the-middle attacks. Any intermediate node can intercept
        // and decrypt the control + data-plane traffic.
        tracing::error!(
            "TLS certificate verification is DISABLED (InsecureSkipVerify=true). \
             All control and data-plane traffic is vulnerable to MITM attacks and \
             authentication credentials can be captured and replayed. \
             For production, set tls.ca_file (frpc: tls.trusted_ca_file) to a CA \
             that signed the server certificate to enable verification."
        );
        let verifier = Arc::new(InsecureSkipVerify);
        if let (Some(cert_path), Some(key_path)) = (cert_file, key_file) {
            if !cert_path.is_empty() && !key_path.is_empty() {
                let cert_bytes = std::fs::read(cert_path).map_err(|e| {
                    crate::Error::Transport(TransportError::Other(format!(
                        "open client cert file: {e}"
                    )))
                })?;
                let client_certs = CertificateDer::pem_slice_iter(&cert_bytes)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| {
                        crate::Error::Transport(TransportError::Other(format!(
                            "read client certs: {e}"
                        )))
                    })?;
                let key_bytes = std::fs::read(key_path).map_err(|e| {
                    crate::Error::Transport(TransportError::Other(format!(
                        "open client key file: {e}"
                    )))
                })?;
                let client_key = PrivateKeyDer::from_pem_slice(&key_bytes).map_err(|e| {
                    crate::Error::Transport(TransportError::Other(format!("read client key: {e}")))
                })?;
                rustls::ClientConfig::builder()
                    .dangerous()
                    .with_custom_certificate_verifier(verifier)
                    .with_client_auth_cert(client_certs, client_key)
                    .map_err(|e| {
                        crate::Error::Transport(TransportError::Other(format!(
                            "build mTLS client config with skip-verify: {e}"
                        )))
                    })?
            } else {
                rustls::ClientConfig::builder()
                    .dangerous()
                    .with_custom_certificate_verifier(verifier)
                    .with_no_client_auth()
            }
        } else {
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(verifier)
                .with_no_client_auth()
        }
    };

    Ok(TlsConnector::from(Arc::new(config)))
}

/// A certificate verifier that accepts all server certificates (InsecureSkipVerify=true).
#[derive(Debug)]
pub(crate) struct InsecureSkipVerify;

impl rustls::client::danger::ServerCertVerifier for InsecureSkipVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
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
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_tls_connector_with_platform_verifier() {
        let result = build_tls_connector(None, None, None);
        assert!(
            result.is_ok(),
            "TLS connector with default roots should build"
        );
    }

    #[test]
    fn test_build_tls_acceptor_missing_cert() {
        let result = build_tls_acceptor("/nonexistent/cert.pem", "/nonexistent/key.pem", None);
        assert!(
            result.is_err(),
            "TLS acceptor with missing files should fail"
        );
    }

    #[test]
    fn test_build_tls_acceptor_or_generate_rejects_partial_cert_key() {
        let cert_only = build_tls_acceptor_or_generate("/tmp/cert.pem", "", None)
            .err()
            .expect("cert without key must fail");
        assert!(
            cert_only
                .to_string()
                .contains("both cert_file and key_file"),
            "unexpected error: {cert_only}"
        );
        let key_only = build_tls_acceptor_or_generate("", "/tmp/key.pem", None)
            .err()
            .expect("key without cert must fail");
        assert!(
            key_only.to_string().contains("both cert_file and key_file"),
            "unexpected error: {key_only}"
        );
    }

    #[tokio::test]
    async fn test_generated_mtls_rejects_client_without_cert() {
        use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
        use rustls::pki_types::ServerName;
        use std::io::Write;
        use std::sync::Arc;
        use tokio::net::{TcpListener, TcpStream};
        use tokio_rustls::TlsConnector;

        let mut ca_params =
            CertificateParams::new(Vec::<String>::default()).expect("empty SAN is valid");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params
            .key_usages
            .push(rcgen::KeyUsagePurpose::DigitalSignature);
        ca_params
            .key_usages
            .push(rcgen::KeyUsagePurpose::KeyCertSign);
        ca_params.key_usages.push(rcgen::KeyUsagePurpose::CrlSign);
        let ca_key = KeyPair::generate().expect("generate CA key");
        let ca_cert = ca_params
            .self_signed(&ca_key)
            .expect("self-sign CA certificate");

        let mut ca_file = tempfile::NamedTempFile::new().expect("create CA tempfile");
        let ca_der = ca_cert.der();
        let ca_b64 = crate::base64::encode(ca_der.as_ref());
        let mut ca_pem = String::from("-----BEGIN CERTIFICATE-----\n");
        for chunk in ca_b64.as_bytes().chunks(64) {
            ca_pem.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
            ca_pem.push('\n');
        }
        ca_pem.push_str("-----END CERTIFICATE-----\n");
        ca_file.write_all(ca_pem.as_bytes()).expect("write CA PEM");

        let acceptor = build_tls_acceptor_or_generate(
            "",
            "",
            Some(ca_file.path().to_str().expect("temp path")),
        )
        .expect("generated identity with CA must build");

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept connection");
            acceptor.accept(stream).await
        });

        let client_config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(InsecureSkipVerify))
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(client_config));
        let tcp = TcpStream::connect(addr).await.expect("connect to server");
        let _handshake = connector
            .connect(ServerName::try_from("frp").expect("valid server name"), tcp)
            .await;

        let server_result = tokio::time::timeout(std::time::Duration::from_secs(5), server)
            .await
            .expect("server handshake must not hang")
            .expect("server task must complete");
        assert!(
            server_result.is_err(),
            "mTLS acceptor must reject a client without a certificate"
        );
    }
}

#[cfg(test)]
mod connector_cache_tests {
    // These run as ONE test: CONNECTOR_CACHE / CONNECTOR_BUILD_COUNT are
    // process-global statics, so parallel tests would race on them.
    use super::*;

    fn dummy_ca_pem() -> String {
        "-----BEGIN CERTIFICATE-----\nMIID\n-----END CERTIFICATE-----\n".to_string()
    }

    #[test]
    fn cache_behavior() {
        // 1) Cache hit: identical args must not rebuild.
        let before = connector_build_count();
        let _ = build_tls_connector_skip_verify(None, None, None).unwrap();
        let _ = build_tls_connector_skip_verify(None, None, None).unwrap();
        assert_eq!(
            connector_build_count(),
            before + 1,
            "second call with identical args must hit the cache"
        );

        // 2) mtime change → new key → rebuild.
        let dir = tempfile::tempdir().unwrap();
        let ca_path = dir.path().join("ca.pem");
        std::fs::write(&ca_path, dummy_ca_pem()).unwrap();
        let ca = ca_path.to_str().unwrap().to_string();
        let before = connector_build_count();
        let _ = build_tls_connector_skip_verify(Some(&ca), None, None).unwrap();
        let _ = build_tls_connector_skip_verify(Some(&ca), None, None).unwrap();
        assert_eq!(
            connector_build_count(),
            before + 1,
            "unchanged CA must hit cache"
        );
        // 2) mtime/size change → new key → rebuild. Sleep past the mtime
        //    granularity window (1s on ext4/apfs, 2s on FAT).
        std::thread::sleep(std::time::Duration::from_millis(2100));
        std::fs::write(&ca_path, dummy_ca_pem()).unwrap();
        let _ = build_tls_connector_skip_verify(Some(&ca), None, None).unwrap();
        assert_eq!(
            connector_build_count(),
            before + 2,
            "changed CA file must rebuild the connector"
        );

        // 3) A failing build must not be cached (and a missing-file key must
        //    not collide with the no-CA entry from step 1).
        let before = connector_build_count();
        assert!(build_tls_connector_skip_verify(Some("/nonexistent/ca.pem"), None, None).is_err());
        assert!(build_tls_connector_skip_verify(Some("/nonexistent/ca.pem"), None, None).is_err());
        assert_eq!(
            connector_build_count(),
            before,
            "failed builds must not be cached"
        );
    }
}
