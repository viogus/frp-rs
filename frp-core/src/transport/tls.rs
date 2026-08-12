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
    /// PEM file with the TLS certificate (server identity).
    pub cert_file: Option<String>,
    /// PEM file with the TLS private key matching `cert_file`.
    pub key_file: Option<String>,
    /// PEM file with CA certificates. On the server this enables mTLS:
    /// client certificates are required and verified against this store.
    /// On the client this is the trust anchor used instead of
    /// skip-verify: when set, the server certificate is verified against
    /// it. **Setting this on the client is the fix for the insecure
    /// skip-verify default** (Go frp compat: `tls_trusted_ca_file` /
    /// frpc `tls.trusted_ca_file`).
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
/// the most recent one keyed by (path, content hash): a reload that changes
/// the CA or client-cert files yields a different hash, so the entry
/// self-invalidates. Hashing the file *contents* (instead of only mtime/size,
/// which the mtime-granularity window can miss) makes the key exact; the
/// hash itself is memoized per (mtime, size) in [`FILE_HASH_MEMO`], so the
/// files are only re-read when their stat changes and a cache hit costs one
/// `metadata()` syscall, not a full file read + hash per dial.
/// `tokio_rustls::TlsConnector` is an `Arc<ClientConfig>` — sharing is free.
struct ConnectorKey {
    // (path, content hash) — hash None means "configured but file missing",
    // which must stay distinct from "not configured" (None) for cache
    // correctness.
    ca: Option<(String, Option<[u8; 32]>)>,
    cert: Option<(String, Option<[u8; 32]>)>,
    key: Option<(String, Option<[u8; 32]>)>,
}

impl PartialEq for ConnectorKey {
    fn eq(&self, other: &Self) -> bool {
        self.ca == other.ca && self.cert == other.cert && self.key == other.key
    }
}

/// A stat is only trustworthy for memoization once the mtime has settled.
/// Linux filesystems update timestamps lazily: a same-size rewrite within
/// ~ms of the previous write can leave mtime (and ctime) unchanged (kernel
/// probe: back-to-back same-size rewrites keep the old mtime ~88% of the
/// time at 4ms HZ=250 tick granularity; NFSv3 ~1s and FAT ~2s are worse),
/// so a naive (mtime, size) memo could serve a stale hash. 100ms is far
/// outside the observed coalescing window, so a file whose mtime is older
/// than this is authoritative; a fresh mtime means the file may still be
/// mid-write and is re-read + re-hashed every time (matching the pre-memo
/// per-dial behavior).
///
/// The precise guarantee of the memo is therefore:
/// - a file is re-read when its (mtime, size) stat changes, or when the
///   mtime is fresh (unsettled — the file may still be mid-write);
/// - a same-size rewrite whose mtime coalesces into an unchanged value is
///   NOT detected: the old hash keeps being served until the next stat
///   change (not forever — stale only until then);
/// - atomic-rename rotations (write a temp file, then rename over the
///   path — the dominant cert-manager pattern) always stamp a fresh mtime
///   on the path, so they are never missed.
///   For PEM updates, prefer atomic rename over in-place rewrite: besides
///   never exposing a partially written file, it guarantees the memo
///   re-reads, where an in-place same-size rewrite can hide inside the
///   coalescing window.
const STAT_SETTLE_WINDOW: std::time::Duration = std::time::Duration::from_millis(100);

/// Memoized (stat → content hash) per PEM path. `stat: None` means the file
/// could not be stat'ed (missing — "configured but absent"), which must stay
/// distinct from "not configured" (`None` in the [`ConnectorKey`]).
struct FileMemoEntry {
    stat: Option<(std::time::SystemTime, u64)>,
    hash: Option<[u8; 32]>,
}

static FILE_HASH_MEMO: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<std::path::PathBuf, FileMemoEntry>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

/// SHA-256 of a file's contents, or `None` when the file cannot be read.
///
/// Memoized per (mtime, size): the file is only re-read when the stat
/// changed or the mtime has not settled yet (see [`STAT_SETTLE_WINDOW`]) —
/// a cache hit on an unchanged file costs one `metadata()` syscall instead
/// of a full read + SHA-256 per dial.
fn file_hash(path: &str) -> Option<[u8; 32]> {
    let stat = std::fs::metadata(path)
        .ok()
        .map(|m| (m.modified().unwrap_or(std::time::UNIX_EPOCH), m.len()));
    // Settled = missing file (nothing to coalesce) or mtime at least
    // STAT_SETTLE_WINDOW old. A future mtime (utime'd forward) is settled
    // too — it cannot be re-coalesced by the lazy-timestamp window.
    let settled = match stat {
        Some((mtime, _)) => match mtime.elapsed() {
            Ok(age) => age >= STAT_SETTLE_WINDOW,
            Err(_) => true,
        },
        None => true,
    };
    // Lookup under a short lock only: the memo must not be held across the
    // blocking read + SHA-256 below (that would serialize concurrent dials
    // on unrelated paths and do blocking I/O under the mutex).
    let memo_hit = {
        let memo = FILE_HASH_MEMO.lock().unwrap_or_else(|e| e.into_inner());
        if settled {
            match memo.get(std::path::Path::new(path)) {
                Some(entry) if entry.stat == stat => Some(entry.hash),
                _ => None,
            }
        } else {
            None
        }
    };
    if let Some(hash) = memo_hit {
        return hash;
    }
    #[cfg(test)]
    FILE_READ_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let hash = std::fs::read(path).ok().map(|bytes| {
        ring::digest::digest(&ring::digest::SHA256, &bytes)
            .as_ref()
            .try_into()
            .expect("SHA-256 output is 32 bytes")
    });
    // Re-insert outside the read (last-writer-wins): a concurrent dial may
    // have inserted a fresher entry meanwhile; a duplicate read on a race
    // is harmless — both computed the same content hash.
    FILE_HASH_MEMO
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(std::path::PathBuf::from(path), FileMemoEntry { stat, hash });
    hash
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
        ca: non_empty(ca_file).map(|p| (p.to_string(), file_hash(p))),
        cert: non_empty(cert_file).map(|p| (p.to_string(), file_hash(p))),
        key: non_empty(key_file).map(|p| (p.to_string(), file_hash(p))),
    }
}

// RwLock: the cache-hit path (every outbound TLS dial) only needs a read
// lock; the exclusive lock is taken only on the rare rebuild (audit D3-4).
static CONNECTOR_CACHE: std::sync::RwLock<Option<(ConnectorKey, TlsConnector)>> =
    std::sync::RwLock::new(None);

/// Minimum interval between skip-verify warnings. The first occurrence logs
/// immediately at error level (the security value); repeat occurrences
/// within the window are suppressed, then re-logged once per window at warn
/// with a repeat note — a busy deployment running the insecure default must
/// not get a per-connection log flood.
const SKIP_VERIFY_WARN_MIN_INTERVAL: std::time::Duration = std::time::Duration::from_secs(300);

/// Last skip-verify warning time; `None` = never warned. `tokio::time::Instant`
/// is monotonic — it cannot run backwards or break under a mis-set wall
/// clock, so a pre-1970 `SystemTime::now()` can never turn this rate limit
/// into a per-dial flood (the old `AtomicU64` sentinel `last != 0` never held
/// when `SystemTime::now()` errored and returned 0).
static LAST_SKIP_VERIFY_WARN: std::sync::Mutex<Option<tokio::time::Instant>> =
    std::sync::Mutex::new(None);

/// True when a skip-verify warning is due. The initial state is `None`
/// ("never warned") — the first call always warns, with no sentinel
/// timestamp value that a broken clock could alias.
fn skip_verify_warn_due(last: Option<tokio::time::Instant>, now: tokio::time::Instant) -> bool {
    match last {
        None => true,
        Some(prev) => now.saturating_duration_since(prev) >= SKIP_VERIFY_WARN_MIN_INTERVAL,
    }
}

/// Log the InsecureSkipVerify warning at most once per
/// [`SKIP_VERIFY_WARN_MIN_INTERVAL`] per process: error level on the first
/// occurrence, then a shorter warn-level repeat carrying the interval.
fn warn_skip_verify_rate_limited() {
    // Only the state update runs under the lock; logging happens outside so
    // a subscriber that itself dials TLS (e.g. an OTLP exporter) cannot
    // deadlock on a re-entrant warning.
    let (first, should_log) = {
        let mut last = LAST_SKIP_VERIFY_WARN
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let now = tokio::time::Instant::now();
        if !skip_verify_warn_due(*last, now) {
            (false, false)
        } else {
            let first = last.is_none();
            *last = Some(now);
            (first, true)
        }
    };
    if !should_log {
        return;
    }
    if first {
        tracing::error!(
            "TLS certificate verification is DISABLED (InsecureSkipVerify=true). \
             All control and data-plane traffic is vulnerable to MITM attacks and \
             authentication credentials can be captured and replayed. \
             For production, set tls.ca_file (frpc: tls.trusted_ca_file) to a CA \
             that signed the server certificate to enable verification. \
             (This warning repeats at most once every {}s.)",
            SKIP_VERIFY_WARN_MIN_INTERVAL.as_secs()
        );
    } else {
        tracing::warn!(
            "TLS certificate verification is still DISABLED (InsecureSkipVerify=true). \
             See the first warning for remediation; this warning repeats at most \
             once every {}s.",
            SKIP_VERIFY_WARN_MIN_INTERVAL.as_secs()
        );
    }
}

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

/// Number of actual PEM file reads for hashing. Test-only — lets tests
/// assert a cache hit did not re-read the file (the stat→hash memo must
/// turn per-dial file reads into per-dial `metadata()` syscalls).
#[cfg(test)]
static FILE_READ_COUNT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Test-only accessor: how many times a PEM file was actually read to hash
/// its contents.
#[cfg(test)]
fn file_read_count() -> usize {
    FILE_READ_COUNT.load(std::sync::atomic::Ordering::Relaxed)
}

/// Build a TLS client connector with certificate verification skipped when no
/// CA file is given (InsecureSkipVerify=true, matching Go frp's default for
/// auto-generated self-signed certs). With `ca_file`, verify against it
/// (mTLS when client cert/key are also provided). The most recent connector
/// is cached per (path, content hash) — see [`ConnectorKey`]. When no CA file
/// is configured, a per-connection MITM warning is logged (see the fn body).
pub fn build_tls_connector_skip_verify(
    ca_file: Option<&str>,
    cert_file: Option<&str>,
    key_file: Option<&str>,
) -> Result<TlsConnector, crate::Error> {
    // Warn per TLS-enabled connection (not once per process at connector
    // build — the connector is cached, so the build-time log was easy to
    // miss). Fires for every dial that lands on the insecure skip-verify
    // default, i.e. whenever no CA file is configured. Rate-limited so busy
    // deployments get the first occurrence at error level but no flood.
    if non_empty(ca_file).is_none() {
        warn_skip_verify_rate_limited();
    }
    let key = connector_key(ca_file, cert_file, key_file);
    if let Some((cached_key, cached)) = CONNECTOR_CACHE
        .read()
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
    *CONNECTOR_CACHE.write().unwrap_or_else(|e| e.into_inner()) = Some((key, connector.clone()));
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
    fn skip_verify_warn_rate_limit_first_call_always_warns() {
        // The initial state is `None` ("never warned") — the first dial must
        // warn immediately. A sentinel-timestamp implementation degenerates
        // to a per-dial error-level flood when `SystemTime::now()` errors
        // (pre-1970 clock: `now == 0` never satisfies `last != 0`); the
        // monotonic Instant + Option state has no such hole.
        let now = tokio::time::Instant::now();
        assert!(skip_verify_warn_due(None, now), "first call must warn");
        assert!(
            !skip_verify_warn_due(Some(now), now),
            "repeat within the window must be suppressed"
        );
        assert!(
            !skip_verify_warn_due(
                Some(now - SKIP_VERIFY_WARN_MIN_INTERVAL + std::time::Duration::from_millis(1)),
                now
            ),
            "just inside the window must be suppressed"
        );
        assert!(
            skip_verify_warn_due(Some(now - SKIP_VERIFY_WARN_MIN_INTERVAL), now),
            "after the window the warning repeats"
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

        // 2) content change → new key → rebuild.
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
        // 2) content change → new key → rebuild. The key hashes file
        //    *contents*, so a same-size rewrite (which the old mtime+size
        //    key could miss) invalidates the cache entry — as long as the
        //    stat→hash memo re-reads. An in-place rewrite can coalesce
        //    into an unchanged mtime, so make the stat change explicit and
        //    settled first (same mechanism as step 4): without it, a dial
        //    landing ≥100ms after the (unchanged) mtime would hit the memo
        //    and serve the stale hash of the old content.
        std::fs::write(&ca_path, dummy_ca_pem().replace("MIID", "MIIE")).unwrap();
        {
            let f = std::fs::File::options().write(true).open(&ca_path).unwrap();
            f.set_modified(std::time::SystemTime::now() + std::time::Duration::from_secs(5))
                .unwrap();
        }
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

        // 4) Unchanged file → no re-read: the stat→hash memo must turn
        //    per-dial file reads into per-dial metadata() syscalls. First
        //    move the mtime far into the future: it changes the stat (so the
        //    memo re-reads once) and, being a settled stat, makes the
        //    subsequent memo hits trustworthy even under the kernel's lazy
        //    timestamp coalescing.
        let before_builds = connector_build_count();
        let before_reads = file_read_count();
        {
            let f = std::fs::File::options().write(true).open(&ca_path).unwrap();
            f.set_modified(std::time::SystemTime::now() + std::time::Duration::from_secs(5))
                .unwrap();
        }
        let _ = build_tls_connector_skip_verify(Some(&ca), None, None).unwrap();
        assert_eq!(
            file_read_count(),
            before_reads + 1,
            "a stat change must re-read the file exactly once to re-hash it"
        );
        let _ = build_tls_connector_skip_verify(Some(&ca), None, None).unwrap();
        assert_eq!(
            file_read_count(),
            before_reads + 1,
            "a second dial with an unchanged file must not re-read it"
        );
        assert_eq!(
            connector_build_count(),
            before_builds,
            "unchanged content after a stat change must still hit the connector cache"
        );
    }
}
