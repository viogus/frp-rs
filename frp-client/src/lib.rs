//! frp client daemon (`frpc`) — registers proxies with an frp server, accepts
//! work connections, and bridges traffic to local services.

#[cfg(feature = "admin")]
pub mod admin;
pub mod backoff;
pub mod control;
pub mod health;
pub mod nat_hole;
pub mod plugin;
pub mod proxy;
pub mod proxy_runtime;
pub mod reload;
pub mod service;
pub mod store;
pub(crate) mod util;
pub mod visitor;
#[cfg(feature = "vnet")]
pub mod vnet;
pub mod work_conn;

/// The `[web_server.tls] enable` diagnostic answer for **this crate's** build:
/// whether the admin server is compiled (`admin`) and whether it can serve
/// HTTPS (`tls`).
///
/// Both facts are this crate's, so they are resolved here rather than by
/// `frp-core` (which owns neither feature) or by `frpc` (whose own `tls`
/// feature is off in every default build, because `full` forwards
/// `frp-client/default` — so a `cfg!(feature = "tls")` inside `frpc/src/main.rs`
/// would answer `false` for a build whose admin server does serve HTTPS). It
/// lives in the crate root, not in the `admin` module, because `frpc` asks it
/// in builds that do not compile that module at all.
///
/// The gate it describes is the acceptor in `admin::run_admin_server`:
/// `#[cfg(feature = "tls")]` selects the TLS arm, and the
/// `not(feature = "tls")` arm discards a configured `cert_file` + `key_file`
/// pair.
pub const fn web_server_tls_enable_reader() -> frp_core::config::WebServerTlsEnableReader {
    frp_core::config::WebServerTlsEnableReader::from_features(
        cfg!(feature = "admin"),
        cfg!(feature = "tls"),
    )
}
