use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;

use tracing::{error, info, instrument, warn};

#[cfg(feature = "oidc")]
use frp_core::auth::OidcVerifier;
use frp_core::auth::{AuthConfig, AuthMethod};
use frp_core::config::{AuthServerConfig, ServerConfig};
use frp_core::format_socket_addr;
use frp_core::init_error::ConstructError;
#[cfg(feature = "tls")]
use frp_core::transport::build_tls_acceptor_or_generate;
use frp_core::transport::{detect_and_strip_magic, ConnectionType};
use frp_core::unsafe_features::UnsafeFeatures;

use crate::lock::RwLockExt;

// Re-export state types for backward compatibility.
// All existing `use crate::service::*` imports continue to work.
pub use crate::state::{AppState, ControlTx, InternalMsg, ReloadableState};

// The dedicated `websocket_port` listener. Its 24 `tracing` events therefore
// report target `frp_server::service::listeners` instead of
// `frp_server::service`; `RUST_LOG` target matching is a prefix comparison, so
// a directive such as `RUST_LOG=frp_server::service=debug` still enables them.
//
// The KCP listener block that used to sit inline in `run` moved here the same
// way; its `tracing` events carry the same `frp_server::service::listeners`
// target.
//
// The QUIC listener block moved here the same way too; its `tracing` events
// carry the same `frp_server::service::listeners` target.
//
// The dashboard server block moved here the same way too; its `tracing` events
// carry the same `frp_server::service::listeners` target.
//
// The TCPMux HTTP CONNECT listener block moved here the same way too; its
// `tracing` events carry the same `frp_server::service::listeners` target. As
// the first un-gated seam (`pub mod tcpmux;` is unconditional in `lib.rs`), its
// module gate is gone: every item that can be gated carries its own `#[cfg]`;
// the method and the three imports it needs compile in every shape, ungated.
//
// The SSH tunnel gateway block moved here the same way too; its `tracing` events
// carry the same `frp_server::service::listeners` target. This seam is gated
// (`#[cfg(feature = "ssh")]`), so the method carries that gate itself and the
// call site keeps it. The `read_ok()` the block calls needs `RwLockExt` in its
// new module, so `listeners.rs`'s import gained the `ssh` shape (its gate was
// `tls` + websocket/kcp only); `service.rs` keeps its own ungated import for the
// `write_ok()` calls that stay behind.
//
// The HTTP VHost listener block moved here the same way too; its `tracing` events
// carry the same `frp_server::service::listeners` target. Like the TCPMux seam,
// this block is un-gated (`pub mod vhost;` is unconditional in `lib.rs`), so the
// method is ungated and no import changed: `format_socket_addr`, `error!` and
// `info!` were already unconditional here.
//
// The HTTPS VHost listener block moved here the same way too; its `tracing`
// events carry the same `frp_server::service::listeners` target. This block is
// un-gated as well: `crate::vhost::run_vhost_https_listener` has a
// `#[cfg(not(feature = "tls"))]` stub returning an error
// (`frp-server/src/vhost.rs:1837`), so no gate is needed and no import changed.
mod listeners;

// ---------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------

/// Build an `AuthConfig` from a server config's `auth` sub-struct.
/// Shared by `Service::new()` and `Service::reload()`.
fn build_auth_config(
    auth: &frp_core::config::AuthServerConfig,
    unsafe_features: &UnsafeFeatures,
) -> Result<AuthConfig, String> {
    // The method parse is the shared `frp_core::auth` policy, not a local match:
    // Go compares the method exactly against `SupportedAuthMethods`
    // (`pkg/config/v1/validation/server.go:31`) after `Auth.Complete()` has
    // filled an empty one to `token` (`pkg/config/v1/server.go:136-139`), so
    // nothing but the two names is accepted and no spelling is folded to lower
    // case. The load path already rejects an unrecognised spelling with Go's
    // text (`frp-core/src/config/loader.rs`), so this call is the
    // construction-time backstop for a `ServerConfig` that never went through
    // the loader (the unit tests below build one directly) — it must not be the
    // *first* check, or a bad spelling would reach the exit-3 construction path
    // instead of Go's exit-1 load error.
    //
    // History: this used to be `match auth.method.to_lowercase().as_str()` with
    // `_ => Token`. `"OIDC"` therefore selected OIDC (Go errors) while
    // `" oidc"`, `"oidc "`, `"tokenn"` and the Cyrillic-о lookalike selected
    // **token** — an operator who asked for OIDC got a token-auth server that
    // accepts anyone holding the token.
    let method = frp_core::auth::parse_auth_method(&auth.method)?;
    // The feature refusal is keyed off the *parsed* method, so `"OIDC"` is now
    // an error like Go's rather than (pre-change) OIDC or a feature error.
    // (frp-core's `oidc` can be ON here through feature unification while
    // frp-server's own is off; the feature that matters is the one that supplies
    // the verifier, i.e. this crate's.) The refusal stays ahead of token-source
    // resolution: the method is the decisive reason the config cannot work, so a
    // broken source must neither mask it nor be executed for a config that is
    // going to be rejected.
    if method == AuthMethod::Oidc {
        #[cfg(not(feature = "oidc"))]
        {
            return Err(frp_core::auth::OIDC_FEATURE_REQUIRED.to_string());
        }
    }
    let token_source = auth.token_source.clone();
    let token = if let Some(ref source) = token_source {
        frp_core::config::validate_auth_token_source(&auth.token, &auth.token_source)?;
        frp_core::auth::validate_token_source_unsafe(source, unsafe_features)?;
        source
            .resolve()
            .map_err(|e| format!("failed to resolve auth.tokenSource: {e}"))?
    } else {
        // Go frp v0.70.1: a token-source resolution failure is a startup
        // error — ValueSource.Resolve errors propagate in Go with no
        // empty-token fallback. Match that: a failing dynamic source must
        // not silently degrade auth to an empty token (when both sides'
        // sources fail, that would silently disable auth).
        frp_core::auth::resolve_dynamic_token_checked(&auth.token, unsafe_features)?
    };
    Ok(AuthConfig {
        method,
        token,
        token_source,
        oidc_issuer: auth.oidc_issuer.clone(),
        oidc_audience: auth.oidc_audience.clone(),
        oidc_skip_expiry: auth.oidc_skip_expiry,
        oidc_skip_issuer: auth.oidc_skip_issuer,
        oidc_skip_nbf: auth.oidc_skip_nbf,
        oidc_skip_audience: auth.oidc_skip_audience,
        oidc_additional_audience: auth.oidc_additional_audience.clone(),
        oidc_tls_trusted_ca_file: auth.oidc_tls_trusted_ca_file.clone(),
        additional_data: None,
        oidc_proxy_url: auth.oidc_proxy_url.clone(),
        additional_auth_scopes: auth.additional_auth_scopes.clone(),
        authentication_timeout: auth.authentication_timeout,
        token_auth_timeout: auth.token_auth_timeout,
        use_encryption: auth.use_encryption,
    })
}

/// Whether two `auth.tokenSource` settings differ.
///
/// `frp_core::config::ValueSource` derives `Debug` but not `PartialEq`; the
/// client half of this fix compares its own token source the same way, by
/// `format!("{…:?}")` (`frp-client/src/reload.rs`). Both sides are the same
/// struct type here, so this is a faithful field-for-field comparison; a
/// false "differs" would only re-apply the credential on a reload that did not
/// change it (reported as `auth token updated`), never the reverse.
fn value_source_differs(
    old: &Option<frp_core::config::ValueSource>,
    new: &Option<frp_core::config::ValueSource>,
) -> bool {
    match (old, new) {
        (None, None) => false,
        (Some(o), Some(n)) => format!("{o:?}") != format!("{n:?}"),
        _ => true,
    }
}

/// Resolve the allow-ports ranges from a server config: explicit `allow_ports`
/// spec if present, otherwise the `[allow_port_start, allow_port_end]` range.
/// Shared by `Service::new()` and `Service::reload()`.
fn resolve_allow_ports(cfg: &ServerConfig) -> Vec<frp_core::config::PortsRange> {
    if !cfg.allow_ports.is_empty() {
        // Invalid entries were already rejected by config validation.
        frp_core::config::parse_allow_ports(&cfg.allow_ports).unwrap_or_default()
    } else if cfg.allow_port_start == 0 && cfg.allow_port_end == 0 {
        // Default: no restriction — allow all ports.
        // Go frp compat: when both limits are unset, any port is allowed.
        vec![frp_core::config::PortsRange {
            start: 1,
            end: 65535,
            single: 0,
        }]
    } else {
        vec![frp_core::config::PortsRange {
            start: cfg.allow_port_start,
            end: cfg.allow_port_end,
            single: 0,
        }]
    }
}

/// Resolve the `max_connections` server config into the connection-semaphore
/// size.
///
/// A **delegation**, deliberately: the reload's restart-change list compares this
/// field against its effective value (`frp_core::config::effective_max_connections`,
/// which is this function) so that an absent `max_connections` and an explicit
/// `max_connections = 512` are not reported as a change. A second copy of the
/// rule here would let the semaphore and the comparison drift.
///
/// `Some(0)` means unlimited and MUST resolve to 0 (not `usize::MAX`):
/// `AppState::new` builds `Semaphore::new(n)` whenever n > 0, and tokio
/// panics on `usize::MAX` (batch_semaphore asserts permits <= MAX_PERMITS);
/// with panic=abort in release, `usize::MAX` would crash frps at boot on the
/// documented "0 = unlimited" setting (audit H1). `None` defaults to 512.
fn resolve_max_connections(max_connections: Option<u32>) -> usize {
    frp_core::config::effective_max_connections(max_connections)
}

/// Record a "restart required" change entry when `old != new`. Used by
/// `reload()` for settings that only take effect on a full restart.
fn note_restart_change<T: PartialEq + std::fmt::Display>(
    old: &T,
    new: &T,
    name: &str,
    changes: &mut Vec<String>,
) {
    if *old != *new {
        changes.push(format!("{name}: {old} -> {new} (restart required)"));
    }
}

/// Record an "applied" change entry when `old != new`. Used by `reload()` for
/// the settings it can re-key **in place** — the counterpart of
/// [`note_restart_change`], which marks the ones it can only report.
fn note_applied_change<T: PartialEq + std::fmt::Display>(
    old: &T,
    new: &T,
    name: &str,
    changes: &mut Vec<String>,
) {
    if *old != *new {
        changes.push(format!("{name}: {old} -> {new}"));
    }
}

/// Record every `[auth]` difference a SIGUSR1 reload can only **report**.
///
/// **What this models.** `reload()` applies five `[auth]` fields in place —
/// `auth.token`, `auth.tokenSource`, `auth.additionalAuthScopes` and the two
/// auth timeouts (`auth.authenticationTimeout`, `auth.tokenAuthTimeout`), all of
/// which are read from the *live* `ReloadableState` on the path that uses them
/// (see the apply block there and its per-field reader citations). Those five
/// are ignored here — the `_`-prefixed bindings below — because the apply block
/// reports them against live state. What is left is reported here against `old`,
/// the running config: `auth.method` and the OIDC group (the startup-built
/// verifier's inputs).
///
/// **What keeps it complete.** Both `let AuthServerConfig { … }` patterns
/// below name every field with **no `..`**, so adding (or renaming) a field of
/// [`AuthServerConfig`] makes this function fail to compile — E0027, "pattern
/// does not mention the field" — until the new field is named here and
/// classified. A list of named reads (`old.x != new.x`) has no such property:
/// the client half of this fix measured exactly that on the named-reads shape it
/// had *before* it was rewritten to this same no-`..` destructure — a probe
/// field added to its `[auth]` struct left `cargo check` green and the
/// completeness test passing, i.e. the next `[auth]` field would have been
/// silently accepted as `no changes detected` again
/// (`frp-client/src/reload.rs`, `auth_field_changes`, which now uses the same
/// form). The `_` names keep the "bound but never used" warning off; they must
/// stay in the pattern.
///
/// **What it does not cover.** It compares only the `AuthServerConfig` shape
/// (what `self.cfg.auth` holds), which is not field-for-field the runtime
/// `AuthConfig` — that one carries `additional_data`, which has no config
/// counterpart and therefore cannot differ between two loads of the file, and
/// no `oidc_token_endpoint`. A runtime field with no config counterpart can
/// never be a *reload* difference. It also cannot see a difference the loader
/// normalises away before `reload()` compares (an absent `[auth] method` and
/// `method = ""` are both completed to `"token"`), nor an `[auth]` field that
/// `build_auth_config` never reads at all. It panics on nothing: every value
/// pushed through `note_restart_change` is `PartialEq + Display`, and the OIDC
/// group is a fixed string.
fn note_auth_restart_changes(
    old: &AuthServerConfig,
    new: &AuthServerConfig,
    changes: &mut Vec<String>,
) {
    let AuthServerConfig {
        method: old_method,
        // Applied in place by `reload()` — reported there, against live state.
        token: _old_token,
        token_source: _old_token_source,
        oidc_issuer: old_oidc_issuer,
        oidc_audience: old_oidc_audience,
        oidc_token_endpoint: old_oidc_token_endpoint,
        oidc_skip_expiry: old_oidc_skip_expiry,
        oidc_skip_issuer: old_oidc_skip_issuer,
        oidc_skip_nbf: old_oidc_skip_nbf,
        oidc_skip_audience: old_oidc_skip_audience,
        oidc_additional_audience: old_oidc_additional_audience,
        oidc_tls_trusted_ca_file: old_oidc_tls_trusted_ca_file,
        oidc_proxy_url: old_oidc_proxy_url,
        // Applied in place by `reload()` — see above.
        additional_auth_scopes: _old_additional_auth_scopes,
        // Applied in place by `reload()` — both are read from the live
        // `auth_cfg` on every use (see the apply block's reader citations).
        authentication_timeout: _old_authentication_timeout,
        token_auth_timeout: _old_token_auth_timeout,
        // **Neither applied nor reported**, deliberately, and this is the one
        // `[auth]` field with that disposition: nothing on the server ever reads
        // `AuthConfig::use_encryption` (the only writer is `build_auth_config`
        // above; every other `use_encryption` in this crate is a *different*
        // field — `ProxyInfo`/`NewVisitorConn`/`ssh_gateway`), and Go's
        // `AuthServerConfig` has no such field at all
        // (`pkg/config/v1/server.go:129-135`; `UseEncryption` is `proxy.go:32`
        // and `visitor.go:25`). So a restart cannot make a change to it take
        // effect either — reporting it "restart required" would be a false
        // statement, and there is no running value for it to disagree with.
        use_encryption: _old_use_encryption,
    } = old;
    let AuthServerConfig {
        method: new_method,
        token: _new_token,
        token_source: _new_token_source,
        oidc_issuer: new_oidc_issuer,
        oidc_audience: new_oidc_audience,
        oidc_token_endpoint: new_oidc_token_endpoint,
        oidc_skip_expiry: new_oidc_skip_expiry,
        oidc_skip_issuer: new_oidc_skip_issuer,
        oidc_skip_nbf: new_oidc_skip_nbf,
        oidc_skip_audience: new_oidc_skip_audience,
        oidc_additional_audience: new_oidc_additional_audience,
        oidc_tls_trusted_ca_file: new_oidc_tls_trusted_ca_file,
        oidc_proxy_url: new_oidc_proxy_url,
        additional_auth_scopes: _new_additional_auth_scopes,
        authentication_timeout: _new_authentication_timeout,
        token_auth_timeout: _new_token_auth_timeout,
        use_encryption: _new_use_encryption,
    } = new;

    // `auth.method` picks which credential is authoritative, so it is the one
    // restart-only field reported with its direction (`token -> oidc`): the
    // pair is a closed, non-secret set, and "which method is actually live" is
    // the question an operator asking about a reload is trying to answer.
    // Values, not just the name — but only for this field; see the OIDC group
    // below for why the rest are value-free.
    note_restart_change(old_method, new_method, "auth.method", changes);

    // The OIDC verifier is built once, in `Service::with_unsafe_features`,
    // from exactly these fields (`OidcVerifier::new`): issuer, audience, the
    // three skips it forwards, `oidc_additional_audience`, the CA file and the
    // proxy URL. A change to any of them cannot reach the running verifier, so
    // the whole group reports the one line this reload has always printed for
    // it. `oidc_token_endpoint` is grouped here too: it is an `[auth]` OIDC
    // setting that this arm did not compare at all before, and grouping it
    // says "restart required" without claiming the verifier reads it.
    //
    // A fixed string, no values: `oidc_tls_trusted_ca_file` is a path and
    // `oidc_proxy_url` may carry `user:pass@`, and this summary is logged and
    // echoed back through the reload path — the client half of this fix uses
    // the same rule ("names only, never a token or secret value",
    // `frp-client/src/reload.rs`).
    if old_oidc_issuer != new_oidc_issuer
        || old_oidc_audience != new_oidc_audience
        || old_oidc_token_endpoint != new_oidc_token_endpoint
        || old_oidc_skip_expiry != new_oidc_skip_expiry
        || old_oidc_skip_issuer != new_oidc_skip_issuer
        || old_oidc_skip_nbf != new_oidc_skip_nbf
        || old_oidc_skip_audience != new_oidc_skip_audience
        || old_oidc_additional_audience != new_oidc_additional_audience
        || old_oidc_tls_trusted_ca_file != new_oidc_tls_trusted_ca_file
        || old_oidc_proxy_url != new_oidc_proxy_url
    {
        changes.push("OIDC settings changed (restart required)".to_string());
    }

    // What this function reports is what is left: `auth.method` and the OIDC
    // group, both above. The auth timeouts are **not** here: they are
    // live-read, so the apply block re-keys them in place and reports them
    // there, and `auth.useEncryption` is not here because nothing reads it.
}

/// Print every restart-only `ServerConfig` difference a `SIGUSR1` reload can
/// only **report** — the `ServerConfig`-shaped counterpart of
/// [`note_auth_restart_changes`], called next to it from `reload()`.
///
/// **The list itself** is [`ServerConfig::restart_only_changes`]
/// (`frp-core/src/config/restart_only.rs`), which destructures both configs with
/// **no `..`** — so adding or renaming a field of `ServerConfig`, or of one of
/// its sub-structs, is a compile error (E0027) until the new field is named and
/// classified. A list of named reads (`old.x != new.x`) has no such property: the
/// client half of this series measured exactly that on the named-reads shape it
/// had before it was rewritten to a no-`..` destructure.
///
/// **Why the list is not here.** Three `ServerConfig` fields (`kcp_bind_port`,
/// `quic_bind_port`, `websocket_port`) are `#[cfg]`-gated on **frp-core's**
/// features, while a pattern written in this crate could only be gated on *this*
/// crate's — and Cargo unifies the two independently. Measured on a draft of this
/// list that lived here: `cargo test -p frp-server --no-default-features
/// --all-targets` (`.github/workflows/ci.yml`) failed to compile with E0027
/// (`pattern does not mention fields kcp_bind_port, quic_bind_port,
/// websocket_port`) because the `frp-client` dev-dependency turns `frp-core/kcp`
/// on while `frp-server/kcp` is off, and the mirror case
/// (`cargo check --workspace --no-default-features --features tiny`, same file)
/// has the field absent, where an unconditional pattern entry would be E0026. In
/// `frp-core` the gates match the struct exactly.
///
/// **What stays here** is the part this crate owns: whether the field's only
/// reader is compiled into this build, and the wording of the summary line.
/// `name_only` entries print no values at all: they are credential-shaped
/// (`web_server.password`, `http_plugins`).
fn note_restart_changes(old: &ServerConfig, new: &ServerConfig, changes: &mut Vec<String>) {
    for change in old.restart_only_changes(new) {
        if !server_reader_present(change.reader) {
            continue;
        }
        if change.name_only {
            changes.push(format!("{} changed (restart required)", change.name));
        } else {
            changes.push(format!(
                "{}: {} -> {} (restart required)",
                change.name, change.old, change.new
            ));
        }
    }
}

/// Whether this build contains the only reader a restart-only field has.
///
/// `ServerReader` is `frp-core`'s classification of *which* build feature a
/// field's reader needs; this crate owns the features, so it resolves them here
/// (`Service::run`'s dashboard, SSH-gateway and QUIC blocks). The one gate that
/// is not this crate's is `Otel`: that reader is `frps`'s `init_logging`, gated
/// on the binary's `otel` feature, which forwards `frp-core/otel`. `frp-server`
/// declares no `otel` feature of its own, so a `#[cfg(feature = "otel")]` here
/// would be constant `false`; `frp_core::logging::OTEL_ENABLED` is the same
/// question asked where the feature lives. It tracks `frp-core`, so a build that
/// enables `frp-core/otel` through another member while the binary under test
/// does not would report this group anyway — recorded in the change report.
fn server_reader_present(reader: frp_core::config::ServerReader) -> bool {
    use frp_core::config::ServerReader;
    match reader {
        ServerReader::Any => true,
        ServerReader::Dashboard => cfg!(feature = "dashboard"),
        ServerReader::Ssh => cfg!(feature = "ssh"),
        // The three listener ports: `frp-core`'s features decide whether the
        // *field* exists, these decide whether anything reads it.
        ServerReader::Kcp => cfg!(feature = "kcp"),
        ServerReader::Quic => cfg!(feature = "quic"),
        ServerReader::Websocket => cfg!(feature = "websocket"),
        ServerReader::Otel => frp_core::logging::OTEL_ENABLED,
    }
}

/// The `[web_server.tls] enable` diagnostic answer for **this crate's** build:
/// whether the dashboard is compiled (`dashboard`) and whether this crate can
/// serve it over HTTPS (`tls`).
///
/// The sibling of [`server_reader_present`]: this crate owns both features, so
/// it resolves them here instead of letting a binary's `cfg!` answer for it.
/// `frps`'s own `tls` feature is off in every default build (`full` forwards
/// `frp-server/default`), so a `cfg!(feature = "tls")` inside `frps/src/main.rs`
/// would say `false` for a build whose dashboard does serve HTTPS. The gate is
/// the dashboard's acceptor, compiled behind `#[cfg(feature = "tls")]`
/// (`frp-server/src/dashboard.rs`, `frp-server/src/service.rs`).
pub const fn web_server_tls_enable_reader() -> frp_core::config::WebServerTlsEnableReader {
    frp_core::config::WebServerTlsEnableReader::from_features(
        cfg!(feature = "dashboard"),
        cfg!(feature = "tls"),
    )
}

/// Whether **this crate** compiles the reader of `web_server.port` — the
/// `dashboard` feature (`frp-server/src/dashboard.rs`, spawned from
/// `Service::new` / `Service::run` when the port is non-zero).
///
/// The field is unconditional in `frp-core`'s `ServerConfig`, so `frp-core`
/// cannot tell an honoured port from an inert one; this crate can. The answer is
/// handed to `ConfigPresence::warn_inert_web_server_port`, which emits the
/// "nothing reads the key" record only for `Absent`. A binary-local `cfg!` would
/// be wrong for the same reason as [`web_server_tls_enable_reader`]'s.
pub const fn web_server_port_reader() -> frp_core::config::ListenerPortReader {
    frp_core::config::ListenerPortReader::from_features(cfg!(feature = "dashboard"))
}

/// The `ssh_tunnel_gateway.bind_port` twin of [`web_server_port_reader`]: this
/// crate's `ssh` feature gates the SSH gateway listener
/// (`frp-server/src/service.rs`, `if self.cfg.ssh_tunnel_gateway.bind_port > 0`).
pub const fn ssh_tunnel_gateway_bind_port_reader() -> frp_core::config::ListenerPortReader {
    frp_core::config::ListenerPortReader::from_features(cfg!(feature = "ssh"))
}

/// Whether **this crate** compiles the reader of `kcp_bind_port` — its own `kcp`
/// feature, which gates the KCP listener (`frp-server/src/service/listeners.rs`).
///
/// The field is `#[cfg(feature = "kcp")]`-gated in `frp-core`'s `ServerConfig`,
/// and Cargo unifies the two crate features independently: `frp-server/kcp =
/// ["frp-core/kcp"]` moves them together one way, so a caller who names the
/// inner feature by hand
/// (`cargo build -p frps --no-default-features --features tiny,frp-core/kcp`)
/// gets the parser and the field without this crate's listener. `frp-core`
/// cannot observe this crate's feature, so the answer is resolved here and handed
/// to `ConfigPresence::warn_unhonoured_server_feature_keys`. A binary-local
/// `cfg!` would be wrong for the same reason as
/// [`web_server_tls_enable_reader`]'s (`frps/kcp` forwards
/// `frp-server/kcp`, so the binary's own flag is a third, independently
/// forwarded switch).
pub const fn kcp_bind_port_reader() -> frp_core::config::ListenerPortReader {
    frp_core::config::ListenerPortReader::from_features(cfg!(feature = "kcp"))
}

/// The `quic_bind_port` twin of [`kcp_bind_port_reader`]: this crate's `quic`
/// feature gates the QUIC listener.
pub const fn quic_bind_port_reader() -> frp_core::config::ListenerPortReader {
    frp_core::config::ListenerPortReader::from_features(cfg!(feature = "quic"))
}

/// The `websocket_port` twin of [`kcp_bind_port_reader`]: this crate's
/// `websocket` feature gates the WebSocket listener. There is no
/// `--websocket-port` flag, so this reader is only ever consulted for the file
/// key.
pub const fn websocket_port_reader() -> frp_core::config::ListenerPortReader {
    frp_core::config::ListenerPortReader::from_features(cfg!(feature = "websocket"))
}

/// All three feature-gated listener-port answers at once, from **this crate's**
/// gates — the value `frps` and this crate's reload path hand to
/// `ConfigPresence::warn_unhonoured_server_feature_keys`.
///
/// One combined constructor rather than three call sites so the three cannot be
/// swapped: `kcp_bind_port` and `quic_bind_port` have the same type, and a
/// `kcp_bind_port_reader()` passed where the QUIC reader was meant would be a
/// silent, shape-dependent wrong answer.
pub const fn gated_listener_port_readers() -> frp_core::config::GatedListenerPortReaders {
    frp_core::config::GatedListenerPortReaders::from_features(
        cfg!(feature = "kcp"),
        cfg!(feature = "quic"),
        cfg!(feature = "websocket"),
    )
}

/// Spawn a boxed future with type erasure. Reduces binary size by
/// preventing monomorphization of `tokio::spawn` for every concrete
/// future type — the unsizing coercion from `Pin<Box<ConcreteFut>>`
/// to `Pin<Box<dyn Future<...> + Send>>` ensures `tokio::spawn` is
/// specialized for the single pointer-sized `dyn` type.
fn spawn_boxed(fut: Pin<Box<dyn Future<Output = ()> + Send + 'static>>) {
    tokio::spawn(fut);
}

// ---------------------------------------------------------------
// Service
// ---------------------------------------------------------------

pub struct Service {
    cfg: ServerConfig,
    state: Arc<AppState>,
    /// Path to config file for SIGUSR1 reload.
    config_file: Option<String>,
    unsafe_features: UnsafeFeatures,
}

impl Service {
    /// Create a new Service with default unsafe features (all blocked).
    pub async fn new(
        cfg: ServerConfig,
        config_file: Option<String>,
    ) -> Result<Self, ConstructError> {
        Self::with_unsafe_features(cfg, config_file, UnsafeFeatures::default()).await
    }

    /// Create a new Service with a custom unsafe features allowlist.
    /// Use this when `--allow-unsafe` CLI flag is provided.
    ///
    /// The error is a [`ConstructError`], whose [`ConstructError::kind`] is the
    /// *only* thing the daemon turns into a process exit code (it never looks at
    /// the message). See `frp-core/src/init_error.rs` for why.
    pub async fn with_unsafe_features(
        cfg: ServerConfig,
        config_file: Option<String>,
        unsafe_features: UnsafeFeatures,
    ) -> Result<Self, ConstructError> {
        // Every failure below is an auth construction failure (the server's
        // whole pre-run surface is auth: the token source, the token/oidc
        // startup checks, and the OIDC verifier), so all of them are tagged
        // explicitly at the raise site rather than left to the `From` default.
        let auth_cfg =
            build_auth_config(&cfg.auth, &unsafe_features).map_err(ConstructError::auth)?;
        auth_cfg
            .check_startup()
            .map_err(|e| ConstructError::auth(format!("security misconfiguration: {e}")))?;

        #[cfg(feature = "oidc")]
        let oidc_verifier = if auth_cfg.method == AuthMethod::Oidc {
            match OidcVerifier::new(
                auth_cfg.oidc_issuer.clone(),
                auth_cfg.oidc_audience.clone(),
                auth_cfg.oidc_skip_expiry,
                auth_cfg.oidc_skip_issuer,
                auth_cfg.oidc_skip_nbf,
                auth_cfg.oidc_skip_audience,
                auth_cfg.oidc_additional_audience.clone(),
                Some(auth_cfg.oidc_tls_trusted_ca_file.clone()).filter(|s| !s.is_empty()),
                Some(auth_cfg.oidc_proxy_url.clone()).filter(|s| !s.is_empty()),
            )
            .await
            {
                Ok(v) => {
                    info!(issuer = %auth_cfg.oidc_issuer, "OIDC verifier initialized (issuer: {})", auth_cfg.oidc_issuer);
                    let v = Arc::new(v);
                    v.start_background_refresh();
                    Some(v)
                }
                Err(e) => {
                    error!(error = %e, "OIDC verifier initialization failed: {e}");
                    return Err(ConstructError::auth(format!(
                        "Cannot start frps with OIDC auth: {e}"
                    )));
                }
            }
        } else {
            None
        };
        #[cfg(not(feature = "oidc"))]
        let oidc_verifier = None;

        let enc_key = frp_core::encryption::derive_key(&auth_cfg.token);
        let allow_ports = resolve_allow_ports(&cfg);
        let sub_host = cfg.sub_domain_host.clone();
        let max_connections = resolve_max_connections(cfg.max_connections);
        // Same effective-value function the reload's comparison uses, so the
        // limiter and the report cannot disagree about what "unset" means.
        let max_accept_rate = frp_core::config::effective_max_accept_rate(cfg.max_accept_rate);
        let mut state = AppState::new(
            auth_cfg,
            if cfg.proxy_bind_addr.is_empty() {
                cfg.bind_addr.clone()
            } else {
                cfg.proxy_bind_addr.clone()
            },
            enc_key,
            allow_ports,
            sub_host,
            cfg.transport.tcp_mux.unwrap_or(true),
            cfg.transport.tcp_mux_keepalive_interval,
            frp_core::mux::idle_dead_timeout_from_secs(cfg.transport.tcp_mux_keepalive_timeout),
            cfg.transport.tcp_keepalive,
            cfg.transport.tcp_send_buffer_size,
            cfg.transport.tcp_recv_buffer_size,
            cfg.transport.heartbeat_timeout,
            cfg.udp_packet_size,
            cfg.tls_only,
            oidc_verifier,
            cfg.sudp_port,
            cfg.vhost_http_timeout,
            cfg.user_conn_timeout,
            cfg.tcp_mux_passthrough,
            {
                // Go frp compat: custom_404_page is a file path, not inline HTML.
                // Try to read the file; if it doesn't exist, log a warning and
                // treat the value as inline HTML (backward-compatible fallback).
                let page_path = cfg.web_server.custom_404_page.clone();
                if page_path.is_empty() {
                    String::new()
                } else {
                    match std::fs::read_to_string(&page_path) {
                        Ok(content) => content,
                        Err(e) => {
                            if e.kind() == std::io::ErrorKind::NotFound {
                                tracing::warn!(
                                    path = %page_path,
                                    "custom_404_page file not found, using value as inline HTML"
                                );
                            } else {
                                tracing::warn!(
                                    path = %page_path,
                                    error = %e,
                                    "failed to read custom_404_page file, using value as inline HTML"
                                );
                            }
                            page_path
                        }
                    }
                }
            },
            Arc::new(crate::plugin::HttpPluginManager::new(
                cfg.http_plugins.clone(),
            )),
            cfg.max_ports_per_client,
            cfg.max_conns_per_proxy,
            cfg.max_proxies_per_client,
            cfg.nat_hole_analysis_data_reserve_hours,
            cfg.detailed_errors_to_client,
            max_connections,
            max_accept_rate,
            frp_core::config::ServerConfigSnapshot::from_config(&cfg),
        );

        // Initialize prometheus registry when enabled
        #[cfg(feature = "dashboard")]
        if cfg.web_server.port > 0 && cfg.web_server.enable_prometheus {
            crate::metrics::prom::register_all();
        }

        // Load persisted proxy configs from the store file
        let store_path = crate::store::resolve_store_path(&config_file);
        let loaded = crate::store::load_store(&store_path);
        if !loaded.is_empty() {
            let mut store = state.proxy_config_store.write().await;
            for (name, config) in loaded {
                store.entry(name).or_insert(config);
            }
            info!(count = store.len(), path = %store_path.display(),
                "loaded {} stored proxy configs", store.len());
        }
        state.store_path = Some(store_path);

        Ok(Self {
            state: Arc::new(state),
            cfg,
            config_file,
            unsafe_features,
        })
    }

    /// Get a clone of the shared AppState (for tests and introspection).
    pub fn state(&self) -> std::sync::Arc<AppState> {
        self.state.clone()
    }

    #[instrument(skip(self), fields(bind_addr = %self.cfg.bind_addr, bind_port = %self.cfg.bind_port))]
    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        let bind_addr = format_socket_addr(&self.cfg.bind_addr, self.cfg.bind_port);
        info!(bind_addr = %bind_addr, "frps starting on {}", bind_addr);

        #[cfg(feature = "tls")]
        {
            // Always initialize a TLS acceptor — Go frp auto-generates a
            // self-signed cert even without explicit TLS config, because
            // Go frpc may send TLS ClientHello (0x16/0x17) by default.
            let ca_file = if self.cfg.tls_ca_file.is_empty() {
                None
            } else {
                Some(self.cfg.tls_ca_file.as_str())
            };
            let acceptor = match build_tls_acceptor_or_generate(
                &self.cfg.tls_cert_file,
                &self.cfg.tls_key_file,
                ca_file,
            ) {
                Ok(acc) => {
                    if self.cfg.tls_cert_file.is_empty() {
                        info!("TLS enabled with auto-generated self-signed certificate");
                    } else {
                        info!(cert_file = %self.cfg.tls_cert_file, "TLS enabled with cert: {}", self.cfg.tls_cert_file);
                    }
                    acc
                }
                Err(e) => {
                    error!(error = %e, "Failed to initialize TLS: {}", e);
                    return Err(e.into());
                }
            };
            // Store in shared state for hot-reload access.
            *self.state.tls_acceptor.write_ok() = Some(acceptor);
        }
        #[cfg(not(feature = "tls"))]
        let _tls_acceptor: Option<()> = None;

        let max_accept_rate = frp_core::config::effective_max_accept_rate(self.cfg.max_accept_rate);
        // Hoisted accept-rate-limiter gate: when max_accept_rate == 0 the
        // limiter is a no-op (rate 0.0 → try_acquire always Ok), so skip
        // taking the mutex on every accept. The limiter never changes after
        // startup, so this is computed once per listener task.
        let rate_limiter_enabled = max_accept_rate > 0;
        let listener = TcpListener::bind(&bind_addr).await?;
        info!(bind_addr = %bind_addr, "frps listener started on {}", bind_addr);

        // Optional WebSocket listener
        #[cfg(feature = "websocket")]
        self.start_websocket_listener(rate_limiter_enabled).await;

        // Start HTTP VHost listener if configured. Go frp binds vhost
        // listeners on proxyBindAddr when set (pkg/server/service.go).
        self.start_http_vhost_listener().await;

        // Start HTTPS VHost listener if configured
        // Go frp starts the HTTPS vhost listener whenever vhostHTTPSPort is
        // configured; the shared TLS acceptor auto-generates a server identity
        // when no cert/key files are set.
        self.start_https_vhost_listener().await;

        // Start TCPMux HTTP CONNECT listener if configured
        self.start_tcpmux_listener().await;

        // Start SSH tunnel gateway if configured
        #[cfg(feature = "ssh")]
        self.start_ssh_tunnel_gateway().await;

        // Start KCP listener if configured
        #[cfg(feature = "kcp")]
        self.start_kcp_listener(rate_limiter_enabled).await;

        // Start QUIC listener if configured (auto-generates self-signed TLS cert if needed)
        #[cfg(feature = "quic")]
        self.start_quic_listener(rate_limiter_enabled).await;

        // Start dashboard server if configured
        #[cfg(feature = "dashboard")]
        self.start_dashboard_listener().await;

        // Background cleanup for stale NAT hole punch sessions.
        // Sessions should normally be completed by the provider's NatHoleReport,
        // but if the provider crashes or the network drops, this ensures sessions
        // older than 2 minutes don't leak memory.
        let nat_hole = self.state.xtcp.nat_hole.clone();
        let nat_shutdown_token = self.state.shutdown_token.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        nat_hole.expire_sessions(Duration::from_secs(120)).await;
                        // Clean expired analyzer entries to prevent unbounded memory growth.
                        let (removed, total) = nat_hole.analyzer.clean();
                        if removed > 0 {
                            tracing::debug!(removed = %removed, total = %total, "Analyzer cleanup: removed {}/{} expired entries", removed, total);
                        }
                    }
                    _ = nat_shutdown_token.cancelled() => {
                        tracing::debug!("NAT cleanup task: shutdown requested, stopping");
                        break;
                    }
                }
            }
        });

        // Periodic port-reservation pruner: sweep 24h-expired entries so stale
        // reservations don't block port reuse. Same 60s cadence as NAT cleanup.
        self.state
            .clone()
            .spawn_port_reservation_pruner(self.state.shutdown_token.clone());

        // Periodic TLS certificate hot-reload: stat cert/key files every 60 seconds.
        // When mtimes change (e.g., certbot/cert-manager renews in-place), rebuild
        // the acceptor and atomically swap so new connections use the new cert
        // without a restart.
        #[cfg(feature = "tls")]
        {
            let poll_state = self.state.clone();
            let cert_file = self.cfg.tls_cert_file.clone();
            let key_file = self.cfg.tls_key_file.clone();
            let ca_file = if self.cfg.tls_ca_file.is_empty() {
                None
            } else {
                Some(self.cfg.tls_ca_file.clone())
            };
            tokio::spawn(async move {
                let mut last_cert_mtime: Option<std::time::SystemTime> = None;
                let mut last_key_mtime: Option<std::time::SystemTime> = None;
                let mut interval = tokio::time::interval(Duration::from_secs(60));
                // Skip the first tick (fires immediately).
                interval.tick().await;
                loop {
                    tokio::select! {
                        _ = interval.tick() => {
                            // Stat cert and key files. If either mtime changed, rebuild.
                            let cert_meta = match std::fs::metadata(&cert_file) {
                                Ok(m) => m,
                                Err(_) => continue,
                            };
                            let key_meta = match std::fs::metadata(&key_file) {
                                Ok(m) => m,
                                Err(_) => continue,
                            };
                            let cert_mtime = cert_meta.modified().ok();
                            let key_mtime = key_meta.modified().ok();
                            let cert_changed = cert_mtime != last_cert_mtime;
                            let key_changed = key_mtime != last_key_mtime;
                            if cert_changed || key_changed {
                                last_cert_mtime = cert_mtime;
                                last_key_mtime = key_mtime;
                                let ca = ca_file.as_deref();
                                match build_tls_acceptor_or_generate(&cert_file, &key_file, ca) {
                                    Ok(new_acceptor) => {
                                        let mut guard = poll_state.tls_acceptor.write_ok();
                                        *guard = Some(new_acceptor);
                                        tracing::info!(
                                            "TLS certificate hot-reloaded (cert: {}, key: {})",
                                            cert_file,
                                            key_file
                                        );
                                    }
                                    Err(e) => {
                                        tracing::error!(
                                            "Failed to reload TLS certificate: {} (keeping old config)",
                                            e
                                        );
                                    }
                                }
                            }
                        }
                        _ = poll_state.shutdown_token.cancelled() => {
                            tracing::debug!("TLS hot-reload task: shutdown requested, stopping");
                            break;
                        }
                    }
                }
            });
        }

        // Main accept loop — mixed-mode: TLS, WebSocket, and V1 on same port.
        // Uses MSG_PEEK to detect connection type without consuming bytes,
        // matching Go frp v0.69.1 behavior.

        // Spawn signal listener for graceful shutdown.
        // ctrl_c() only catches SIGINT; SIGTERM needs an explicit unix signal
        // handler (docker stop / systemctl stop send SIGTERM).
        let shutdown_token = self.state.shutdown_token.clone();
        tokio::spawn(async move {
            #[cfg(unix)]
            {
                // SIGTERM → graceful shutdown (docker stop / systemctl stop
                // send SIGTERM; ctrl_c() alone only catches SIGINT).
                let mut term_sig =
                    match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    {
                        Ok(s) => Some(s),
                        Err(e) => {
                            tracing::warn!(error = %e, "SIGTERM handler unavailable: {}", e);
                            None
                        }
                    };
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {
                        info!("Received SIGINT, initiating graceful shutdown...");
                    }
                    _ = async {
                        if let Some(sig) = term_sig.as_mut() {
                            sig.recv().await;
                        } else {
                            std::future::pending::<()>().await;
                        }
                    } => {
                        info!("Received SIGTERM, initiating graceful shutdown...");
                    }
                }
            }
            #[cfg(not(unix))]
            {
                tokio::signal::ctrl_c().await.ok();
                info!("Received SIGINT, initiating graceful shutdown...");
            }
            shutdown_token.cancel();
        });

        // Stale-control reaper: run_id_to_ctl_tx entries whose receiver has
        // been dropped (control handler panicked / exited without running
        // unregister_control) would otherwise linger forever and dispatch
        // work-conns into a dead channel. Sweep every 60s.
        let state = self.state.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                // Stop promptly on graceful shutdown (port-reservation pruner
                // pattern): the drain path cancels control handlers whose
                // cleanup() already runs unregister_control, so a final sweep
                // here would be both unnecessary and a teardown-linger.
                tokio::select! {
                    _ = interval.tick() => {}
                    _ = state.shutdown_token.cancelled() => return,
                }
                let stale: Vec<(String, u64)> = state
                    .run_id_to_ctl_tx
                    .iter()
                    .filter(|r| r.tx.is_closed())
                    .map(|r| (r.key().clone(), r.control_id))
                    .collect();
                for (run_id, control_id) in stale {
                    // Atomically remove only if the entry still belongs to the
                    // same generation: remove_if compares inside the shard
                    // lock, so a superseding control that registered a fresh
                    // sender for this run_id is never removed by this sweep
                    // (a get-then-remove would race with re-login).
                    let removed = state
                        .run_id_to_ctl_tx
                        .remove_if(&run_id, |_, cur| cur.control_id == control_id);
                    if removed.is_some() {
                        state
                            .client_registry
                            .mark_offline_by_run_id_and_control_id(&run_id, control_id);
                        // The handler exited WITHOUT running cleanup()
                        // (panic/abort), so its registrations would otherwise
                        // leak permanently: used_ports/used_udp_ports,
                        // sk_index, vhost/tcpmux routes, TCP-group listeners,
                        // per-client port counts, OIDC subjects, metrics, and
                        // the proxy registry entries. Run the full
                        // unregister_control sweep. Double-call safety: when
                        // cleanup() DID run it removes the map entry first, so
                        // remove_if above returned None and this code never
                        // runs; unregister_control is also generation-guarded
                        // (control_id) with per-proxy ownership re-checks, so
                        // it can never tear down a superseding control's fresh
                        // registrations (control_id >= 1 always, the counter
                        // starts at 1).
                        crate::control::proxy_ops::unregister_control(
                            &state, &run_id, control_id, false, true,
                        )
                        .await;
                        // Remove the proxy registry entries (mirroring
                        // control::cleanup): unregister_control deliberately
                        // leaves proxy_manager.remove() to the caller because
                        // the https SNI-sniff gate count must only be
                        // decremented when an entry was actually removed
                        // (proxy_ops.rs note). Atomic generation-guarded
                        // removal: remove_if_control_id compares control_id
                        // inside the shard lock, so a superseding control
                        // that re-registered this name between the sweep
                        // list and the removal keeps its entry (round-7
                        // audit MEDIUM — the previous get-then-remove raced
                        // re-login and could destroy the fresh registration).
                        // The removed entry's own type drives the https
                        // gate-count decrement, so no separate get is needed.
                        let proxy_names =
                            state.proxy_manager.list_client_proxy_names(&run_id).await;
                        for name in proxy_names {
                            if let Some(removed) = state
                                .proxy_manager
                                .remove_if_control_id(&name, control_id)
                                .await
                            {
                                if removed.proxy_type == "https" {
                                    state.dec_https_proxy_count();
                                }
                            }
                        }
                        // OIDC subject mapping for this run_id: unregister_
                        // control only clears it when IT removed the
                        // run_id_to_ctl_tx entry (removed_control_id), but
                        // this sweep's remove_if deleted that entry first, so
                        // the (subject, generation) entry would leak forever
                        // for an OIDC client that never reconnects. Clear it
                        // directly — generation-guarded inside the lock, so a
                        // newer control's subject entry survives (round-7
                        // audit LOW).
                        crate::control::login::remove_oidc_subject_generation(
                            &state, &run_id, control_id,
                        )
                        .await;
                        // Plugin user-info entry for this run_id: same leak
                        // shape as the OIDC subject above. unregister_control
                        // only drops it when IT removed the run_id_to_ctl_tx
                        // entry (removed_control_id), but this sweep's
                        // remove_if deleted that entry first, so the
                        // generation guard fails there and remove_user is
                        // skipped — the plugin `users` map (http.rs:97-101,
                        // "bounded by live controls") would otherwise grow by
                        // one entry per control that exited without a clean
                        // unregister: exactly the path this reaper exists
                        // for.
                        //
                        // Same-run_id reconnect guard: a control that died
                        // uncleanly and reconnected with the SAME run_id (frpc
                        // reuses its run_id) between the sweep's remove_if and
                        // here may be mid-login. login.rs records the plugin
                        // user entry AFTER its run_id_to_ctl_tx insert (same
                        // run_mu critical section — audit-fix ordering), so a
                        // fresh record only exists once a fresh generation is
                        // registered. remove_user is now generation-exact —
                        // the users map stores (control_id, UserInfo) and the
                        // entry is removed only when it still holds THIS
                        // sweep's control_id (remove-if-match under the users
                        // map's write lock) — so even an unconditional call
                        // here could no longer delete the record of a control
                        // that re-logged in with a fresh control_id (the old
                        // comment's "re-recorded on the next login hook"
                        // claim was wrong: that login already ran).
                        //
                        // Round-4 audit finding: the re-check and remove_user
                        // used to be two separate steps, so a same-run_id
                        // re-login's insert+record (login.rs, under its own
                        // run_mu — which the reaper did not hold) could land
                        // between them and delete the fresh record. The
                        // generation-exact remove_user closes that window
                        // structurally. Hold the per-run_id run_mu across
                        // both steps anyway, mirroring the login path's
                        // acquisition and lock order (run_mu →
                        // run_id_to_ctl_tx → users RwLock; the reaper
                        // otherwise takes no run_mu and no path takes the
                        // users lock then run_mu, so no inversion) — defense
                        // in depth, not the sole guard: a re-login either
                        // completed before us (its fresh generation is
                        // visible in the re-check below → skip) or is queued
                        // on run_mu until this removal is done (its record is
                        // not yet made → remove_user cannot delete it). With
                        // run_mu held, re-check run_id_to_ctl_tx: a NEWER
                        // control_id → the fresh control re-logged in and its
                        // record is in place → skip; no entry (or still the
                        // swept generation) → remove_user (leak fix stands;
                        // the generation-exact entry check makes even a
                        // racing re-login's fresh record immune).
                        let (run_mu, _run_mu_guard) = state.get_run_mu(&run_id);
                        let reaper_run_guard = run_mu.lock().await;
                        let fresh_generation_present = state
                            .run_id_to_ctl_tx
                            .get(&run_id)
                            .is_some_and(|cur| cur.control_id != control_id);
                        if !fresh_generation_present {
                            state.plugin_manager.remove_user(&run_id, control_id);
                        }
                        drop(reaper_run_guard);
                        tracing::info!(
                            run_id = %run_id,
                            "removed stale control entry (handler died)"
                        );
                    }
                }
            }
        });

        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                Ok((stream, addr)) => {
                    frp_core::transport::set_nodelay(&stream);
                    if self.state.tcp_keepalive > 0 {
                        frp_core::transport::set_keepalive(
                            &stream,
                            self.state.tcp_keepalive as u64,
                        );
                    }
                    frp_core::transport::set_send_recv_buffer(
                        &stream,
                        self.state.tcp_send_buffer_size,
                        self.state.tcp_recv_buffer_size,
                    );
                    let state = self.state.clone();

                    let permit = state.conn_semaphore.as_ref()
                        .and_then(|s| s.clone().try_acquire_owned().ok());
                    if permit.is_none() && state.conn_semaphore.is_some() {
                        warn!(addr = %addr, "Max connections reached, rejecting connection from {}", addr);
                        continue;
                    }
                    // Rate limit: the limiter is lock-free (AtomicU64 CAS),
                    // so no guard is held across any .await boundary. When
                    // disabled (max_accept_rate == 0) skip the call entirely
                    // — the limiter is a no-op.
                    let rate_wait = if rate_limiter_enabled {
                        state.accept_rate_limiter.try_acquire().err()
                    } else {
                        None
                    };
                    if let Some(wait) = rate_wait {
                        warn!(addr = %addr, wait_ms = wait.as_millis(), "accept rate limit reached ({} conn/s), delaying {}ms", max_accept_rate, wait.as_millis());
                        // The connection is being delayed, not accepted — do not
                        // hold a conn_semaphore slot while we wait (parity with
                        // the vhost/tcpmux accept loops).
                        drop(permit);
                        tokio::time::sleep(wait).await;
                        continue;
                    }
                    spawn_boxed(Box::pin(async move {
                        // Connection read deadline: wrap the initial message
                        // detection (detect_and_strip_magic) with a timeout.
                        // Matches Go frp's SetReadDeadline(10s) before reading
                        // any data from a new connection (server/service.go:557).
                        // Single absolute deadline from task start covering the whole
                        // initial read phase (magic + TLS detection + first message),
                        // matching Go's single connReadTimeout deadline.
                        let accept_deadline = tokio::time::Instant::now() + Duration::from_secs(10);
                        let _permit = permit;
                        let (ct, stream_io) = match tokio::time::timeout_at(
                            accept_deadline,
                            detect_and_strip_magic(stream),
                        )
                        .await
                        {
                            Ok(Ok((c, s))) => (c, s),
                            Ok(Err(e)) => {
                                warn!(addr = %addr, error = %e, "Failed to detect connection type from {}: {}", addr, e);
                                return;
                            }
                            Err(_elapsed) => {
                                warn!(addr = %addr, read_timeout_secs = 10,
                                    "Initial read timeout (10s) before message detection from {}, dropping connection",
                                    addr
                                );
                                return;
                            }
                        };

                        match ct {
                                #[cfg(feature = "tls")]
                                ConnectionType::Tls(first_byte) => {
                                    crate::handlers::handle_tls_connection(
                                        state,
                                        addr,
                                        accept_deadline,
                                        first_byte,
                                        stream_io,
                                    )
                                    .await;
                                }
                                #[cfg(not(feature = "tls"))]
                                ConnectionType::Tls(first_byte) => {
                                    crate::handlers::handle_tls_connection(
                                        state,
                                        addr,
                                        accept_deadline,
                                        first_byte,
                                        stream_io,
                                    )
                                    .await;
                                }
                                ConnectionType::WebSocket => {
                                    #[cfg(feature = "websocket")]
                                    {
                                        crate::handlers::handle_websocket_connection(
                                            state,
                                            addr,
                                            accept_deadline,
                                            stream_io,
                                        )
                                        .await;
                                    }
                                    #[cfg(not(feature = "websocket"))]
                                    {
                                        // `not(feature = "websocket")` here is
                                        // *this crate's* feature. The variant
                                        // exists in the match because frp-core
                                        // may be compiled with its own
                                        // `websocket` feature ON through Cargo
                                        // feature unification even then — e.g.
                                        // in this crate's
                                        // `cargo check -p frp-server
                                        // --no-default-features --all-targets`
                                        // run, frp-server's dev-dependency on
                                        // frp-client (default features) pulls
                                        // frp-core/websocket in.
                                        //
                                        // Two graphs satisfy this cfg, and they
                                        // differ in whether the arm is taken:
                                        //  - frp-core's `websocket` *also* off:
                                        //    `detect_and_strip_magic`'s `b'G'`
                                        //    arm is off too, so 'G' is
                                        //    classified `V1(b'G')` and this arm
                                        //    is never taken.
                                        //  - frp-core's `websocket` on (the
                                        //    --all-targets run above, and any
                                        //    other graph with frp-client in
                                        //    it): the `b'G'` detection arm is
                                        //    compiled, `ConnectionType::WebSocket`
                                        //    *is* returned, and this is the live
                                        //    path — a 'G' connection is warned
                                        //    about and dropped, which is the
                                        //    intended behaviour for a build with
                                        //    no WebSocket handler.
                                        let _ = (state, accept_deadline, stream_io);
                                        warn!(addr = %addr, "WebSocket connection from {} but WebSocket feature not enabled, dropping", addr);
                                    }
                                }
                                ConnectionType::V2 => {
                                    crate::handlers::handle_v2_connection(
                                        state,
                                        addr,
                                        accept_deadline,
                                        stream_io,
                                    )
                                    .await;
                                }
                                ConnectionType::V1(_) => {
                                    crate::handlers::handle_v1_connection(
                                        state,
                                        addr,
                                        accept_deadline,
                                        stream_io,
                                    )
                                    .await;
                                }
                        }
                    }));
                }
                Err(e) => {
                    error!(error = %e, "Failed to accept connection: {}", e);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
                }
                _ = self.state.shutdown_token.cancelled() => {
                    info!("Accept loop stopped for graceful shutdown");
                    break;
                }
            }
        }

        // --- Graceful drain phase ---
        // Accept loop has stopped. Let existing bridge connections finish.
        let drain_timeout = Duration::from_secs(self.cfg.graceful_shutdown_timeout);
        let drain_start = std::time::Instant::now();
        let initial = self
            .state
            .active_connections
            .load(std::sync::atomic::Ordering::Relaxed);
        info!(active = %initial, timeout_secs = %drain_timeout.as_secs(),
            "Draining {} active connections (timeout {}s)",
            initial, drain_timeout.as_secs());

        loop {
            let remaining = self
                .state
                .active_connections
                .load(std::sync::atomic::Ordering::Relaxed);
            if remaining == 0 {
                info!(elapsed_secs = %drain_start.elapsed().as_secs_f32(),
                    "All connections drained in {:.1}s", drain_start.elapsed().as_secs_f32());
                break;
            }
            if drain_start.elapsed() > drain_timeout {
                warn!(remaining = %remaining, timeout_secs = %drain_timeout.as_secs(),
                    "Drain timeout — {} connections still active, forcing shutdown", remaining);
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        // Stop the OIDC background JWKS refresh before exiting — the verifier
        // itself is dropped with AppState, but aborting the refresh task here
        // gives it a deterministic stop point during graceful shutdown
        // (audit round 5, LOW 2.4). cfg-gated: without the `oidc` feature the
        // verifier is a method-less stub type.
        #[cfg(feature = "oidc")]
        if let Some(verifier) = &self.state.oidc.verifier {
            verifier.stop_background_refresh();
        }
        Ok(())
    }

    /// Reload configuration from the config file (SIGUSR1 handler).
    /// Re-reads the TOML config and applies the safe-to-reload settings:
    /// `allow_ports`, the `[auth]` credential (`auth.token` / `auth.tokenSource`),
    /// `auth.additionalAuthScopes`, `auth.authenticationTimeout` /
    /// `auth.tokenAuthTimeout` (all read from the live `auth_cfg` on use), the
    /// bridge encryption key derived from that credential, and TLS certificates.
    ///
    /// Everything else in `[auth]` — `auth.method` above all — is **reported,
    /// not applied**: see [`note_auth_restart_changes`] and the invariant the
    /// apply block below maintains. `auth.useEncryption` is the one exception to
    /// even *that*: nothing on the server reads it, so it is neither applied nor
    /// reported (see the same function). `ServerConfig.tls_enable` has the same
    /// disposition for the same reason: no reader in `frp-server`/`frps`, so it
    /// is neither applied nor reported.
    ///
    /// NOT reloadable — restart-only (checked once in `AppState::new`, never
    /// re-applied here): `max_ports_per_client`, `max_conns_per_proxy`,
    /// `max_proxies_per_client`. They gate live registrations via their
    /// semaphores/maps, so a reload cannot retroactively rescale them.
    pub async fn reload(&self) -> Result<String, String> {
        let config_path = match &self.config_file {
            Some(p) => p.clone(),
            None => return Err("No config file path stored".into()),
        };
        // `load_server_config_with_presence` (not the plain wrapper) so the
        // `[web_server.tls] enable` diagnostic still reaches the log on a
        // reload: the loader itself is silent — on the startup `-c` path it
        // would run before `init_logging` and reach no subscriber — so every
        // in-process load site that *does* have a sink emits it here. Measured
        // on the base binary: a reload of a config with the key logged
        // `web_server.tls.enable has no effect: …` before `SIGUSR1: no changes
        // detected`; `enable` has no field, so that record was the only signal
        // the reload gave about it.
        let (new_cfg, presence): (ServerConfig, _) =
            frp_core::config::load_server_config_with_presence(&config_path, false)
                .map_err(|e| format!("Failed to reload config: {e}"))?;
        presence.warn_inert_web_server_tls_enable(web_server_tls_enable_reader());
        // The flat server `tls_enable` is inert as well; this reload site has a
        // sink, so it delivers the record. Once per load — a reload adds one
        // rather than replacing the startup record.
        presence.warn_inert_server_tls_enable();
        // The feature-gated listener ports this build has no field for, **or**
        // has a field for while this crate's listener is compiled out, report
        // here too: a reload that adds `websocket_port = 7500` (say) to a
        // `micro`/`tiny` config still cannot open the port, and the hand-named
        // inner-feature shape (`tiny,frp-core/websocket`) deserializes the key
        // without a listener. The reader answer is this crate's own
        // (`gated_listener_port_readers`), never the binary's. One per load — a
        // reload adds one rather than replacing the startup record.
        presence.warn_unhonoured_server_feature_keys(gated_listener_port_readers());
        // The two listener ports whose field *is* present but whose reader is
        // not: `web_server.port` (dashboard) and `ssh_tunnel_gateway.bind_port`
        // (ssh). Same one-record-per-load rule; a reload that starts naming one
        // of them adds a record rather than replacing the startup one.
        presence.warn_inert_web_server_port(web_server_port_reader());
        presence.warn_inert_ssh_tunnel_gateway_bind_port(ssh_tunnel_gateway_bind_port_reader());

        let mut changes: Vec<String> = Vec::new();

        // Build new reloadable state
        let new_auth_cfg = build_auth_config(&new_cfg.auth, &self.unsafe_features)?;
        new_auth_cfg
            .check_startup()
            .map_err(|e| format!("security misconfiguration: {e}"))?;
        let new_enc_key = frp_core::encryption::derive_key(&new_auth_cfg.token);
        let new_allow_ports = resolve_allow_ports(&new_cfg);

        // Apply under write lock
        {
            let mut r = self.state.reloadable.write_ok();
            if *r.allow_ports != new_allow_ports {
                changes.push(format!(
                    "allow_ports: {:?} -> {:?}",
                    r.allow_ports, new_allow_ports
                ));
                r.allow_ports = Arc::new(new_allow_ports);
            }

            // `[auth]`: the `AuthConfig` that goes live is the **running** one
            // with the reloadable fields replaced — never `new_auth_cfg`
            // wholesale. Committing the freshly parsed struct is what let a
            // reload install `method = Oidc` from the file while
            // `state.oidc.verifier` was still `None` (built once, at startup,
            // from the startup method), leaving the config and the running auth
            // disagreeing. Rebuilding from the running value makes
            // `r.auth_cfg.method` the method this process actually serves for
            // the process's whole lifetime, so the login dispatch — which keys
            // off `Option<verifier>`, not off the method
            // (`frp-server/src/control/login.rs`) — cannot be handed a method
            // whose verifier was never built. Everything not copied here is
            // reported restart-required by `note_auth_restart_changes` below
            // (or, for the one inert field, deliberately not reported at all —
            // see that function).
            let mut live_auth = (*r.auth_cfg).clone();
            let credential_changed = live_auth.token != new_auth_cfg.token
                || value_source_differs(&live_auth.token_source, &new_auth_cfg.token_source);
            if credential_changed {
                // `live_auth` is a clone, so its `token` is a second copy of the
                // *running* token; overwriting it frees that copy's buffer
                // without going through `AuthConfig`'s zeroizing `Drop` (which
                // only runs when a whole `AuthConfig` is dropped, and the
                // running one is still alive in `r.auth_cfg`). Zeroize the copy
                // first. Covered: this copy. Not covered by anything here: the
                // replaced `token_source` (a `ValueSource` can carry an exec env
                // value); no zeroizing primitive for it exists in the tree, and
                // this is the only place a reload replaces one.
                frp_core::auth::zeroize_string(&mut live_auth.token);
                live_auth.token = new_auth_cfg.token.clone();
                live_auth.token_source = new_auth_cfg.token_source.clone();
            }
            // `additionalAuthScopes` is read live, per control connection and
            // per scoped message, from the two places this keeps in step:
            // `ReloadableState::additional_auth_scopes`
            // (`frp-server/src/control/login.rs`) and
            // `auth_cfg.additional_auth_scopes`
            // (`frp-server/src/handlers/dispatch.rs`,
            // `frp-server/src/control/proxy.rs`). The pre-fix comparison read
            // the *new* value out of `r.auth_cfg` only when the token arm above
            // had already replaced it, so a scopes-only change compared the old
            // value against itself and was reported as `no changes detected`.
            let scopes_changed = r.additional_auth_scopes != new_auth_cfg.additional_auth_scopes;
            if scopes_changed {
                changes.push(format!(
                    "additional_auth_scopes: {:?} -> {:?}",
                    r.additional_auth_scopes, new_auth_cfg.additional_auth_scopes
                ));
                live_auth.additional_auth_scopes = new_auth_cfg.additional_auth_scopes.clone();
            }
            // The two auth timeouts are read from the **live** `auth_cfg` on
            // every use, so re-keying them here reaches every reader and they
            // are applied rather than reported: the login timestamp window and
            // the replay table's prune
            // (`frp-server/src/control/login/auth.rs:332-372`), the scoped-message
            // freshness gate (`frp-server/src/handlers/dispatch.rs:68`, `:552`)
            // and the nathole pre-check (`frp-server/src/control/nathole.rs:380`,
            // `:575`). Pre-fix the reload never compared them, so a change to
            // one alone was `no changes detected`, and it moved only by
            // accident — when the token arm happened to replace the whole
            // struct. Refusing them as "restart required" would be false: a
            // restart is not needed for a value the next login re-reads.
            let timeouts_changed = live_auth.authentication_timeout
                != new_auth_cfg.authentication_timeout
                || live_auth.token_auth_timeout != new_auth_cfg.token_auth_timeout;
            if timeouts_changed {
                note_applied_change(
                    &live_auth.authentication_timeout,
                    &new_auth_cfg.authentication_timeout,
                    "auth.authenticationTimeout",
                    &mut changes,
                );
                note_applied_change(
                    &live_auth.token_auth_timeout,
                    &new_auth_cfg.token_auth_timeout,
                    "auth.tokenAuthTimeout",
                    &mut changes,
                );
                live_auth.authentication_timeout = new_auth_cfg.authentication_timeout;
                live_auth.token_auth_timeout = new_auth_cfg.token_auth_timeout;
            }
            if credential_changed {
                changes.push("auth token updated".into());
                r.encryption_key = new_enc_key;
            }
            if credential_changed || scopes_changed || timeouts_changed {
                r.auth_cfg = Arc::new(live_auth);
                // The mirror is derived from `auth_cfg`, never assigned
                // independently — the two readers above must not disagree.
                r.additional_auth_scopes = r.auth_cfg.additional_auth_scopes.clone();
            }
        }

        // Log settings that require restart
        note_restart_change(
            &self.cfg.bind_port,
            &new_cfg.bind_port,
            "bind_port",
            &mut changes,
        );
        note_restart_change(
            &self.cfg.bind_addr,
            &new_cfg.bind_addr,
            "bind_addr",
            &mut changes,
        );
        // `ServerConfig.tls_enable` is deliberately **not** compared here: no
        // code in `frp-server`/`frps` reads it. `grep -rn tls_enable
        // frp-server/src frps/src` returns only comment lines and call sites of
        // the unrelated helper `presence.warn_inert_web_server_tls_enable(reader)`
        // (whose `reader` comes from `web_server_tls_enable_reader()`),
        // which reads a different key, `[web_server.tls] enable`; zero field
        // reads. No hit count is pinned here: stating one is self-invalidating,
        // because this comment and any later comment that merely mentions the
        // identifier change the number. The earlier "seven hits" was already
        // wrong for that reason, missed
        // `frp-server/src/control/login.rs:949`, and was raised by the lines
        // asserting it. So neither a reload nor a restart can make a change to
        // it take effect and a "restart required" line would be false. The same
        // disposition `auth.useEncryption` has in
        // [`note_auth_restart_changes`]; pinned by
        // `inert_settings_are_not_reported` in
        // `frp-server/tests/server_reload_restart_only.rs`.
        // TLS certificate hot-reload: if cert/key/ca paths changed, rebuild
        // acceptor and swap atomically. Existing connections keep old config;
        // new connections pick up the new cert immediately.
        #[cfg(feature = "tls")]
        if self.cfg.tls_cert_file != new_cfg.tls_cert_file
            || self.cfg.tls_key_file != new_cfg.tls_key_file
            || self.cfg.tls_ca_file != new_cfg.tls_ca_file
        {
            let ca = if new_cfg.tls_ca_file.is_empty() {
                None
            } else {
                Some(new_cfg.tls_ca_file.as_str())
            };
            match build_tls_acceptor_or_generate(&new_cfg.tls_cert_file, &new_cfg.tls_key_file, ca)
            {
                Ok(acceptor) => {
                    *self.state.tls_acceptor.write_ok() = Some(acceptor);
                    changes.push(format!(
                        "TLS certificate reloaded (cert: {}, key: {})",
                        new_cfg.tls_cert_file, new_cfg.tls_key_file
                    ));
                }
                Err(e) => {
                    changes.push(format!(
                        "TLS certificate reload FAILED: {} (keeping old config)",
                        e
                    ));
                }
            }
        }
        // `[auth]` fields a reload cannot apply (the OIDC verifier is created
        // once at startup and fetches JWKS; the remaining scalars are read from
        // state a reload does not re-key). Baseline is `self.cfg.auth`:
        // `reload` takes `&self`, nothing writes `self.cfg` after construction,
        // and the apply block above derives the live `auth_cfg` from the
        // running one — it never copies a restart-only field out of the file.
        // So `self.cfg.auth` *is* the running value for every field this
        // reports, including `auth.method` (the reason a method-only change
        // used to vanish into `config reloaded: no changes detected`).
        note_auth_restart_changes(&self.cfg.auth, &new_cfg.auth, &mut changes);

        // Every other restart-only field, named — the `ServerConfig`-shaped
        // counterpart of the call above. Baseline is `self.cfg` for the same
        // reason it is there: nothing writes `self.cfg` after construction and
        // the apply block above never copies a restart-only field out of the
        // file, so `self.cfg` *is* the running value. Pre-fix, a change to any
        // of these alone vanished into `config reloaded: no changes detected`.
        note_restart_changes(&self.cfg, &new_cfg, &mut changes);

        if changes.is_empty() {
            Ok("config reloaded: no changes detected".into())
        } else {
            info!(changes = %changes.join("; "), "Config reloaded: {}", changes.join("; "));
            Ok(changes.join("; "))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression (audit H1): `Some(0)` ("0 = unlimited") must resolve to 0,
    /// not `usize::MAX` — `AppState::new` builds `Semaphore::new(n)` whenever
    /// n > 0, and tokio panics on `usize::MAX` (MAX_PERMITS assertion); with
    /// panic=abort in release, frps would crash at boot on the documented
    /// "0 = unlimited" setting.
    #[test]
    fn resolve_max_connections_zero_means_unlimited() {
        assert_eq!(resolve_max_connections(Some(0)), 0);
        assert_eq!(resolve_max_connections(Some(5)), 5);
        assert_eq!(resolve_max_connections(None), 512);
    }

    /// Regression: a failing dynamic token source is a startup error — it
    /// must not silently fall back to an empty token (when both sides'
    /// sources fail, that would silently degrade auth to no-auth). Go frp
    /// v0.70.1 fails startup on token-source resolution errors.
    #[test]
    fn build_auth_config_fails_on_token_source_error() {
        let auth = frp_core::config::AuthServerConfig {
            token: "file:///nonexistent/frp-token-startup.txt".to_string(),
            ..Default::default()
        };
        let result = build_auth_config(&auth, &UnsafeFeatures::default());
        let err = result.expect_err("token-source failure must fail startup");
        // The startup error must not leak the token-file path.
        assert!(
            !err.contains("frp-token-startup.txt"),
            "error leaked the token-file path: {err}"
        );
    }

    /// With frp-server's own `oidc` feature OFF (frp-core's `oidc` may still be
    /// ON through feature unification — the configuration the
    /// `-p frp-server --no-default-features --features dashboard` CI step
    /// compiles), `method = "oidc"` is a **configuration error**, not a silent
    /// fallthrough to token auth. Before this pin the build started as token
    /// auth whenever `auth.token` was set, so the operator asked for OIDC and got
    /// a server that accepted anyone holding the token.
    #[test]
    #[cfg(not(feature = "oidc"))]
    fn oidc_method_with_server_oidc_off_is_rejected() {
        // Both halves of the measured downgrade: no token, and a token set.
        for token in ["", "secret"] {
            let auth = frp_core::config::AuthServerConfig {
                method: "oidc".to_string(),
                token: token.to_string(),
                ..Default::default()
            };
            let err = build_auth_config(&auth, &UnsafeFeatures::default())
                .expect_err("an oidc config in an oidc-less build must be rejected");
            assert!(
                err.contains("\"oidc\"") && err.contains("feature"),
                "error must name the missing feature: {err}"
            );
        }

        // The other half, still true and worth pinning: a *hand-built*
        // `AuthMethod::Oidc` must fail closed on the token path (it is matched
        // exhaustively now, but no verifier exists in this build). Built by
        // mutation rather than struct-update: `AuthConfig` implements `Drop`
        // (the zeroizing token), so `..Default::default()` cannot move out of it.
        let mut cfg = AuthConfig::with_token("secret");
        cfg.method = AuthMethod::Oidc;
        assert!(cfg.validate_login(None, Some(1_700_000_000)).is_err());
    }

    /// Pin which `web_server.tls.enable` message this build's resolver selects.
    ///
    /// Before this test no lane witnessed `web_server_tls_enable_reader()`:
    /// every frps lane linked frp-server with `tls` on, so its
    /// `cfg!(feature = "tls")` argument could be replaced by the literal `true`
    /// and stay green — a dashboard-on/tls-off build would then emit the
    /// "TLS is available" text and name a switch it cannot honour. The
    /// `-p frp-server --no-default-features --features dashboard` CI step runs
    /// exactly this test in the shape that catches that mutant.
    #[test]
    fn web_server_tls_enable_reader_answers_from_this_build() {
        use frp_core::config::WebServerTlsEnableReader;

        let got = web_server_tls_enable_reader();
        #[cfg(all(feature = "dashboard", feature = "tls"))]
        let want = WebServerTlsEnableReader::WebServerTls;
        #[cfg(all(feature = "dashboard", not(feature = "tls")))]
        let want = WebServerTlsEnableReader::WebServerNoTls;
        #[cfg(not(feature = "dashboard"))]
        let want = WebServerTlsEnableReader::NoWebServer;

        // Debug-only sabotage hook for the resolver CI step: that step runs this
        // test a second time with `FRP_WARNING_PIN_SABOTAGE` set and requires the
        // run to **fail**, mirroring `FRPS_DIR_REGISTRY_TEST_DISCARD` in the frps
        // bin unit step. Expecting the wrong variant is exactly the mutant this
        // pin asserts against, so a body whose `assert_eq!` was deleted, made
        // unreachable, or replaced by a marker-printing stub passes the sabotaged
        // run — nothing at log level can tell such a stub from a real body, but a
        // vacuous pin cannot be made to fail. Never set outside that step.
        #[cfg(debug_assertions)]
        let want = if std::env::var_os("FRP_WARNING_PIN_SABOTAGE").is_some() {
            // Any variant *other* than the honest answer, so the hook flips the
            // expectation in every feature shape. Hard-coding
            // `from_features(true, true)` read as the same thing but collided
            // with the honest answer whenever `tls` was on — e.g. if
            // `frp-server`'s `dashboard` feature ever implied `tls`, the
            // assertion held, the sabotaged run passed, and the guard
            // false-reddened with "restore the assertions" while the hook was a
            // no-op, silently disabling the guard for exactly the
            // `dashboard`+`tls` shape this pin exists to separate.
            if want == WebServerTlsEnableReader::WebServerTls {
                WebServerTlsEnableReader::WebServerNoTls
            } else {
                WebServerTlsEnableReader::WebServerTls
            }
        } else {
            want
        };

        assert_eq!(got, want);

        // Printed only after the assertion above. The CI step runs this test with
        // `-- --nocapture` and greps this line, so a body that returns before its
        // assertions (still `1 passed` under libtest) cannot pass the step while
        // asserting nothing. The marker deliberately names no variant: the
        // assertion pins the variant, and spelling it here coupled the step to
        // `WebServerTlsEnableReader`'s `Debug` text, so a legitimate variant
        // rename reddened the step for a reason its message could not diagnose.
        println!("web-server-tls-enable-reader-pin: assertions ran");
    }

    /// Pin which `web_server.port` answer this build's resolver gives.
    ///
    /// `web_server.port` is an **unconditional** field of `frp-core`'s
    /// `ServerConfig`, so serde always accepts the key; only this crate's
    /// `dashboard` feature reads it. A resolver that hard-coded either variant
    /// would either warn in a build that honours the port (dashboard on) or stay
    /// silent in every shipped build (dashboard off) — the two directions the
    /// real-binary rows in `frps/tests/warn_delivery.rs` cover. The
    /// `dashboard`-off half runs in the default-feature `-p frp-server` lanes
    /// (`.github/workflows/ci.yml:2278` `--features vnet --lib`, `:4017`
    /// `--no-default-features --all-targets -j 1`; `ssh` is on in the first and
    /// off in the second, covering the `ssh_tunnel_gateway.bind_port` twin too)
    /// and the `dashboard`-on half in the unfiltered `:3848`
    /// (`-p frp-server --features dashboard -j 1`). The
    /// `--no-default-features --features dashboard --lib` lane at `:2315`
    /// filters by `web_server_tls_enable_reader`, so it does **not** run these
    /// pins.
    #[test]
    fn web_server_port_reader_answers_from_this_build() {
        use frp_core::config::ListenerPortReader::{Absent, Present};

        let got = web_server_port_reader();
        let want = if cfg!(feature = "dashboard") {
            Present
        } else {
            Absent
        };
        assert_eq!(
            got, want,
            "web_server.port's reader is this crate's `dashboard` feature"
        );
        // The assertion has to be able to fail: if a rename ever made the two
        // variants compare equal, `assert_eq!` above would hold vacuously.
        assert_ne!(Present, Absent);
        println!("web-server-port-reader-pin: assertions ran");
    }

    /// The `ssh_tunnel_gateway.bind_port` twin of
    /// [`web_server_port_reader_answers_from_this_build`].
    #[test]
    fn ssh_tunnel_gateway_bind_port_reader_answers_from_this_build() {
        use frp_core::config::ListenerPortReader::{Absent, Present};

        let got = ssh_tunnel_gateway_bind_port_reader();
        let want = if cfg!(feature = "ssh") {
            Present
        } else {
            Absent
        };
        assert_eq!(
            got, want,
            "ssh_tunnel_gateway.bind_port's reader is this crate's `ssh` feature"
        );
        assert_ne!(Present, Absent);
        println!("ssh-tunnel-gateway-bind-port-reader-pin: assertions ran");
    }

    /// The **CLI-overlay** half of the same question.
    ///
    /// `frps --dashboard-port <non-zero>` with no `-c`/`--config-dir` writes
    /// `web_server.port` through `override_server_config`, *after* the load that
    /// records the config file's own request, so the value has to be merged back
    /// into `ConfigPresence` by hand (`frp-core`'s `AppliedReaderGatedPorts` /
    /// `ConfigPresence::record_applied_reader_gated_ports`). This pins that the
    /// merged request produces the same record as the file key, using **this
    /// build's** reader — so the dashboard-off lanes
    /// (`--no-default-features --all-targets -j 1`, `--features vnet --lib`)
    /// assert a record and the dashboard-on lanes (`--features dashboard -j 1`
    /// and the `--no-default-features --features dashboard --lib` lane) assert
    /// silence, with no `cfg!` that could be right for the wrong reason.
    /// `frp-core`'s `cli` tests pin the merge itself, and
    /// `frps/tests/warn_delivery.rs` pins the spawned binary.
    #[test]
    fn dashboard_port_overlay_record_follows_this_builds_reader() {
        use frp_core::config::ListenerPortReader::{Absent, Present};
        use frp_core::config::{AppliedReaderGatedPorts, ConfigPresence};

        let mut presence = ConfigPresence::default();
        presence.record_applied_reader_gated_ports(AppliedReaderGatedPorts {
            web_server_port: true,
            ..Default::default()
        });
        let records = presence.unhonoured_reader_gated_port_records(
            web_server_port_reader(),
            ssh_tunnel_gateway_bind_port_reader(),
        );
        let want = if web_server_port_reader() == Absent {
            vec![frp_core::config::WEB_SERVER_PORT_UNHONOURED_WARNING]
        } else {
            Vec::new()
        };
        assert_eq!(
            records, want,
            "an overlay-applied web_server.port owes a record exactly when this build has no \
             reader for it"
        );
        // The assertion has to be able to fail in both directions: if a rename
        // ever made the two variants compare equal, or a reader returned one
        // variant everywhere, the comparison above would hold vacuously.
        assert_ne!(Present, Absent);
        println!("dashboard-port-overlay-record-pin: assertions ran");
    }

    /// Pin which `kcp_bind_port` answer this build's resolver gives.
    ///
    /// `kcp_bind_port` is `#[cfg(feature = "kcp")]`-gated in `frp-core`'s
    /// `ServerConfig`, but **this crate's** `kcp` feature is what compiles the
    /// listener, and Cargo unifies the two independently: the
    /// `-p frp-server --no-default-features --all-targets` lane turns
    /// `frp-core/kcp` on through the `frp-client` dev-dependency while this
    /// crate's `kcp` is off, so that lane is the hand-named inner-feature shape
    /// (`cargo build -p frps --no-default-features --features tiny,frp-core/kcp`)
    /// at the unit level. A resolver that hard-coded either variant would either
    /// warn in a build that binds the port or stay silent in exactly the shape
    /// this reader exists for.
    #[test]
    fn kcp_bind_port_reader_answers_from_this_build() {
        use frp_core::config::ListenerPortReader::{Absent, Present};

        let got = kcp_bind_port_reader();
        let want = if cfg!(feature = "kcp") {
            Present
        } else {
            Absent
        };
        assert_eq!(
            got, want,
            "kcp_bind_port's reader is this crate's `kcp` feature"
        );
        assert_ne!(Present, Absent);
        println!("kcp-bind-port-reader-pin: assertions ran");
    }

    /// The `quic_bind_port` twin of [`kcp_bind_port_reader_answers_from_this_build`].
    #[test]
    fn quic_bind_port_reader_answers_from_this_build() {
        use frp_core::config::ListenerPortReader::{Absent, Present};

        let got = quic_bind_port_reader();
        let want = if cfg!(feature = "quic") {
            Present
        } else {
            Absent
        };
        assert_eq!(
            got, want,
            "quic_bind_port's reader is this crate's `quic` feature"
        );
        assert_ne!(Present, Absent);
        println!("quic-bind-port-reader-pin: assertions ran");
    }

    /// The `websocket_port` twin of
    /// [`kcp_bind_port_reader_answers_from_this_build`]. There is no
    /// `--websocket-port` flag, so this reader is only consulted for the file
    /// key.
    #[test]
    fn websocket_port_reader_answers_from_this_build() {
        use frp_core::config::ListenerPortReader::{Absent, Present};

        let got = websocket_port_reader();
        let want = if cfg!(feature = "websocket") {
            Present
        } else {
            Absent
        };
        assert_eq!(
            got, want,
            "websocket_port's reader is this crate's `websocket` feature"
        );
        assert_ne!(Present, Absent);
        println!("websocket-port-reader-pin: assertions ran");
    }

    /// The combined constructor must agree with the three individual readers —
    /// the three fields are the same type, so a swapped pair would otherwise be
    /// invisible.
    #[test]
    fn gated_listener_port_readers_answers_from_this_build() {
        let got = gated_listener_port_readers();
        assert_eq!(got.kcp, kcp_bind_port_reader());
        assert_eq!(got.quic, quic_bind_port_reader());
        assert_eq!(got.websocket, websocket_port_reader());
        println!("gated-listener-port-readers-pin: assertions ran");
    }

    /// **The hand-named inner-feature shape, end to end through the loader.**
    ///
    /// A file naming all three ports is loaded exactly as `frps` loads it and the
    /// record list is taken with **this build's** readers
    /// (`gated_listener_port_readers`). The property asserted is shape-agnostic
    /// and therefore holds in every lane:
    ///
    /// * this crate compiles the listener (`Present`) — `frp-server/kcp =
    ///   ["frp-core/kcp"]` guarantees the field also exists, so nothing is
    ///   unread and the key must be **silent**;
    /// * this crate does not (`Absent`) — either `frp-core` dropped the key or it
    ///   deserialized the field with no listener behind it (the hand-named
    ///   shape), and the key must be **recorded** either way.
    ///
    /// That "either way" is what makes the field-present-without-a-listener case
    /// assertable from this crate at all: only `frp-core` can see its own
    /// feature, so the reader's answer is the only honest input here. The
    /// `-p frp-server --no-default-features --all-targets` lane is the one that
    /// reaches the `Absent` half with `frp-core/kcp` **on**
    /// (`frp-core/src/config/tests.rs` pins the same split from the other side,
    /// where `cfg!(feature = "kcp")` is visible).
    ///
    /// **The shape is asserted, not only the invariant.** The record rule alone
    /// also holds when `frp-core` compiled the field *out* (`!field_present`
    /// implies a record), so a lane that stopped resolving to the hand-named
    /// shape would lose the absent-listener coverage without reddening. Each
    /// port therefore also asserts `field_present || has_listener` — this lane
    /// must keep `frp-core`'s field present while **this** crate's listener is
    /// off — which is the Done-when's "a test builds that shape and asserts it".
    #[test]
    fn gated_listener_port_records_follow_this_builds_readers() {
        use frp_core::config::ListenerPortReader::{Absent, Present};

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("frps.toml");
        std::fs::write(
            &path,
            "bind_port = 7000\nkcp_bind_port = 7100\nquic_bind_port = 7200\n\
             websocket_port = 7500\n",
        )
        .unwrap();
        // Lenient, because in a build that compiles a field out the key is only
        // *tolerated*; strict mode accepts it too
        // (`frp-core/src/config/tests.rs` pins that), but lenient is the load
        // `frps` performs unless asked otherwise.
        let (cfg, presence) =
            frp_core::config::load_server_config_with_presence(path.to_str().unwrap(), false)
                .expect("the port keys load in every shape");
        // The serde field set is the one fact about `frp-core`'s features that is
        // observable from here, so it is measured rather than assumed: the
        // field-present half of the hand-named shape is exactly
        // `field_present && reader == Absent`.
        let value = serde_json::to_value(&cfg).unwrap();
        let records = presence.unhonoured_server_feature_key_records(gated_listener_port_readers());
        for (key, reader, has_listener) in [
            (
                "kcp_bind_port",
                kcp_bind_port_reader(),
                cfg!(feature = "kcp"),
            ),
            (
                "quic_bind_port",
                quic_bind_port_reader(),
                cfg!(feature = "quic"),
            ),
            (
                "websocket_port",
                websocket_port_reader(),
                cfg!(feature = "websocket"),
            ),
        ] {
            let field_present = value.get(key).and_then(|port| port.as_u64()).is_some();
            let recorded = records.iter().any(|record| record.contains(key));
            // The reader is this crate's own gate, so the per-port pin tests'
            // answer and the literal `cfg!` have to agree here too.
            assert_eq!(
                reader,
                frp_core::config::ListenerPortReader::from_features(has_listener),
                "`{key}`: the reader must be this crate's own feature"
            );
            // **The shape itself, not only the invariant it produces.** This
            // lane's feature resolution must stay the hand-named shape:
            // `frp-core` compiled the field (through the `frp-client`
            // dev-dependency) while `frp-server`'s listener is off. Without this
            // assertion a future change that turned `frp-core`'s feature off
            // here would silently drop the only absent-listener coverage — the
            // record invariant below would still hold, because
            // `!field_present` also implies a record.
            assert!(
                field_present || has_listener,
                "this lane must remain the hand-named shape for `{key}`: frp-core's field \
                 present (field_present={field_present}) while frp-server's listener is \
                 absent (has_listener={has_listener})"
            );
            assert_eq!(
                recorded,
                reader == Absent || !field_present,
                "`{key}` must be recorded exactly when this build has no listener for it \
                 (reader {reader:?}, frp-core field present: {field_present}); \
                 records: {records:?}"
            );
            println!(
                "gated-listener-port-record-pin: {key} field_present={field_present} \
                 reader={reader:?} has_listener={has_listener} record={recorded}"
            );
        }
        assert_ne!(Present, Absent);
        println!("gated-listener-port-record-pin: assertions ran");
    }
}
