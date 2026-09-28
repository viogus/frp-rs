#![cfg(feature = "oidc")]
//! The server's `SIGUSR1` reload against `[auth]` (`TODO.md`, "The server's
//! SIGUSR1 reload compares neither `auth.method` nor the running verifier…").
//!
//! These tests drive `frp_server::service::Service::reload` in process and then
//! read the **live** state it left behind (`Service::state()`), which is what
//! the item is about: the file on disk versus the auth the process actually
//! serves. The shell probe kept with the change
//! (`/tmp/server-reload-auth-report.md`) measures the same two shapes from
//! outside, through a real `frps` and a real `frpc`; these tests add what a
//! black-box probe cannot see (the live `auth_cfg` and the verifier).
//!
//! The feature gate is on `frp-server`'s own `oidc`: `build_auth_config`
//! refuses `method = "oidc"` without it, so a method change could not reach the
//! report at all in that build (it is refused earlier, with the feature error).
//!
//! Shape A — `method = "token"` with the OIDC fields **present and unchanged**
//! (`oidc_issuer`, `oidc_audience`; with `method = "token"` the loader
//! validates neither), rewritten to `method = "oidc"` with the same token and
//! the same OIDC fields. Pre-fix: `config reloaded: no changes detected`.
//!
//! Shape B — the same plus a changed token. Pre-fix: `auth token updated`, and
//! because `reload()` assigned the whole freshly parsed `AuthConfig`, the live
//! `auth_cfg.method` became `Oidc` while `state.oidc.verifier` — built once, at
//! startup, from the startup method — was still `None`.

mod common;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use frp_core::auth::{generate_token, AuthMethod};
use frp_core::config::load_server_config;
use frp_core::unsafe_features::UnsafeFeatures;
use frp_server::service::Service;

use common::{allocate_port, raw_login};

const T1: &str = "reload-auth-token-one";
const T2: &str = "reload-auth-token-two";
/// The OIDC fields are present in *every* config here, from the first write:
/// Shape A is only reachable when the running config already carries them, so
/// the reload that flips the method sees them unchanged. Nothing ever contacts
/// this issuer — with `method = "token"` no verifier is built, and the reload
/// path only calls `check_startup`.
const PROBE_ISSUER: &str = "http://127.0.0.1:9/oidc";
const PROBE_AUDIENCE: &str = "reload-probe-audience";

/// `bind_addr`/`bind_port`/`tcp_mux=false` (raw V1 frames, like
/// `common::start_test_server`) plus a whole `[auth]` section; `extra` appends
/// further `[auth]` keys.
fn probe_config(port: u16, method: &str, token: &str, extra: &str) -> String {
    format!(
        r#"bind_addr = "127.0.0.1"
bind_port = {port}
tcp_mux = false

[auth]
method = "{method}"
token = "{token}"
oidc_issuer = "{PROBE_ISSUER}"
oidc_audience = "{PROBE_AUDIENCE}"
{extra}
"#
    )
}

/// A config whose credential is a **file** `tokenSource`. `token` must be empty
/// when a source is set, and a file source needs no unsafe allowlist (only
/// `exec` does).
fn source_config(port: u16, token_file: &Path) -> String {
    format!(
        r#"bind_addr = "127.0.0.1"
bind_port = {port}
tcp_mux = false

[auth]
method = "token"
tokenSource = {{ type = "file", file = {{ path = "{}" }} }}
oidc_issuer = "{PROBE_ISSUER}"
oidc_audience = "{PROBE_AUDIENCE}"
"#,
        token_file.display()
    )
}

/// An in-process `frps` with a real config file, listening on a free port, plus
/// the accessors these tests need on the state it is serving from.
struct Server {
    svc: Arc<Service>,
    /// Kept alive for the test's lifetime; the file path lives inside it.
    _dir: tempfile::TempDir,
    config_path: PathBuf,
    run: tokio::task::JoinHandle<()>,
}

impl Server {
    async fn start(toml: &str) -> Self {
        let dir = tempfile::tempdir().expect("temp dir");
        let config_path = dir.path().join("frps.toml");
        std::fs::write(&config_path, toml).expect("write initial config");
        let cfg = load_server_config(config_path.to_str().expect("utf-8 path"), false)
            .expect("the initial config must load");
        let port = cfg.bind_port;
        let svc = Arc::new(
            Service::with_unsafe_features(
                cfg,
                Some(config_path.to_string_lossy().into_owned()),
                UnsafeFeatures::default(),
            )
            .await
            .expect("service construction"),
        );
        let runner = svc.clone();
        let run = tokio::spawn(async move {
            let _ = runner.run().await;
        });
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let mut ready = false;
        for _ in 0..50 {
            if tokio::net::TcpStream::connect(addr).await.is_ok() {
                ready = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(ready, "server did not start listening on {addr} in time");
        Self {
            svc,
            _dir: dir,
            config_path,
            run,
        }
    }

    /// Rewrite the config file and reload — the two steps `SIGUSR1` performs.
    async fn rewrite_and_reload(&self, toml: &str) -> Result<String, String> {
        std::fs::write(&self.config_path, toml).expect("rewrite config");
        self.svc.reload().await
    }

    /// The method of the `AuthConfig` the server is validating logins with.
    fn method(&self) -> AuthMethod {
        self.svc
            .state()
            .reloadable
            .read()
            .expect("reloadable lock")
            .auth_cfg
            .method
            .clone()
    }

    /// The credential the server is validating logins with.
    fn token(&self) -> String {
        self.svc
            .state()
            .reloadable
            .read()
            .expect("reloadable lock")
            .auth_cfg
            .token
            .clone()
    }

    /// Whether an OIDC verifier exists in the running state. Built once, in
    /// `Service::with_unsafe_features`, and never rebuilt by a reload.
    fn verifier_present(&self) -> bool {
        self.svc.state().oidc.verifier.is_some()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.run.abort();
    }
}

/// A real V1 token login against the running server: the same wire path the
/// shell probe drives with a real `frpc`. A transport error and a `LoginResp`
/// carrying `error` both mean "not accepted"; the error text is returned so a
/// caller can assert *which* branch answered.
async fn token_login(port: u16, token: &str) -> Result<(), String> {
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs() as i64;
    let key = generate_token(token, ts);
    match raw_login(addr, Some(key), Some(ts), token).await {
        Ok((_stream, resp)) => match resp.error {
            None => Ok(()),
            Some(e) => Err(e),
        },
        Err(e) => Err(format!("transport: {e}")),
    }
}

// ---------------------------------------------------------------
// Shape A
// ---------------------------------------------------------------

/// A method-only change is **reported**, and the running auth does not move.
///
/// Pre-fix this reload answered `config reloaded: no changes detected` — the
/// token matched, the OIDC fields matched, and nothing compared the method —
/// while the file on disk said `oidc`.
#[tokio::test]
async fn method_only_change_is_reported_not_silently_ignored() {
    let port = allocate_port();
    let server = Server::start(&probe_config(port, "token", T1, "")).await;
    assert_eq!(server.method(), AuthMethod::Token);
    assert!(
        !server.verifier_present(),
        "method = \"token\" must not build a verifier"
    );

    let summary = server
        .rewrite_and_reload(&probe_config(port, "oidc", T1, ""))
        .await
        .expect("the rewritten config is loadable");

    assert!(
        !summary.contains("no changes detected"),
        "a method change must not be reported as a no-op: {summary}"
    );
    assert!(
        summary.contains("auth.method: token -> oidc (restart required)"),
        "the summary must name the method change and its direction: {summary}"
    );
    // Reported, not applied: the process is still a token-auth server, which is
    // exactly what the summary just told the operator.
    assert_eq!(server.method(), AuthMethod::Token);
    assert!(!server.verifier_present());
    assert_eq!(server.token(), T1);
    assert!(
        token_login(port, T1).await.is_ok(),
        "the file's token must still log in: the running auth was left alone"
    );
}

// ---------------------------------------------------------------
// Shape B
// ---------------------------------------------------------------

/// A method change combined with a token change applies the **token** and
/// reports the **method** — it never installs `method == Oidc` on a server whose
/// verifier is `None`.
///
/// Pre-fix the whole freshly parsed `AuthConfig` was assigned, so the live
/// method became `Oidc` (the assertion below is the one that would have failed)
/// and logins took the token branch only by accident of the dispatch.
#[tokio::test]
async fn method_change_never_installs_a_method_without_a_verifier() {
    let port = allocate_port();
    let server = Server::start(&probe_config(port, "token", T1, "")).await;

    let summary = server
        .rewrite_and_reload(&probe_config(port, "oidc", T2, ""))
        .await
        .expect("the rewritten config is loadable");

    // State first: this assertion is the one the pre-fix code failed.
    assert_eq!(
        server.method(),
        AuthMethod::Token,
        "a reload must not claim a method the running verifier cannot serve \
         (summary: {summary})"
    );
    assert_eq!(server.token(), T2, "the new token is the live credential");
    assert!(!server.verifier_present());
    assert!(
        summary.contains("auth token updated"),
        "the credential change still applies: {summary}"
    );
    assert!(
        summary.contains("auth.method: token -> oidc (restart required)"),
        "the method change is reported: {summary}"
    );
    assert!(
        token_login(port, T2).await.is_ok(),
        "the live credential is the file's new token, served by the token path"
    );
    assert!(
        token_login(port, T1).await.is_err(),
        "the superseded token must not log in"
    );
}

// ---------------------------------------------------------------
// Positive controls: what must keep working, and what must stay quiet
// ---------------------------------------------------------------

/// (a) a reload of an unchanged file is still `no changes detected` — the
/// report is a diff, not a standing alarm; (b) a credential-only change is
/// still applied and reported with no `restart required` noise.
#[tokio::test]
async fn unchanged_file_stays_quiet_and_a_credential_change_still_applies() {
    let port = allocate_port();
    let server = Server::start(&probe_config(port, "token", T1, "")).await;

    let quiet = server
        .rewrite_and_reload(&probe_config(port, "token", T1, ""))
        .await
        .expect("reload");
    assert_eq!(quiet, "config reloaded: no changes detected");

    let applied = server
        .rewrite_and_reload(&probe_config(port, "token", T2, ""))
        .await
        .expect("reload");
    assert!(
        applied.contains("auth token updated"),
        "credential change: {applied}"
    );
    assert!(
        !applied.contains("restart required"),
        "a credential change is applied in place and needs no restart: {applied}"
    );
    assert_eq!(server.method(), AuthMethod::Token);
    assert_eq!(server.token(), T2);
    assert!(token_login(port, T2).await.is_ok());

    // The same file again: the diff is now empty, including after the reload
    // that replaced the live `AuthConfig` (the restart-only fields are compared
    // against `self.cfg.auth`, which nothing writes).
    let quiet_again = server
        .rewrite_and_reload(&probe_config(port, "token", T2, ""))
        .await
        .expect("reload");
    assert_eq!(quiet_again, "config reloaded: no changes detected");

    // `method = ""` is Go's zero value and the loader completes it to
    // `"token"` on both sides (`AuthServerConfig::complete`), so a file that
    // only *spells out* the default is not a change — the comparison is on the
    // completed value, not on the raw serde string. (The client half pins the
    // same equivalence in `frp-client/src/reload.rs`.)
    let spelled_out = server
        .rewrite_and_reload(&probe_config(port, "", T2, ""))
        .await
        .expect("reload");
    assert_eq!(spelled_out, "config reloaded: no changes detected");
}

/// `[auth]` fields the pre-fix reload never compared at all are reported now
/// instead of vanishing into `no changes detected`, and still not applied.
///
/// `oidc_skip_nbf` is one of the fields the startup verifier is built from (it
/// was missing from the pre-fix OR-chain), and `authenticationTimeout` was
/// missing from the comparison entirely.
#[tokio::test]
async fn auth_fields_the_pre_fix_reload_never_compared_are_reported() {
    let port = allocate_port();
    let server = Server::start(&probe_config(port, "token", T1, "")).await;

    let summary = server
        .rewrite_and_reload(&probe_config(
            port,
            "token",
            T1,
            "oidc_skip_nbf = true\nauthentication_timeout = 7\n",
        ))
        .await
        .expect("reload");

    assert!(
        summary.contains("OIDC settings changed (restart required)"),
        "oidc_skip_nbf is a verifier input and must be reported: {summary}"
    );
    assert!(
        summary.contains("auth.authenticationTimeout: 90 -> 7 (restart required)"),
        "the pre-fix comparison never read this field at all: {summary}"
    );
    assert_eq!(
        server.method(),
        AuthMethod::Token,
        "reporting a restart-required field must not change the running auth"
    );
    assert_eq!(server.token(), T1);
}

// ---------------------------------------------------------------
// `auth.tokenSource` — the dynamic half of the credential
// ---------------------------------------------------------------

/// A `tokenSource` change is applied **with** the token it resolves, and is not
/// reported as restart-required.
///
/// Pre-fix the source was never compared at all, so a `tokenSource` rewrite was
/// either `config reloaded: no changes detected` (same token in both files) or —
/// when the two files held different tokens — it was applied only because the
/// *resolved* token differed, which is not the same claim.
///
/// The shape below separates those two claims. Both files start out holding
/// `T1`, so the resolved token cannot be what decides anything; only after the
/// reload does file A change to `T2`. The server re-resolves the source on every
/// login (`AuthConfig::resolve_token`, called from the login path), so from then
/// on it is the **live `token_source`** that decides which token logs in: file B
/// (`T1`) if the reload applied the source, file A (`T2`) if it did not.
#[tokio::test]
async fn a_token_source_change_is_applied_as_part_of_the_credential() {
    let port = allocate_port();
    let files = tempfile::tempdir().expect("temp dir");
    let file_a = files.path().join("token-a");
    let file_b = files.path().join("token-b");
    std::fs::write(&file_a, T1).expect("write token file A");
    std::fs::write(&file_b, T1).expect("write token file B");

    let server = Server::start(&source_config(port, &file_a)).await;
    assert_eq!(server.token(), T1, "construction resolves the source");
    assert!(token_login(port, T1).await.is_ok());

    let summary = server
        .rewrite_and_reload(&source_config(port, &file_b))
        .await
        .expect("reload");
    assert!(
        summary.contains("auth token updated"),
        "a source change is a credential change even when it resolves the same \
         token: {summary}"
    );
    assert!(
        !summary.contains("restart required"),
        "the credential is applied in place: {summary}"
    );

    // Now make the two sources disagree, without touching the config file
    // again: only the live `token_source` decides which token is accepted.
    std::fs::write(&file_a, T2).expect("rewrite token file A");
    assert!(
        token_login(port, T1).await.is_ok(),
        "the live source must be file B: file A now holds {T2}"
    );
    assert!(
        token_login(port, T2).await.is_err(),
        "file A is no longer the live source, so its new value must not log in"
    );
}

// ---------------------------------------------------------------
// The dispatch invariant, driven to its broken state by hand
// ---------------------------------------------------------------

/// What the login path does with `method == Oidc` and **no** verifier.
///
/// The reload tests above pin that `reload` cannot reach that state any more
/// (`method_change_never_installs_a_method_without_a_verifier`), which is why
/// the login dispatch can keep keying off `Option<verifier>` rather than off
/// the method: the two spellings agree. This test writes the broken state
/// straight into the live state — the pre-fix Shape B state — and pins the
/// answer: the verifier-absent branch runs the **token** path, which fails
/// closed (`OIDC auth requires server-side verifier (not configured)`) rather
/// than accepting a token under an OIDC-labelled config.
///
/// What it does not cover: the OIDC branch itself (that needs a live issuer and
/// a verifier, see `oidc_integration.rs`), and any route to this state other
/// than the direct write below — none is known to exist.
#[tokio::test]
async fn token_login_fails_closed_if_the_method_says_oidc_without_a_verifier() {
    let port = allocate_port();
    let server = Server::start(&probe_config(port, "token", T1, "")).await;

    {
        let state = server.svc.state();
        let mut r = state.reloadable.write().expect("reloadable lock");
        // Mutation, not struct-update syntax: `AuthConfig` implements `Drop`
        // (the zeroizing token).
        let mut broken = (*r.auth_cfg).clone();
        broken.method = AuthMethod::Oidc;
        r.auth_cfg = Arc::new(broken);
    }
    assert_eq!(server.method(), AuthMethod::Oidc);
    assert!(!server.verifier_present());

    let err = token_login(port, T1)
        .await
        .expect_err("a token login must not be accepted by an OIDC-labelled config");
    assert!(
        err.contains("OIDC auth requires server-side verifier"),
        "the verifier-absent branch must be the token path, failing closed \
         with the OIDC-without-verifier error, not accepting the token: {err}"
    );
}
