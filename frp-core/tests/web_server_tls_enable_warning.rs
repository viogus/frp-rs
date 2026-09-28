//! `[web_server.tls] enable` warns on load — and the warning is asserted here,
//! in its own test binary, rather than in `frp-core/src/config/tests.rs`.
//!
//! **Why a separate target.** A `tracing` capture in the `frp-core` unit-test
//! binary is order-dependent: that binary runs ~980 tests in parallel, several of
//! which install or replace a subscriber, and the capture was measured failing
//! 2 of 3 full-suite runs (and passing when run alone, and in a serial run) while
//! costing ~7 s per attempt to observe — exactly the class of load-dependent test
//! flake the repo already carries an item for (`oidc_throttle_tests`). One test
//! per process removes the interference. The *inertness* half of the claim stays
//! in the unit suite (`nested_web_server_tls_enable_is_accepted_and_inert_in_both_modes`);
//! what lives here is the diagnostic: the event is emitted, once, and its text
//! names the key and the pair that actually drives the dashboard TLS.
//!
//! **What this models.** A real `load_server_config(path, false)` call on a real
//! file whose `[web_server.tls]` contains `enable = true`, with a
//! `tracing_subscriber::fmt` writer (the pattern `frp-core/src/protocol.rs` uses)
//! installed as the scoped default, then the same file with a cert/key pair added
//! to show the warning does not depend on the pair being absent.
//!
//! **What it does not cover.** The user-visible dashboard behaviour itself —
//! plaintext HTTP with no pair — which is `frp-server` end to end and was
//! measured by the fix-round review, not re-measured here; the other sinks a
//! deployment may configure; YAML/INI (the hoist and the warning are
//! format-independent, but only TOML is exercised); and — the gap that matters
//! most — **the warning is not delivered on either binary's `-c` path**, so this
//! test pins the message, not the diagnostic a user sees. Measured on the
//! v0.71.0 binaries (fix-round review R1, re-measured here): `frps -c <file>`
//! and `frpc -c <file>` emit **0** occurrences of the message (`RUST_LOG=debug`
//! included), while `frps --config-dir=<dir>` emits **1**, because the `-c` path
//! deliberately loads the config before `init_logging`
//! (`frps/src/main.rs:263` vs `:290`; `frpc/src/main.rs:561` vs `:583`) and this
//! warning is emitted from inside the loader. Moving it after logging on that
//! path (a `ConfigPresence` presence flag plus a warn in each binary) is filed in
//! `TODO.md`; until then, `docs/config.md` and `CHANGELOG.md` state the scope.

use std::io::{self, Write};
use std::sync::{Arc, Mutex};

use frp_core::config::load_server_config;

#[derive(Clone)]
struct CapturedLogs(Arc<Mutex<Vec<u8>>>);

impl Write for CapturedLogs {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Load `body` through the real loader with a capturing subscriber installed on
/// this thread, and return `(captured stderr text, inert flag, cert, key)`.
fn load_capturing(body: &str, strict: bool) -> (String, bool, String, String) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("frps.toml");
    std::fs::write(&path, body).unwrap();

    let output = Arc::new(Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .without_time()
        .with_writer({
            let output = output.clone();
            move || CapturedLogs(output.clone())
        })
        .finish();
    let guard = tracing::subscriber::set_default(subscriber);
    let cfg = load_server_config(path.to_str().unwrap(), strict)
        .unwrap_or_else(|e| panic!("strict={strict}: must load:\n{e}"));
    drop(guard);

    let logged = String::from_utf8(output.lock().unwrap().clone()).unwrap();
    (
        logged,
        cfg.web_server.tls.enable,
        cfg.web_server.tls_cert().to_string(),
        cfg.web_server.tls_key().to_string(),
    )
}

#[test]
fn nested_web_server_tls_enable_warns_once_and_stays_inert() {
    const HEADER: &str =
        "bind_port = 7000\ntoken = \"t\"\n[web_server]\naddr = \"127.0.0.1\"\nport = 7500\n";

    // `enable` alone: one warning, nothing stored, no cert.
    let (logged, inert, cert, key) =
        load_capturing(&format!("{HEADER}[web_server.tls]\nenable = true\n"), false);
    assert_eq!(
        logged.matches("web_server.tls.enable").count(),
        1,
        "exactly one warning per load; got: {logged}"
    );
    assert!(
        logged.contains("cert_file") && logged.contains("key_file"),
        "the warning names the pair that actually drives the dashboard TLS; got: {logged}"
    );
    assert!(!inert, "inert, not stored");
    assert_eq!(cert, "", "`enable` is not a cert path");
    assert_eq!(key, "");

    // The same shape in strict mode, and with a cert/key pair present: still
    // exactly one warning, still inert, and the pair still drives TLS.
    for strict in [false, true] {
        let (logged, inert, cert, key) = load_capturing(
            &format!(
                "{HEADER}[web_server.tls]\nenable = true\ncert_file = \"/tls/cert.pem\"\n\
                 key_file = \"/tls/key.pem\"\n"
            ),
            strict,
        );
        assert_eq!(
            logged.matches("web_server.tls.enable").count(),
            1,
            "strict={strict}: exactly one warning; got: {logged}"
        );
        assert!(!inert, "strict={strict}");
        assert_eq!(cert, "/tls/cert.pem", "strict={strict}");
        assert_eq!(key, "/tls/key.pem", "strict={strict}");
    }

    // A file without the key warns not at all — the warning is presence-driven,
    // not unconditional.
    let (logged, _, cert, _) = load_capturing(
        &format!("{HEADER}[web_server.tls]\ncert_file = \"/only/cert.pem\"\n"),
        false,
    );
    assert!(
        !logged.contains("web_server.tls.enable"),
        "no warning without the key; got: {logged}"
    );
    assert_eq!(cert, "/only/cert.pem");
}
