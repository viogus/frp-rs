//! `[web_server.tls] enable` — the **presence flag** the loader carries out and
//! the **message** the binaries emit from it, asserted in this file's own test
//! binary rather than in `frp-core/src/config/tests.rs`.
//!
//! **Why a separate target.** A `tracing` capture in the `frp-core` unit-test
//! binary is order-dependent: that binary runs ~980 tests in parallel, several of
//! which install or replace a subscriber, and the capture was measured failing
//! 2 of 3 full-suite runs (and passing when run alone, and in a serial run) while
//! costing ~7 s per attempt to observe — exactly the class of load-dependent test
//! flake the repo already carries an item for (`oidc_throttle_tests`). One test
//! per process removes the interference. The *inertness* half of the claim stays
//! in the unit suite (`nested_web_server_tls_enable_is_accepted_and_inert_in_both_modes`);
//! what lives here is the diagnostic: the presence flag survives the load, the
//! loader itself is **silent**, and the entry point the binaries call emits the
//! message exactly once.
//!
//! **What this models.** A real `load_server_config_uncompleted_with_presence`
//! call on a real file whose `[web_server.tls]` contains `enable`, with a
//! `tracing_subscriber::fmt` writer (the pattern `frp-core/src/protocol.rs` uses)
//! installed as the scoped default and **still installed** for the subsequent
//! `ConfigPresence::warn_inert_web_server_tls_enable` — the same call `frps`/`frpc`
//! make after `init_logging`.
//!
//! **Why the emission is not in the loader (the decision, pinned here).** On the
//! `-c` path the loader runs before `init_logging` (`frps/src/main.rs:263` vs
//! `:290`; `frpc/src/main.rs:561` vs `:583`), so a `tracing::warn` from inside
//! the loader reaches no subscriber — measured on the v0.71.0 binaries as **0**
//! occurrences on `frps -c` / `frpc -c` and 1 on `--config-dir`, where that path
//! does install the sink first. The fix is therefore *one owner*: the loader
//! warns not at all, each binary warns once after its own `init_logging`, and no
//! path double-warns. The `logged_during_load` assertions below pin the loader's
//! silence (a re-added `tracing::warn!` in `normalize_web_server_section` fails
//! here); the rest pin the flag and the message.
//!
//! **Warned whenever the key is written, pair or no pair.** The key is inert in
//! all four combinations, so "does `enable` do anything" is false in all four.
//! Gating on the pair would silence `enable = false` beside a valid pair — the
//! shape where TLS stays **on** against the written value, which is exactly why
//! the "wire `enable` to the pair" alternative was rejected — and that is the
//! case where this warning is the only signal. The cost is one inert-but-harmless
//! record for `enable = false` with no pair. All four are pinned below; the
//! message text is written to be true in every one of them.
//!
//! **What it does not cover.** Delivery on a real binary is
//! `frps/tests/warn_delivery.rs` and `frpc/tests/warn_delivery.rs` (real
//! binaries, `-c` and `--config-dir`, stdout and stderr captured separately); the
//! dashboard behaviour itself (plaintext HTTP with no pair) is `frp-server` end to
//! end and was measured by the fix-round review, not re-measured here; and other
//! sinks, YAML/INI spellings (only TOML is exercised) and `--config-dir` are out
//! of scope for this file. The measured before/after table lives in
//! `docs/config.md` and `CHANGELOG.md`.

use std::io::{self, Write};
use std::sync::{Arc, Mutex};

use frp_core::config::{load_server_config_uncompleted_with_presence, ConfigPresence};

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

/// One captured load: the text emitted **during the load**, the text the
/// `warn_inert_web_server_tls_enable` call appended (with its record count), the
/// presence flag, and the effective cert/key pair.
struct Captured {
    logged_during_load: String,
    warning_records: usize,
    logged_by_warning_call: String,
    presence: ConfigPresence,
    cert: String,
    key: String,
}

fn snapshot(output: &Arc<Mutex<Vec<u8>>>) -> String {
    String::from_utf8(output.lock().unwrap().clone()).unwrap()
}

/// Load `body` through the real loader and then call the binaries' entry point,
/// all under one capturing subscriber, and return what each phase emitted.
fn load_capturing(body: &str, strict: bool) -> Captured {
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
    let (mut cfg, presence) =
        load_server_config_uncompleted_with_presence(path.to_str().unwrap(), strict)
            .unwrap_or_else(|e| panic!("strict={strict}: must load:\n{e}"));

    // Snapshot before the entry point runs, so "the loader is silent" is a real
    // assertion rather than an inference from the total.
    let logged_during_load = snapshot(&output);
    cfg.complete();
    let cert = cfg.web_server.tls_cert().to_string();
    let key = cfg.web_server.tls_key().to_string();

    let before = output.lock().unwrap().len();
    presence.warn_inert_web_server_tls_enable();
    let appended = String::from_utf8(output.lock().unwrap()[before..].to_vec()).unwrap();
    drop(guard);

    Captured {
        warning_records: appended.matches("web_server.tls.enable").count(),
        logged_by_warning_call: appended,
        logged_during_load,
        presence,
        cert,
        key,
    }
}

#[test]
fn nested_web_server_tls_enable_warns_once_and_stays_inert() {
    const HEADER: &str =
        "bind_port = 7000\ntoken = \"t\"\n[web_server]\naddr = \"127.0.0.1\"\nport = 7500\n";

    // `enable = true`, no pair: the loader is silent, the flag is set, nothing is
    // stored, no cert, and the binary's call emits exactly one record naming both
    // the key and the pair that actually drives the dashboard TLS.
    let c = load_capturing(&format!("{HEADER}[web_server.tls]\nenable = true\n"), false);
    assert!(
        !c.logged_during_load.contains("web_server.tls.enable"),
        "the loader must stay silent — the sink does not exist on the `-c` path; got: {}",
        c.logged_during_load
    );
    assert!(
        c.presence.web_server_tls_enable_set(),
        "the presence flag must survive the load (the nested table is removed from the value)"
    );
    assert_eq!(
        c.warning_records, 1,
        "exactly one warning per load; got: {}",
        c.logged_by_warning_call
    );
    assert!(
        c.logged_by_warning_call.contains("cert_file")
            && c.logged_by_warning_call.contains("key_file"),
        "the warning names the pair that actually drives the dashboard TLS; got: {}",
        c.logged_by_warning_call
    );
    assert!(
        c.logged_by_warning_call.contains("plaintext HTTP"),
        "with no pair the warning must say what the dashboard actually serves; got: {}",
        c.logged_by_warning_call
    );

    // The four `enable`/pair combinations. Every one of them sets the flag and
    // emits exactly one record — the key is inert in all four, and the
    // `enable = false` + pair shape is the one where TLS stays **on** against the
    // written value, so it must not be silenced.
    for (enable, pair) in [(true, false), (true, true), (false, false), (false, true)] {
        for strict in [false, true] {
            let body = if pair {
                format!(
                    "{HEADER}[web_server.tls]\nenable = {enable}\ncert_file = \"/tls/cert.pem\"\n\
                     key_file = \"/tls/key.pem\"\n"
                )
            } else {
                format!("{HEADER}[web_server.tls]\nenable = {enable}\n")
            };
            let c = load_capturing(&body, strict);
            assert!(
                !c.logged_during_load.contains("web_server.tls.enable"),
                "enable={enable} pair={pair} strict={strict}: loader silent"
            );
            assert!(
                c.presence.web_server_tls_enable_set(),
                "enable={enable} pair={pair} strict={strict}: flag set"
            );
            assert_eq!(
                c.warning_records, 1,
                "enable={enable} pair={pair} strict={strict}: exactly one warning; got: {}",
                c.logged_by_warning_call
            );
            assert_eq!(
                c.cert,
                if pair { "/tls/cert.pem" } else { "" },
                "enable={enable} pair={pair} strict={strict}: `enable` is not a cert path"
            );
            assert_eq!(
                c.key,
                if pair { "/tls/key.pem" } else { "" },
                "enable={enable} pair={pair} strict={strict}: `enable` is not a key path"
            );
        }
    }

    // A file without the key: no flag, so the entry point emits nothing — the
    // warning is presence-driven, not unconditional.
    let c = load_capturing(
        &format!("{HEADER}[web_server.tls]\ncert_file = \"/only/cert.pem\"\n"),
        false,
    );
    assert!(!c.presence.web_server_tls_enable_set());
    assert_eq!(
        c.warning_records, 0,
        "no warning without the key; got: {}",
        c.logged_by_warning_call
    );
    assert_eq!(c.cert, "/only/cert.pem");

    // The camelCase section spelling reaches the same flag: `[webServer.tls]` is
    // renamed onto `[web_server]` before the mapping runs.
    let c = load_capturing(
        "bind_port = 7000\n[webServer]\naddr = \"127.0.0.1\"\nport = 7500\n[webServer.tls]\nenable = true\n",
        false,
    );
    assert!(
        c.presence.web_server_tls_enable_set(),
        "camelCase section spelling sets the same flag"
    );
    assert_eq!(c.warning_records, 1);

    // A parent-level `certFile` beside a nested section that does **not** write
    // `enable` does not set the flag: only the nested `enable` key does.
    let c = load_capturing(
        "bind_port = 7000\ntoken = \"t\"\n[web_server]\naddr = \"127.0.0.1\"\nport = 7500\n\
         certFile = \"/flat.pem\"\n[web_server.tls]\nkey_file = \"/k.pem\"\n",
        false,
    );
    assert!(!c.presence.web_server_tls_enable_set());
    assert_eq!(c.warning_records, 0);
}

/// The flag's detector reproduces the normalizers' section-rename precedence
/// (`table.entry("web_server").or_insert(v)`): when both sections exist the
/// snake_case one is kept **whole** and the camelCase one is discarded, nested
/// `tls` included. So `enable` written only under `[webServer.tls]` must not set
/// the flag — the key is dropped with the rest of that table — while the same
/// key under `[web_server.tls]` must. (The underlying discard is filed in
/// `TODO.md`, not fixed here; this pins that the *warning* follows the same rule
/// the loader does, so it can never claim a key the loader keeps.)
#[test]
fn both_sections_present_the_flag_follows_the_kept_section() {
    // Only the discarded camelCase table carries `enable` -> no flag.
    let c = load_capturing(
        "bind_port = 7000\n[web_server]\naddr = \"127.0.0.1\"\nport = 7500\n\
         [webServer.tls]\nenable = true\n",
        false,
    );
    assert!(
        !c.presence.web_server_tls_enable_set(),
        "the camelCase table is discarded whole by the rename"
    );
    assert_eq!(c.warning_records, 0);

    // The kept snake_case table carries it -> flag set.
    let c = load_capturing(
        "bind_port = 7000\n[web_server]\naddr = \"127.0.0.1\"\nport = 7500\n\
         [web_server.tls]\nenable = true\n[webServer.tls]\ncert_file = \"/discarded.pem\"\n",
        false,
    );
    assert!(
        c.presence.web_server_tls_enable_set(),
        "the snake_case table is the one kept"
    );
    assert_eq!(c.warning_records, 1);
    assert_eq!(
        c.cert, "",
        "the discarded camelCase table's cert must not reach the config"
    );
}

/// The **string** loader is silent too, and does not surface the flag at all.
///
/// This pins the other half of the "one owner" decision: the diagnostic lives on
/// the CLI startup paths (`frps`/`frpc` run) and `frpc verify`, not in the
/// library. The one in-repo caller that reaches `load_client_config_from_str`
/// with a subscriber already installed is the `frpc` admin API's
/// validate-before-write (`frp-client/src/admin.rs`), which used to see the
/// record come out of the loader; it no longer does. That is deliberate — the
/// endpoint's job is to accept or refuse a body, and the reload path reports the
/// settings it cannot apply — but it is a real scope reduction, so it is pinned
/// here rather than left to be discovered. A future decision to warn from the
/// library has to change this test.
#[test]
fn the_string_loader_stays_silent() {
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
    let cfg = frp_core::config::load_client_config_from_str(
        "server_addr = \"127.0.0.1\"\nserver_port = 7000\n[web_server]\nport = 7500\n\
         [web_server.tls]\nenable = true\n",
    )
    .expect("loads");
    drop(guard);
    let logged = snapshot(&output);
    assert!(
        !logged.contains("web_server.tls.enable"),
        "the string loader must stay silent (the binaries own the record); got: {logged}"
    );
    assert!(!cfg.web_server.tls.enable, "still inert");
}
