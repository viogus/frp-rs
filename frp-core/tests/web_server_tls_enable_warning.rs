//! `[web_server.tls] enable` — the **presence flag** the loader carries out and
//! the **message** the binaries emit from it, asserted in this file's own test
//! binary rather than in `frp-core/src/config/tests.rs`.
//!
//! **Why a separate target.** A `tracing` capture in the `frp-core` unit-test
//! binary is order-dependent: that binary runs ~980 tests in parallel, several of
//! which install or replace a subscriber, and the capture was measured failing
//! 2 of 3 full-suite runs (and passing when run alone, and in a serial run) while
//! costing ~7 s per attempt to observe — the interference here is genuinely
//! order-dependent, unlike the `oidc_throttle_tests` item this once cited as a
//! sibling class: that one was an accept-before-request-bytes race in its mock IdP,
//! deterministic on macOS (where the accepted socket inherits the listener's
//! non-blocking mode) and absent on Linux (where it does not), and fixed by making
//! the mock wait for the request head regardless of the inherited mode. One test
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
//! `-c` path the loader runs before `init_logging` (the single-config branch of
//! `frps/src/main.rs` and of `frpc/src/main.rs`: the load call, then
//! `init_logging`), so a `tracing::warn` from inside
//! the loader reaches no subscriber — measured on the v0.71.0 binaries as **0**
//! occurrences on `frps -c` / `frpc -c` and 1 on `--config-dir`, where that path
//! does install the sink first. The fix is therefore *one owner*: the loader
//! warns not at all, every load site that has a sink warns once after
//! `init_logging` is installed (the CLI startup paths, `frpc verify`, and the
//! in-process reloads in `frp-server`/`frp-client`), and no path double-warns. The `logged_during_load` assertions below pin the loader's
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
//! **Two variants, one per build.** The `web_server` reader lives behind
//! `frp-server`'s `dashboard` feature (the dashboard) and `frp-client`'s `admin`
//! feature (the client's admin server/API) — and `frp-core` has **neither**, so a
//! `#[cfg(feature = "dashboard")]` here would be constant `false` in every
//! configuration and pin nothing. The awareness is therefore supplied by the
//! caller: `warn_inert_web_server_tls_enable(has_dashboard)` emits the dashboard
//! variant when the caller compiles one and the no-dashboard variant when it does
//! not. The variants are the two constants this file exercises directly, and
//! `the_no_dashboard_build_names_no_dashboard_behaviour` pins both the text and
//! the selection; the callers pass `cfg!(feature = "dashboard")` (`frps`,
//! `frp-server`) or `cfg!(feature = "admin")` (`frpc`, `frp-client`).
//!
//! **What it does not cover.** Delivery on a real binary is
//! `frps/tests/warn_delivery.rs` and `frpc/tests/warn_delivery.rs` (real
//! binaries, `-c` and `--config-dir`, top-level and `[common]` spellings, stdout
//! and stderr captured separately, plus a real SIGUSR1 reload on the server
//! side); the client's **reload** is `frp-client/tests/reload_warning_delivery.rs`
//! (in-process because the client only processes a reload inside a live session);
//! the dashboard behaviour itself (plaintext HTTP with no pair) is `frp-server`
//! end to end and was measured by the fix-round review, not re-measured here; and
//! other sinks and YAML spellings are out of scope for this file. The `.ini`
//! spelling now reaches the detector too — the INI reader expands a dotted
//! section header whose first segment is a v1 section name into nested tables —
//! and is pinned in `frp-core/src/config/tests.rs` with the rest of the INI
//! format cases. The measured before/after table lives in `docs/config.md` and
//! `CHANGELOG.md`.

use std::io::{self, Write};
use std::sync::{Arc, Mutex};

use frp_core::config::{
    load_server_config_uncompleted_with_presence, ConfigPresence,
    WEB_SERVER_TLS_ENABLE_INERT_WARNING, WEB_SERVER_TLS_ENABLE_INERT_WARNING_NO_DASHBOARD,
};

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
///
/// Models a caller that **compiles a dashboard** — the `frps --features
/// dashboard` / `frpc --features admin` shape the pair clause describes. This
/// crate has no `dashboard` feature and so cannot derive that answer; the
/// no-dashboard shape is [`load_capturing_as`] with `has_dashboard = false`.
fn load_capturing(body: &str, strict: bool) -> Captured {
    load_capturing_as(body, strict, true)
}

/// [`load_capturing`] with the caller's build answer given explicitly, so the
/// no-dashboard variant is exercised too.
fn load_capturing_as(body: &str, strict: bool, has_dashboard: bool) -> Captured {
    load_capturing_files_as(&[("frps.toml", body)], strict, has_dashboard)
}

/// [`load_capturing`] with extra files in the same directory, so the `includes`
/// spelling (which is deep-merged before the detector runs) can be exercised.
fn load_capturing_files(files: &[(&str, &str)], strict: bool) -> Captured {
    load_capturing_files_as(files, strict, true)
}

fn load_capturing_files_as(files: &[(&str, &str)], strict: bool, has_dashboard: bool) -> Captured {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("frps.toml");
    for (name, body) in files {
        std::fs::write(dir.path().join(name), body).unwrap();
    }

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
    presence.warn_inert_web_server_tls_enable(has_dashboard);
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
        "the presence flag must survive the load (the loader removes `enable` from the value before serde)"
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

/// The **build** axis: a build with no dashboard must name no dashboard
/// behaviour, and the caller's answer must pick the variant.
///
/// `frp-core` has neither `frp-server`'s `dashboard` feature nor `frp-client`'s
/// `admin` feature, so it cannot resolve this itself — a
/// `#[cfg(feature = "dashboard")]` inside it would be constant `false` in every
/// configuration and would pin nothing. The caller answers instead, and these are
/// the two texts it chooses between. The first half pins the texts; the second
/// drives the real loader and entry point both ways, so a variant that ignored
/// `has_dashboard` — or a no-dashboard text that inherited a dashboard fact —
/// fails here.
#[test]
fn the_no_dashboard_build_names_no_dashboard_behaviour() {
    const NEEDLE: &str = "web_server.tls.enable has no effect";

    // Both texts are still the same diagnostic, and they are distinct: the
    // dispatch assertions below use `contains`, so one must not be a substring of
    // the other.
    for text in [
        WEB_SERVER_TLS_ENABLE_INERT_WARNING,
        WEB_SERVER_TLS_ENABLE_INERT_WARNING_NO_DASHBOARD,
    ] {
        assert!(
            text.contains(NEEDLE),
            "both variants name the key; got: {text}"
        );
    }
    assert!(
        !WEB_SERVER_TLS_ENABLE_INERT_WARNING
            .contains(WEB_SERVER_TLS_ENABLE_INERT_WARNING_NO_DASHBOARD)
            && !WEB_SERVER_TLS_ENABLE_INERT_WARNING_NO_DASHBOARD
                .contains(WEB_SERVER_TLS_ENABLE_INERT_WARNING),
        "the two variants must be distinct texts, not one a substring of the other"
    );

    // Facts that only a build with a dashboard may state.
    for fact in ["cert_file", "key_file", "plaintext HTTP"] {
        assert!(
            WEB_SERVER_TLS_ENABLE_INERT_WARNING.contains(fact),
            "the dashboard variant names `{fact}`"
        );
        assert!(
            !WEB_SERVER_TLS_ENABLE_INERT_WARNING_NO_DASHBOARD.contains(fact),
            "a build with no dashboard must not name `{fact}`; got: \
             {WEB_SERVER_TLS_ENABLE_INERT_WARNING_NO_DASHBOARD}"
        );
    }

    // What the no-dashboard variant says instead: the build's own inertness.
    for fact in ["no dashboard support", "no dashboard HTTPS server is built"] {
        assert!(
            WEB_SERVER_TLS_ENABLE_INERT_WARNING_NO_DASHBOARD.contains(fact),
            "the no-dashboard variant names `{fact}`; got: \
             {WEB_SERVER_TLS_ENABLE_INERT_WARNING_NO_DASHBOARD}"
        );
    }

    // The selection itself, through the real loader and entry point. Same body,
    // two caller answers, two different records.
    let body = "bind_port = 7000\ntoken = \"t\"\n[web_server]\naddr = \"127.0.0.1\"\nport = 7500\n\
                [web_server.tls]\nenable = true\n";

    let with_dashboard = load_capturing_as(body, false, true);
    assert!(with_dashboard.presence.web_server_tls_enable_set());
    assert_eq!(with_dashboard.warning_records, 1);
    assert!(
        with_dashboard
            .logged_by_warning_call
            .contains(WEB_SERVER_TLS_ENABLE_INERT_WARNING),
        "a dashboard build emits the dashboard variant; got: {}",
        with_dashboard.logged_by_warning_call
    );
    assert!(
        !with_dashboard
            .logged_by_warning_call
            .contains(WEB_SERVER_TLS_ENABLE_INERT_WARNING_NO_DASHBOARD),
        "a dashboard build must not emit the no-dashboard variant; got: {}",
        with_dashboard.logged_by_warning_call
    );

    let without_dashboard = load_capturing_as(body, false, false);
    assert!(without_dashboard.presence.web_server_tls_enable_set());
    assert_eq!(without_dashboard.warning_records, 1);
    assert!(
        without_dashboard
            .logged_by_warning_call
            .contains(WEB_SERVER_TLS_ENABLE_INERT_WARNING_NO_DASHBOARD),
        "a build with no dashboard emits the no-dashboard variant; got: {}",
        without_dashboard.logged_by_warning_call
    );
    assert!(
        !without_dashboard
            .logged_by_warning_call
            .contains(WEB_SERVER_TLS_ENABLE_INERT_WARNING),
        "a build with no dashboard must not emit the dashboard variant; got: {}",
        without_dashboard.logged_by_warning_call
    );
}

/// The `[common]` spelling and the `includes` spelling set the same flag.
///
/// `[common]` is flattened onto the top level by
/// `table.entry(k).or_insert(v)` **before** `normalize_web_server_section` runs,
/// so `[common.web_server.tls] enable` reaches the same removal site as
/// `[web_server.tls] enable`; the detector therefore has to mirror that flatten
/// (it reads the raw value, before normalization). Measured on the base binary:
/// `frps --config-dir` and `frpc --config-dir` with the `[common]` spelling each
/// emitted 1 record, exactly like the top-level spelling — so a detector that
/// only looked at the top level silently lost the record on that path (the
/// pre-fix-round state; probe `/tmp/enable-warn-probe/run-probe2.sh`).
///
/// The precedence is the flatten's own `or_insert`: a **top-level**
/// `[web_server]` already present makes the flatten discard
/// `common.web_server` whole — nested `tls` included — so that mixed shape must
/// **not** set the flag. That is the `[common]` flatten, which is *not* part of
/// the per-key sibling merge ([`both_sections_present_the_flag_follows_the_merge`]),
/// where `[web_server]` + `[webServer.tls]` now **does** set it.
#[test]
fn common_and_includes_spellings_set_the_flag() {
    // `[common.web_server.tls] enable`, whole dashboard section under `[common]`.
    let c = load_capturing(
        "bind_port = 7000\n[common.web_server]\naddr = \"127.0.0.1\"\nport = 7500\n\
         [common.web_server.tls]\nenable = true\n",
        false,
    );
    assert!(
        c.presence.web_server_tls_enable_set(),
        "`[common.web_server.tls] enable` reaches the same removal site"
    );
    assert_eq!(c.warning_records, 1);
    assert_eq!(c.cert, "");

    // The camelCase spelling under `[common]`.
    let c = load_capturing(
        "bind_port = 7000\n[common.webServer]\naddr = \"127.0.0.1\"\nport = 7500\n\
         [common.webServer.tls]\nenable = true\n",
        false,
    );
    assert!(
        c.presence.web_server_tls_enable_set(),
        "`[common.webServer.tls] enable`"
    );
    assert_eq!(c.warning_records, 1);

    // The inline-table form of the same thing.
    let c = load_capturing(
        "bind_port = 7000\ncommon = { web_server = { tls = { enable = true } } }\n",
        false,
    );
    assert!(
        c.presence.web_server_tls_enable_set(),
        "inline `common = {{ web_server = {{ tls = {{ enable = true }} }} }}`"
    );
    assert_eq!(c.warning_records, 1);

    // The same shape in an `includes` file: `process_includes` deep-merges it
    // into the main value before the detector runs, so it must be seen too.
    let c = load_capturing_files(
        &[
            ("frps.toml", "bind_port = 7000\nincludes = [\"inc.txt\"]\n"),
            ("inc.txt", "[common.web_server.tls]\nenable = true\n"),
        ],
        false,
    );
    assert!(
        c.presence.web_server_tls_enable_set(),
        "the `[common]` spelling inside an `includes` file"
    );
    assert_eq!(c.warning_records, 1);

    // Precedence: a top-level `[web_server]` makes the flatten discard
    // `common.web_server` whole, so this shape is inert *and* unflagged — the
    // detector must not report a key the loader dropped. Only the **same**
    // spelling is discarded: the two cross-spelling rows below keep the key and
    // do warn, because `web_server` and `webServer` are different keys, so the
    // flatten keeps both — and the detector reads the flag from the
    // pre-`normalize` value with its own `[common]` fallback
    // (`ConfigPresence::web_server_tls_enable_set_in`), not from the per-key
    // merge that runs afterwards.
    let c = load_capturing(
        "bind_port = 7000\n[web_server]\naddr = \"127.0.0.1\"\nport = 7500\n\
         [common.web_server.tls]\nenable = true\n",
        false,
    );
    assert!(
        !c.presence.web_server_tls_enable_set(),
        "a top-level `[web_server]` makes the flatten drop `common.web_server` whole"
    );
    assert_eq!(c.warning_records, 0);

    // Cross-spelling: the `[common]` section keeps its own spelling, the
    // top-level one is the other spelling, and the detector's `[common]`
    // fallback finds the key — before any per-key merge runs.
    let c = load_capturing(
        "bind_port = 7000\n[webServer]\naddr = \"127.0.0.1\"\nport = 7500\n\
         [common.web_server.tls]\nenable = true\n",
        false,
    );
    assert!(
        c.presence.web_server_tls_enable_set(),
        "`[common.web_server.tls] enable` beside a top-level `[webServer]` is not discarded"
    );
    assert_eq!(c.warning_records, 1);

    let c = load_capturing(
        "bind_port = 7000\n[web_server]\naddr = \"127.0.0.1\"\nport = 7500\n\
         [common.webServer.tls]\nenable = true\n",
        false,
    );
    assert!(
        c.presence.web_server_tls_enable_set(),
        "`[common.webServer.tls] enable` beside a top-level `[web_server]` is not discarded"
    );
    assert_eq!(c.warning_records, 1);
}

/// The flag's detector reproduces the normalizers' section resolution:
/// `[webServer]` and `[web_server]` are the same section and are merged **per
/// key**, with the snake_case section winning each key it defines and nested
/// tables merging recursively (`merge_section_into`). So `enable` written only
/// under `[webServer.tls]` beside a `[web_server]` section **is** seen — the
/// camelCase `tls` table is no longer discarded whole — and the warning fires
/// once. The old whole-table discard (and a detector that mirrored it) is the
/// `TODO.md` item this fixes; the flag must follow the loader, never claim a key
/// the loader drops nor miss one it keeps.
#[test]
fn both_sections_present_the_flag_follows_the_merge() {
    // Only the camelCase table carries `enable`: it merges into `web_server.tls`
    // and reaches the removal site -> flag set, one record.
    let c = load_capturing(
        "bind_port = 7000\n[web_server]\naddr = \"127.0.0.1\"\nport = 7500\n\
         [webServer.tls]\nenable = true\n",
        false,
    );
    assert!(
        c.presence.web_server_tls_enable_set(),
        "the camelCase `tls` table merges per key into `web_server.tls`"
    );
    assert_eq!(c.warning_records, 1);

    // Both tables, separate keys: both survive — `enable` from the snake table,
    // the cert from the camel one.
    let c = load_capturing(
        "bind_port = 7000\n[web_server]\naddr = \"127.0.0.1\"\nport = 7500\n\
         [web_server.tls]\nenable = true\n[webServer.tls]\ncert_file = \"/camel.pem\"\n",
        false,
    );
    assert!(
        c.presence.web_server_tls_enable_set(),
        "the snake_case table carries `enable`"
    );
    assert_eq!(c.warning_records, 1);
    assert_eq!(
        c.cert, "/camel.pem",
        "the camelCase table's cert merges in too — nothing is discarded whole"
    );

    // A key **both** tables define: the snake_case section wins, as the old
    // whole-table `or_insert` resolved it — the order is not inverted.
    let c = load_capturing(
        "bind_port = 7000\n[web_server]\naddr = \"127.0.0.1\"\nport = 7500\n\
         [web_server.tls]\ncert_file = \"/snake.pem\"\n\
         [webServer.tls]\ncert_file = \"/camel.pem\"\n",
        false,
    );
    assert_eq!(c.cert, "/snake.pem");
    assert!(!c.presence.web_server_tls_enable_set());
    assert_eq!(c.warning_records, 0);

    // A `web_server.tls` that is present but **not a table**: `or_insert_deep`
    // drops the camelCase `tls` sub-table whole, so the `enable` inside it never
    // reaches the removal site and the flag must stay unset. Without the
    // matching arm the detector claimed a key the loader had dropped (measured
    // on the frozen tree: 1 record, both modes all-default).
    let c = load_capturing(
        "bind_port = 7000\n[web_server]\naddr = \"127.0.0.1\"\nport = 7500\ntls = \"scalar\"\n\
         [webServer.tls]\nenable = true\n",
        false,
    );
    assert!(
        !c.presence.web_server_tls_enable_set(),
        "the scalar `web_server.tls` makes the merge drop the camelCase `tls` table"
    );
    assert_eq!(c.warning_records, 0);
    assert_eq!(c.cert, "", "and the loader really did drop it");

    // The mirror image: a real snake table with no `enable` still receives the
    // camelCase `tls` table's keys (the merge recurses into tables both sides
    // define), so `enable` reaches the removal site and does warn.
    let c = load_capturing(
        "bind_port = 7000\n[web_server]\naddr = \"127.0.0.1\"\nport = 7500\n\
         [web_server.tls]\ncert_file = \"/snake.pem\"\n[webServer.tls]\nenable = true\n",
        false,
    );
    assert!(
        c.presence.web_server_tls_enable_set(),
        "the camelCase `tls` table merges into the snake one"
    );
    assert_eq!(c.warning_records, 1);
    assert_eq!(c.cert, "/snake.pem");
}

/// The **string** loader is silent too, and does not surface the flag at all.
///
/// This pins the other half of the "one owner" decision: the diagnostic lives on
/// the load sites that have a log sink — the CLI startup paths (`frps`/`frpc`
/// run), `frpc verify`, both in-process reloads, and the `frpc` admin API's
/// config **GET** — not in the library loaders. The GET's emitter is
/// `frp-client/src/admin.rs`'s `config_from_file`, which now loads through
/// `load_client_config_with_presence` and calls
/// `ConfigPresence::warn_inert_web_server_tls_enable` itself, deduplicated so a
/// polled GET warns once per **state change** rather than once per request (that
/// file pins the dedup). It is *not* this string loader: the string loader is
/// what `frpc verify`'s and the admin PUT's validate step use, and neither may
/// emit from here (the CLI paths emit after `init_logging`).
///
/// The admin **PUT** (`handle_put_config`) validates through this very string
/// loader (silent) and then triggers the service reload, so it delivers once per
/// request via the reload site. Out-of-repo consumers of
/// `load_*_config_from_str` remain silent.
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
