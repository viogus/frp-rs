//! The server's flat `tls_enable` — the **presence flag** the loader carries out
//! and the **message** the binaries emit from it, asserted in this file's own
//! test binary rather than in `frp-core/src/config/tests.rs`.
//!
//! **Why a separate target.** Same reason as the sibling
//! `web_server_tls_enable_warning.rs`: a `tracing` capture inside the `frp-core`
//! unit binary is order-dependent (that binary runs ~980 tests in parallel, and
//! several install or replace a subscriber), so a load-dependent capture there is
//! a flake. One test per process removes the interference; the *inertness* half
//! of the claim (no reader of `ServerConfig::tls_enable`) is a grep over
//! `frp-server/src` + `frps/src` recorded in the item, not something a runtime
//! test can assert.
//!
//! **What this models.** A real `load_server_config_uncompleted_with_presence`
//! call on a real file, with a `tracing_subscriber::fmt` writer installed as the
//! scoped default and **still installed** for the subsequent
//! `ConfigPresence::warn_inert_server_tls_enable` — the same call `frps` and
//! `frp-server`'s reload make after `init_logging`.
//!
//! **Which spellings count, and which do not.** `ServerConfig::tls_enable` is a
//! flat field with `#[serde(default)]` and **no alias**
//! (`frp-core/src/config/server.rs:42-43`), unlike `bind_port`'s `bindPort`. The
//! keys a user can write that land in it are: the snake_case `tls_enable` at the
//! top level, `tls_enable` under `[common]` (flattened by
//! `normalize_server_config` via `table.entry(k).or_insert(v)`, so the top-level
//! key wins), and a literal `tls_enable` inside `[transport.tls]` — the lift
//! renames its five Go keys
//! (`force`/`certFile`/`keyFile`/`trustedCaFile`/`serverName`, the match at
//! `frp-core/src/config/normalize.rs:869-878`) and passes everything else through
//! unchanged, so that key is hoisted onto the
//! same field. Either way the key was *written*. A nested
//! `[common.transport.tls] tls_enable` counts **only when no top-level
//! `transport` key is written**, because `[common]`'s flatten is `or_insert` on
//! the whole value (`frp-core/src/config/normalize.rs:652-655`) — a leading
//! `[transport]` table discards `[common]`'s whole, so the key is dropped before
//! the lift and the detector must stay silent (pinned by
//! `common_transport_tls_needs_no_competing_top_level_transport`). An `includes`
//! file counts too: `process_includes` deep-merges before the detector runs. The
//! camelCase `tlsEnable` never matches — it is absent from `known_server_keys()`,
//! so the lenient loader drops it (the field keeps its `false` default, which is
//! "unrecognized", not "inert") and the strict loader refuses it.
//!
//! **Why a written key warns but a synthesized one does not.** The server
//! normalizer *synthesizes* `tls_enable = true` from the legacy
//! `[transport.tls]` section when it carries `force = true`, `certFile` or
//! `keyFile` (`frp-core/src/config/normalize.rs:865-884`,
//! `table.entry("tls_enable").or_insert(…)`) — a Go-shaped input, not a user
//! writing the frp-rs-only field. After normalization the two are
//! indistinguishable, so `ConfigPresence::server_tls_enable_set_in` reads the
//! **raw** value. The `[transport.tls] enable` spelling is a deliberately
//! *unrecognized* neighbour: the *server* lift has no `"enable"` arm (only the
//! client's does, at `frp-core/src/config/normalize.rs:1429-1437`), so it stays a
//! top-level key literally named `enable` — ignored leniently, refused strictly —
//! and never sets `tls_enable` at all. Every case is pinned below.
//!
//! **What it does not cover.** Delivery on a real binary is
//! `frps/tests/warn_delivery.rs` (real `frps`, `-c` and `--config-dir`, stdout and
//! stderr captured separately, plus a real SIGUSR1 reload adding a record). The
//! client side is deliberately **not** covered because it must stay silent:
//! `ClientConfig::tls_enable` is live (`frp-client/src/control.rs:389-395` reads
//! it), so no `frpc`/`frp-client` site calls `warn_inert_server_tls_enable`, and
//! that absence is pinned by the existing `frpc` warning-delivery tests plus the
//! grep recorded in the item. YAML and `.ini` spellings are out of scope (only
//! TOML is exercised).
//!
//! **The two variants are covered by two different lanes, not by one run.** The
//! `#[cfg]` split means a default-features run asserts only the `tls` text and a
//! `--no-default-features` run only the no-TLS text: `.github/workflows/ci.yml:191-194`
//! (`cargo test -p frp-core`, default features) covers the `tls` variant, and
//! `.github/workflows/ci.yml:195-226` (`cargo test -p frp-core --no-default-features
//! --all-targets`, the `run:` at `.github/workflows/ci.yml:226`) covers the no-TLS
//! one. A change to either text is therefore only seen by the
//! lane whose feature set selects it.

use std::io::{self, Write};
use std::sync::{Arc, Mutex};

use frp_core::config::{
    load_server_config_from_str, load_server_config_uncompleted_with_presence, ConfigPresence,
    SERVER_TLS_ENABLE_INERT_WARNING,
};
// The clause arrays the shipped text is *defined* as: the whole-text assertions
// below derive their expected value from these instead of copying the text, so a
// reworded clause cannot leave a stale literal behind in this file.
#[cfg(not(feature = "tls"))]
use frp_core::config::SERVER_TLS_ENABLE_INERT_NO_TLS_CLAUSES;
#[cfg(feature = "tls")]
use frp_core::config::SERVER_TLS_ENABLE_INERT_TLS_CLAUSES;

/// The stable substring every assertion counts. If the `tracing::warn!` call is
/// removed the counts drop to zero; if the message is reworded so this stops
/// appearing, the tests fail on the needle rather than passing vacuously.
const NEEDLE: &str = "tls_enable has no effect on the server";

/// Deliberate goldens for the **rendered bytes**. The clause arrays above are the
/// definition, and the whole-text assertions derive from them — so on their own
/// they move *with* the definition and cannot see a reworded or reordered clause
/// (measured: swapping the two `tls` clauses, or `reads it.` → `reads it at
/// all.`, left every derived assertion green while the rendered message
/// changed). These two literals are the bytes actually shipped by the build the
/// `tls` feature selects: **update them deliberately** when the wording is
/// intentionally changed, and never re-derive them from the array — that is the
/// whole point.
///
/// The hash is FNV-1a 64, chosen because it is stable by specification: not
/// `std::hash::DefaultHasher` (its output is explicitly not stable across
/// releases) and not `sha2` (not a dependency of this crate — it is in
/// `Cargo.lock` only through the vendored `russh`).
#[cfg(feature = "tls")]
const TLS_RENDERED_LEN: usize = 433;
#[cfg(feature = "tls")]
const TLS_RENDERED_FNV1A: u64 = 0x0a17_2261_4d74_606e;
#[cfg(not(feature = "tls"))]
const NO_TLS_RENDERED_LEN: usize = 186;
#[cfg(not(feature = "tls"))]
const NO_TLS_RENDERED_FNV1A: u64 = 0x948e_8cf8_368e_4c41;

/// FNV-1a (64-bit) over the string's UTF-8 bytes; see the goldens above.
fn fnv1a(s: &str) -> u64 {
    const OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    s.as_bytes().iter().fold(OFFSET_BASIS, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(PRIME)
    })
}

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
/// `warn_inert_server_tls_enable` call appended (with its record count), the
/// presence flag, and the effective server fields the warning talks about.
struct Captured {
    logged_during_load: String,
    warning_records: usize,
    logged_by_warning_call: String,
    presence: ConfigPresence,
    tls_enable: bool,
    tls_only: bool,
    cert: String,
    key: String,
}

fn snapshot(output: &Arc<Mutex<Vec<u8>>>) -> String {
    String::from_utf8(output.lock().unwrap().clone()).unwrap()
}

/// Load `body` through the real loader and then call the binaries' entry point,
/// all under one capturing subscriber, and return what each phase emitted.
fn load_capturing(body: &str, strict: bool) -> Captured {
    load_capturing_files(&[("frps.toml", body)], strict)
}

/// [`load_capturing`] with extra files in the same directory, so the `includes`
/// spelling (deep-merged before the detector runs) can be exercised.
fn load_capturing_files(files: &[(&str, &str)], strict: bool) -> Captured {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("frps.toml");
    for (name, body) in files {
        std::fs::write(dir.path().join(name), body).unwrap();
    }

    let output = Arc::new(Mutex::new(Vec::new()));
    let subscriber = subscriber_for(&output);
    let guard = tracing::subscriber::set_default(subscriber);
    let (mut cfg, presence) =
        load_server_config_uncompleted_with_presence(path.to_str().unwrap(), strict)
            .unwrap_or_else(|e| panic!("strict={strict}: must load:\n{e}"));

    // Snapshot before the entry point runs, so "the loader is silent" is a real
    // assertion rather than an inference from the total.
    let logged_during_load = snapshot(&output);
    cfg.complete();

    let before = output.lock().unwrap().len();
    presence.warn_inert_server_tls_enable();
    let appended = String::from_utf8(output.lock().unwrap()[before..].to_vec()).unwrap();
    drop(guard);

    Captured {
        warning_records: appended.matches(NEEDLE).count(),
        logged_by_warning_call: appended,
        logged_during_load,
        presence,
        tls_enable: cfg.tls_enable,
        tls_only: cfg.tls_only,
        cert: cfg.tls_cert_file.clone(),
        key: cfg.tls_key_file.clone(),
    }
}

/// The strict-mode failure shape: load under a capturing subscriber, expect the
/// load to be refused, and return the error text. The warning is never reached
/// (there is no `ConfigPresence`), which is itself the point: a refused key is
/// not a written-and-inert key.
fn load_capturing_expect_err(body: &str) -> String {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("frps.toml");
    std::fs::write(&path, body).unwrap();
    let output = Arc::new(Mutex::new(Vec::new()));
    let subscriber = subscriber_for(&output);
    let guard = tracing::subscriber::set_default(subscriber);
    let err = load_server_config_uncompleted_with_presence(path.to_str().unwrap(), true)
        .expect_err("strict mode must refuse this key")
        .to_string();
    assert_eq!(
        snapshot(&output),
        "",
        "a refused load emits nothing; there is no presence to warn from"
    );
    drop(guard);
    err
}

/// A load that must fail for a **non-strict** reason (e.g. a wrongly typed
/// `transport`), under the same capturing subscriber; returns the error text and
/// the (empty) capture, so "the detector was never reached" is asserted rather
/// than inferred.
fn load_capturing_expect_load_err(body: &str) -> (String, String) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("frps.toml");
    std::fs::write(&path, body).unwrap();
    let output = Arc::new(Mutex::new(Vec::new()));
    let subscriber = subscriber_for(&output);
    let guard = tracing::subscriber::set_default(subscriber);
    let err = load_server_config_uncompleted_with_presence(path.to_str().unwrap(), false)
        .expect_err("this shape must fail to load")
        .to_string();
    let logged = snapshot(&output);
    drop(guard);
    (err, logged)
}

fn subscriber_for(
    output: &Arc<Mutex<Vec<u8>>>,
) -> impl tracing::Subscriber + Send + Sync + 'static {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .without_time()
        .with_writer({
            let output = output.clone();
            move || CapturedLogs(output.clone())
        })
        .finish()
}

/// The message must be true in every configuration that fires it — and in every
/// **build** that fires it. Two variants are selected by the `tls` feature
/// (`frp-server`'s acceptor block is `#[cfg(feature = "tls")]` while the warning
/// is not, and `release.yml` ships `frps-micro`, which has no `tls`), so this
/// splits its assertions the same way.
///
/// Measured on the real binary (`/tmp/tls-warn-probe/run-b.sh` and
/// `run-reload.sh`, stdout and stderr captured separately): in a `tls` build
/// neither file → exit 0 and `TLS enabled with auto-generated self-signed
/// certificate`; both files → exit 0 and `TLS enabled with cert: <path>`;
/// exactly one → exit **1** and `Failed to initialize TLS: transport error: TLS
/// requires both cert_file and key_file to be set; got only one`; both paths
/// unreadable → exit **1** and `open cert file: No such file or directory`; and
/// on a SIGUSR1 reload that introduces either shape the server **keeps running**
/// with `TLS certificate reload FAILED: … (keeping old config)`. On the real
/// `frps-micro` (`run-micro.sh`) `tls_enable = true` + only `tls_cert_file`
/// exits **0** and logs `frps listener started on 0.0.0.0:27331` — no refusal,
/// and no auto-generated line with neither file — which is why the no-TLS
/// variant names no certificate behaviour. The old "non-empty pair" claim was
/// false for the very config that fires it (F1 regression guard).
#[test]
fn the_message_names_the_inertness_the_real_switch_and_the_certificate() {
    // `SERVER_TLS_ENABLE_INERT_WARNING` is a `LazyLock<String>` (the clause array
    // joined), so bind the `&str` the assertions interpolate.
    let warning = SERVER_TLS_ENABLE_INERT_WARNING.as_str();
    assert!(
        SERVER_TLS_ENABLE_INERT_WARNING.contains(NEEDLE),
        "the const must carry the needle the tests count: {warning}"
    );
    assert!(
        SERVER_TLS_ENABLE_INERT_WARNING.contains("nothing in frp-server or frps reads it"),
        "both variants must name the inertness: {warning}"
    );

    // A `tls` build names the pair's real outcomes, both delivery paths.
    #[cfg(feature = "tls")]
    for fact in [
        "`tls_only`",
        "`tls_cert_file`",
        "`tls_key_file`",
        "refused at startup",
        "a reload reports the failure and keeps the running acceptor",
        "auto-generates a self-signed certificate pair",
    ] {
        assert!(
            SERVER_TLS_ENABLE_INERT_WARNING.contains(fact),
            "the message must name {fact:?}: {warning}"
        );
    }

    // …and the whole text, not just a list of clauses: a substring allow-list
    // cannot see a clause being **appended** or **dropped** — under both mutants
    // the list above passed and only the assertion below failed (measured).
    //
    // The expected value is **derived** from the clause array the shipped text is
    // defined as (`SERVER_TLS_ENABLE_INERT_TLS_CLAUSES` joined with one space), so
    // there is no third copy to go stale: a reworded clause moves both together,
    // while the clause-count pin below still reds if one is appended or dropped.
    #[cfg(feature = "tls")]
    assert_eq!(
        warning,
        SERVER_TLS_ENABLE_INERT_TLS_CLAUSES.join(" "),
        "the `tls` variant must be exactly its clause array joined by one space"
    );
    #[cfg(feature = "tls")]
    assert_eq!(
        SERVER_TLS_ENABLE_INERT_TLS_CLAUSES.len(),
        2,
        "a clause was appended to or dropped from the `tls` array — the substring \
         list above cannot detect that"
    );
    // …and the **rendered bytes**, which the derived assertion above cannot see: a
    // reworded clause or a reordered array keeps the derivation green while the
    // shipped message changes. These goldens are the bytes to update deliberately
    // (see `TLS_RENDERED_LEN`), never re-derive them from the array.
    #[cfg(feature = "tls")]
    assert_eq!(
        warning.len(),
        TLS_RENDERED_LEN,
        "the rendered `tls` message changed length — if the new wording is intended, update \
         the golden deliberately"
    );
    #[cfg(feature = "tls")]
    assert_eq!(
        fnv1a(warning),
        TLS_RENDERED_FNV1A,
        "the rendered `tls` message changed bytes — if the new wording is intended, update \
         the golden deliberately: {warning}"
    );

    // A no-TLS build must name *why* the key is inert and must not claim any
    // certificate behaviour — the clause the micro tier made false.
    #[cfg(not(feature = "tls"))]
    {
        assert!(
            SERVER_TLS_ENABLE_INERT_WARNING.contains("no TLS support"),
            "the no-TLS variant must name the missing support: {warning}"
        );
        assert!(
            SERVER_TLS_ENABLE_INERT_WARNING.contains("never builds a TLS acceptor"),
            "the no-TLS variant must say no acceptor is built: {warning}"
        );
        for false_here in [
            "refused at startup",
            "auto-generates",
            "`tls_cert_file`",
            "`tls_key_file`",
        ] {
            assert!(
                !SERVER_TLS_ENABLE_INERT_WARNING.contains(false_here),
                "a no-TLS build must not claim {false_here:?}: {warning}"
            );
        }
    }

    // The whole no-TLS text as well: the deny-list above only rejects four known
    // clauses, so a *new* certificate claim — or a dropped one of the two
    // positive clauses — would still be green. Like the `tls` arm, the expected
    // value is derived from the clause array the shipped text is defined as.
    #[cfg(not(feature = "tls"))]
    assert_eq!(
        warning,
        SERVER_TLS_ENABLE_INERT_NO_TLS_CLAUSES.join(" "),
        "the no-TLS variant must be exactly its clause array joined by one space"
    );
    #[cfg(not(feature = "tls"))]
    assert_eq!(
        SERVER_TLS_ENABLE_INERT_NO_TLS_CLAUSES.len(),
        2,
        "a clause was appended to or dropped from the no-TLS array — the deny-list \
         above cannot detect that"
    );
    // The rendered bytes for this variant too; see `NO_TLS_RENDERED_LEN`.
    #[cfg(not(feature = "tls"))]
    assert_eq!(
        warning.len(),
        NO_TLS_RENDERED_LEN,
        "the rendered no-TLS message changed length — if the new wording is intended, update \
         the golden deliberately"
    );
    #[cfg(not(feature = "tls"))]
    assert_eq!(
        fnv1a(warning),
        NO_TLS_RENDERED_FNV1A,
        "the rendered no-TLS message changed bytes — if the new wording is intended, update \
         the golden deliberately: {warning}"
    );

    // The acceptor is *not* pair-gated in a `tls` build: with neither file set
    // the server auto-generates a self-signed pair. A "non-empty pair" claim
    // here would be false for the config that fires the warning (F1 regression
    // guard).
    assert!(
        !SERVER_TLS_ENABLE_INERT_WARNING.contains("non-empty"),
        "the message must not claim a non-empty pair is required: {warning}"
    );
}

/// A written `tls_enable`, in either value, is inert — so it warns, exactly
/// once, in both strict modes, and the loader itself stays silent.
#[test]
fn written_server_tls_enable_warns_once_and_stays_inert() {
    for (written, mode) in [
        ("true", false),
        ("true", true),
        ("false", false),
        ("false", true),
    ] {
        let value = written == "true";
        let c = load_capturing(&format!("bind_port = 7000\ntls_enable = {written}\n"), mode);
        assert_eq!(
            c.logged_during_load, "",
            "strict={mode}, tls_enable={written}: the loader itself must stay silent"
        );
        assert!(
            c.presence.server_tls_enable_set(),
            "strict={mode}, tls_enable={written}: the flag must survive the load"
        );
        assert_eq!(
            c.warning_records, 1,
            "strict={mode}, tls_enable={written}: exactly one record per load"
        );
        assert!(
            c.logged_by_warning_call.contains(NEEDLE),
            "strict={mode}: the record must be the server message"
        );
        // The field really parses to the written value — it is inert because no
        // reader exists, not because the value is lost.
        assert_eq!(
            c.tls_enable, value,
            "strict={mode}, tls_enable={written}: the field still carries the written value"
        );
    }

    // Control: no key at all. No flag, no record.
    let c = load_capturing("bind_port = 7000\n", false);
    assert!(
        !c.presence.server_tls_enable_set(),
        "absent key must not set the flag"
    );
    assert_eq!(c.warning_records, 0, "absent key must not warn");
    assert!(!c.tls_enable, "absent key leaves the default");
}

/// The legacy `[transport.tls]` section synthesizes `tls_enable = true` — that is
/// not the user writing the flat field, so it must stay silent.
#[test]
fn synthesized_tls_enable_stays_silent() {
    // `force = true` → `tls_only`, plus a synthesized `tls_enable`.
    let c = load_capturing("bind_port = 7000\n[transport.tls]\nforce = true\n", false);
    assert!(c.tls_enable, "`force` synthesizes tls_enable = true");
    assert!(c.tls_only, "`force` is the real switch: tls_only");
    assert!(
        !c.presence.server_tls_enable_set(),
        "a synthesized key was not written"
    );
    assert_eq!(c.warning_records, 0, "a synthesized key must not warn");

    // `certFile`/`keyFile` → the pair that actually builds the acceptor, plus the
    // same synthesized `tls_enable`.
    let c = load_capturing(
        "bind_port = 7000\n[transport.tls]\ncertFile = \"/c.crt\"\nkeyFile = \"/c.key\"\n",
        false,
    );
    assert!(c.tls_enable, "the pair synthesizes tls_enable = true");
    assert_eq!(c.cert, "/c.crt");
    assert_eq!(c.key, "/c.key");
    assert!(!c.presence.server_tls_enable_set());
    assert_eq!(c.warning_records, 0);

    // The `enable` spelling under `[transport.tls]` is a *different* key: the
    // server lift has no `enable` arm, so it becomes a top-level `enable` and
    // never reaches `tls_enable`. Ignored leniently...
    let c = load_capturing("bind_port = 7000\n[transport.tls]\nenable = true\n", false);
    assert!(!c.tls_enable, "the server lift has no `enable` arm");
    assert!(!c.presence.server_tls_enable_set());
    assert_eq!(c.warning_records, 0);

    // ...and refused strictly, by name.
    let err = load_capturing_expect_err("bind_port = 7000\n[transport.tls]\nenable = true\n");
    assert!(
        err.contains("enable"),
        "the strict error must name the key: {err}"
    );

    // A written key beside a synthesized one is still written: `or_insert` keeps
    // the user's `false`, `force` still drives `tls_only`, and the warning fires.
    let c = load_capturing(
        "bind_port = 7000\ntls_enable = false\n[transport.tls]\nforce = true\n",
        false,
    );
    assert!(!c.tls_enable, "the written `false` survives the synthesis");
    assert!(c.tls_only, "`force` still turns on the real switch");
    assert!(
        c.presence.server_tls_enable_set(),
        "the user did write the key"
    );
    assert_eq!(c.warning_records, 1);
}

/// A literal `tls_enable` written *inside* `[transport.tls]` is a third written
/// spelling: the server lift renames its five Go keys (`force`, `certFile`,
/// `keyFile`, `trustedCaFile`, `serverName` — the match at
/// `frp-core/src/config/normalize.rs:869-878`) and passes every other key through
/// unchanged, so this one is hoisted onto the very same inert field the warning
/// is about.
#[test]
fn literal_tls_enable_inside_the_transport_table_is_a_written_spelling() {
    for (body, mode, expected) in [
        (
            "bind_port = 7000\n[transport.tls]\ntls_enable = true\n",
            false,
            true,
        ),
        (
            "bind_port = 7000\n[transport.tls]\ntls_enable = true\n",
            true,
            true,
        ),
        (
            "bind_port = 7000\n[transport.tls]\ntls_enable = false\n",
            false,
            false,
        ),
        (
            "bind_port = 7000\n[common.transport.tls]\ntls_enable = true\n",
            false,
            true,
        ),
    ] {
        let c = load_capturing(body, mode);
        assert_eq!(
            c.logged_during_load, "",
            "the loader must stay silent: {body}"
        );
        assert_eq!(
            c.tls_enable, expected,
            "the key hoists onto the inert field: {body}"
        );
        assert!(
            c.presence.server_tls_enable_set(),
            "strict={mode}: a literal `tls_enable` in `[transport.tls]` was written: {body}"
        );
        assert_eq!(
            c.warning_records, 1,
            "strict={mode}: exactly one record: {body}"
        );
        assert!(
            !c.tls_only,
            "the literal key must not touch the real switch: {body}"
        );
    }

    // Beside a renamed neighbour the literal key is still written, and `force`
    // still drives the real switch: the two do not collapse into one case.
    let c = load_capturing(
        "bind_port = 7000\n[transport.tls]\nforce = true\ntls_enable = true\n",
        false,
    );
    assert!(c.tls_only, "`force` is renamed to the real switch");
    assert!(c.tls_enable);
    assert!(
        c.presence.server_tls_enable_set(),
        "the literal key is written beside a renamed one"
    );
    assert_eq!(c.warning_records, 1);
}

/// `[common]`, its inline form, and an `includes` file all reach the same field,
/// so all of them count as written.
#[test]
fn common_and_includes_spellings_set_the_flag() {
    let c = load_capturing("bind_port = 7000\n[common]\ntls_enable = true\n", false);
    assert!(c.presence.server_tls_enable_set(), "`[common] tls_enable`");
    assert_eq!(c.warning_records, 1);
    assert!(c.tls_enable);

    let c = load_capturing("bind_port = 7000\ncommon = { tls_enable = true }\n", false);
    assert!(
        c.presence.server_tls_enable_set(),
        "inline `common = {{ tls_enable = true }}`"
    );
    assert_eq!(c.warning_records, 1);

    let c = load_capturing_files(
        &[
            ("frps.toml", "bind_port = 7000\nincludes = [\"inc.txt\"]\n"),
            ("inc.txt", "tls_enable = true\n"),
        ],
        false,
    );
    assert!(
        c.presence.server_tls_enable_set(),
        "`tls_enable` inside an `includes` file"
    );
    assert_eq!(c.warning_records, 1);

    // Precedence: the flatten is `or_insert`, so a written top-level key wins
    // over a written `[common]` one. Both spellings were written, so the flag is
    // still set either way; the value follows the top level.
    let c = load_capturing(
        "bind_port = 7000\ntls_enable = true\n[common]\ntls_enable = false\n",
        false,
    );
    assert!(
        c.presence.server_tls_enable_set(),
        "both spellings were written"
    );
    assert_eq!(c.warning_records, 1);
    assert!(c.tls_enable, "the top-level value wins the `or_insert`");
}

/// `tlsEnable` is not a loader spelling for this field, so it is not "written and
/// inert" — it is unrecognized. Silent, and the value is dropped rather than
/// applied.
#[test]
fn camelcase_tls_enable_is_not_a_written_key() {
    let c = load_capturing("bind_port = 7000\ntlsEnable = true\n", false);
    assert!(!c.tls_enable, "the camelCase key is dropped, not applied");
    assert!(
        !c.presence.server_tls_enable_set(),
        "an unrecognized key was not written"
    );
    assert_eq!(c.warning_records, 0);

    let err = load_capturing_expect_err("bind_port = 7000\ntlsEnable = true\n");
    assert!(
        err.contains("tlsEnable"),
        "the strict error must name the key: {err}"
    );
}

/// The string loader returns no `ConfigPresence`, so nothing can warn from it;
/// it must not emit the record itself.
#[test]
fn the_string_loader_stays_silent() {
    let output = Arc::new(Mutex::new(Vec::new()));
    let subscriber = subscriber_for(&output);
    let guard = tracing::subscriber::set_default(subscriber);
    let cfg = load_server_config_from_str("bind_port = 7000\ntls_enable = true\n").unwrap();
    let logged = snapshot(&output);
    drop(guard);
    assert!(cfg.tls_enable, "the field still parses on the string path");
    assert_eq!(logged, "", "the string loader must not emit the diagnostic");
}

/// A nested `tls_enable` under `[common.transport.tls]` counts as written **only
/// when no top-level `transport` key is written**, because `[common]`'s flatten
/// is `table.entry(k).or_insert(v)` on the whole value
/// (`frp-core/src/config/normalize.rs:652-655`): a written top-level `transport`
/// — table or not — wins, and `[common]`'s `transport` (nested `tls` table and
/// all) is discarded **before** the lift at
/// `frp-core/src/config/normalize.rs:861-885` can hoist anything.
///
/// This is the invariant the sibling `web_server_tls_enable_set_in` already
/// keeps ("without this arm the detector claimed a key the loader had dropped"):
/// the flag must not claim a key that never reached the field. The message's own
/// mechanism claim ("hoisted onto the same inert field") is false in the
/// competing shape, so the detector is silent there rather than rewording the
/// message to cover a config it does not model.
///
/// Measured on the real `frps` with stdout and stderr captured separately
/// (`/tmp/tls-warn-probe/run-c.sh`): `[common.transport.tls] tls_enable = true`
/// alone warns 1 (before **and** after this change); beside `[transport]
/// heartbeat_timeout = 30` it warned 1 before and warns 0 after; a flat
/// `[common] tls_enable = true` beside the same competing table still warns 1
/// (a different key, and it survives the flatten); `transport = 30` (a top-level
/// non-table) fails the load with `invalid type: integer 30, expected struct
/// ServerTransportConfig` (exit 1) before any warning can be emitted, which is
/// why "absent **or not a table**" and "absent" are indistinguishable at the
/// warning. All five shapes are asserted below.
#[test]
fn common_transport_tls_needs_no_competing_top_level_transport() {
    // Alone: the flatten inserts `[common]`'s `transport`, the lift removes its
    // `tls` table and hoists the literal key onto the inert field.
    let c = load_capturing(
        "bind_port = 7000\n[common.transport.tls]\ntls_enable = true\n",
        false,
    );
    assert!(
        c.presence.server_tls_enable_set(),
        "alone: the key does reach the lift"
    );
    assert!(
        c.tls_enable,
        "alone: the lift hoists it onto the inert field"
    );
    assert_eq!(c.warning_records, 1, "alone: exactly one record");

    // Competing: the top-level `transport` wins the flatten whole, so the key is
    // dropped before the lift and nothing is hoisted — the detector must not
    // claim it and must stay silent.
    let c = load_capturing(
        "bind_port = 7000\n[transport]\nheartbeat_timeout = 30\n\
         [common.transport.tls]\ntls_enable = true\n",
        false,
    );
    assert!(
        !c.presence.server_tls_enable_set(),
        "competing: a dropped key must not be claimed"
    );
    assert!(!c.tls_enable, "competing: nothing reached the field");
    assert_eq!(c.warning_records, 0, "competing: no record");

    // A flat `tls_enable` under `[common]` is a different key and survives the
    // same competing top-level table, so it still counts — pinned so the fix
    // cannot swallow this shape too.
    let c = load_capturing(
        "bind_port = 7000\n[transport]\nheartbeat_timeout = 30\n[common]\ntls_enable = true\n",
        false,
    );
    assert!(
        c.presence.server_tls_enable_set(),
        "flat `[common] tls_enable` still counts beside a competing transport"
    );
    assert!(c.tls_enable, "the flat key survives the flatten");
    assert_eq!(c.warning_records, 1);

    // An **empty** top-level `transport` table also wins the flatten whole —
    // `or_insert` only cares that the key exists — so the `[common]` key is
    // dropped and nothing is hoisted. Pinned because a mutant that treats an
    // empty table as "absent" moves this shape 0 → 1 record while every other
    // assertion in this file stays green (round-2 archive-copy measurement).
    for body in [
        "bind_port = 7000\n[transport]\n[common.transport.tls]\ntls_enable = true\n",
        "bind_port = 7000\ntransport = {}\n[common.transport.tls]\ntls_enable = true\n",
    ] {
        let c = load_capturing(body, false);
        assert!(
            !c.presence.server_tls_enable_set(),
            "an empty competing `transport` still drops the key: {body}"
        );
        assert!(!c.tls_enable, "nothing reached the field: {body}");
        assert_eq!(c.warning_records, 0, "no record: {body}");
    }

    // The "not a table" half: a wrongly typed top-level `transport` also
    // discards `[common]`'s, and the file cannot even load — so the detector is
    // never reached and the load emits nothing.
    let (err, logged) = load_capturing_expect_load_err(
        "bind_port = 7000\ntransport = 30\n[common.transport.tls]\ntls_enable = true\n",
    );
    assert!(
        err.contains("expected struct ServerTransportConfig"),
        "a non-table `transport` must fail as a type error: {err}"
    );
    assert_eq!(logged, "", "a failed load emits nothing");
}
