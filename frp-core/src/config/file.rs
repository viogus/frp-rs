use std::path::Path;

use super::client::ClientConfig;
use super::format::{detect_format, parse_to_toml_value, ConfigFormat};
use super::loader::{validate_client_config, validate_server_config, ConfigPresence};
use super::normalize::{
    load_config_from_file, normalize_client_config, normalize_server_config, ConfigSide,
};
use super::server::ServerConfig;
use super::strict::{known_client_keys, known_server_keys};
use crate::unsafe_features::UnsafeFeatures;

/// Load a server configuration from a file path, auto-detecting format by extension.
/// When `strict_config` is true, unknown fields cause an error (Go frp default).
///
/// The returned config is **completed** ([`ServerConfig::complete`]). Callers
/// that must overlay CLI-flag values on top of the file take the un-completed
/// config from [`load_server_config_uncompleted`] instead — see that function
/// for why the distinction exists.
pub fn load_server_config(
    path: &str,
    strict_config: bool,
) -> Result<ServerConfig, Box<dyn std::error::Error>> {
    let mut cfg = load_server_config_uncompleted(path, strict_config)?;
    cfg.complete();
    Ok(cfg)
}

/// Load a server configuration from a file path **without** running
/// [`ServerConfig::complete`].
///
/// This exists to mirror Go's ordering. On Go, **only the flags-only path**
/// completes a struct that flags have populated: `cmd/frps/root.go:77-83` calls
/// `serverCfg.Complete()` on the struct pflag bound. The `-c` path is the
/// opposite — `config.LoadServerConfig` builds a fresh `svrCfg`
/// (`pkg/config/load.go:313`), unmarshals the file into it, and completes that
/// (`:318-321`), discarding the pflag-bound struct — so Go's flags are ignored in
/// that lane, exactly as frp-rs ignores them (`FrpsArgs::cli_overrides_enabled`;
/// frp-rs's override lane has the same **order** as Go's flags-only path —
/// overlay, then complete — though not the same **values**, since Go pre-seeds
/// every pflag default into the struct (`pkg/config/flags.go:230-255`) while
/// frp-rs keeps the file's deserialized values except where a flag overrides
/// them). frp-rs loads
/// the file first and overlays the flags afterwards, so an override written
/// after `complete()` lands on an already-completed value and can no longer
/// re-trigger a completion: `--dashboard-addr ""` could not re-run Go's
/// `WebServer.Complete()` fill (`pkg/config/v1/common.go:71-72` → `127.0.0.1`)
/// and `--bind-addr ""` could not be filled to `0.0.0.0`
/// (`pkg/config/v1/server.go:110`). The merge order is also observable through a
/// derived field: `proxy_bind_addr` inherits the **effective** `bind_addr`
/// (`server.go:112-114`), so completing before the overlay left the proxy
/// listeners on the file's address while the control listener moved to
/// `--bind-addr` — measured end to end, see `docs/developing.md` § CLI inputs
/// § 2b.
///
/// The `transport` completion (`complete_with_heartbeat_timeout_set`) still runs
/// here. Calling it is safe because no `frps` CLI flag writes a field it reads
/// (`heartbeat_timeout`, `tcp_mux`, `tcp_mux_keepalive_interval`), and because
/// the *presence* of `serverHeartbeatTimeout` in the file — carried by the
/// `heartbeat_timeout_set` argument — cannot be recovered from an
/// already-completed config. (The function is itself idempotent: every write it
/// makes is conditioned on a value its own output no longer holds.)
pub fn load_server_config_uncompleted(
    path: &str,
    strict_config: bool,
) -> Result<ServerConfig, Box<dyn std::error::Error>> {
    Ok(load_server_config_uncompleted_with_presence(path, strict_config)?.0)
}

/// [`load_server_config_uncompleted`], plus the [`ConfigPresence`] flags read
/// from the same file.
///
/// The flags exist for facts the loader cannot act on itself. In particular
/// `[webServer.tls]`/`[web_server.tls]` `enable` is inert, and its diagnostic
/// must be emitted where a log sink exists — on the `-c` path that is **after**
/// `init_logging`, in the binary, so it cannot live inside this load.
pub fn load_server_config_uncompleted_with_presence(
    path: &str,
    strict_config: bool,
) -> Result<(ServerConfig, ConfigPresence), Box<dyn std::error::Error>> {
    let (mut cfg, presence) = load_config_from_file::<ServerConfig>(
        path,
        strict_config,
        ConfigSide::Server,
        known_server_keys,
        normalize_server_config_with_legacy_include_cleanup,
        validate_server_config,
    )?;
    cfg.transport
        .complete_with_heartbeat_timeout_set(presence.server_heartbeat_timeout_set);
    Ok((cfg, presence))
}

/// [`load_server_config`], plus the [`ConfigPresence`] flags read from the same
/// file — the completing sibling of
/// [`load_server_config_uncompleted_with_presence`].
///
/// Callers that already have a log sink (the server's SIGUSR1 reload,
/// `frps --config-dir`) use this and call
/// `ConfigPresence::warn_inert_web_server_tls_enable` themselves, so the record
/// is emitted where it can be seen and exactly once per load.
pub fn load_server_config_with_presence(
    path: &str,
    strict_config: bool,
) -> Result<(ServerConfig, ConfigPresence), Box<dyn std::error::Error>> {
    let (mut cfg, presence) = load_server_config_uncompleted_with_presence(path, strict_config)?;
    cfg.complete();
    Ok((cfg, presence))
}

/// Load a client configuration from a file path, auto-detecting format by extension.
/// When `strict_config` is true, unknown fields cause an error (Go frp default).
pub fn load_client_config(
    path: &str,
    strict_config: bool,
) -> Result<ClientConfig, Box<dyn std::error::Error>> {
    Ok(load_client_config_with_presence(path, strict_config)?.0)
}

/// [`load_client_config`], plus the [`ConfigPresence`] flags read from the same
/// file — the client half of
/// [`load_server_config_uncompleted_with_presence`]'s rationale.
pub fn load_client_config_with_presence(
    path: &str,
    strict_config: bool,
) -> Result<(ClientConfig, ConfigPresence), Box<dyn std::error::Error>> {
    let (mut cfg, presence) = load_config_from_file::<ClientConfig>(
        path,
        strict_config,
        ConfigSide::Client,
        known_client_keys,
        normalize_client_config_with_legacy_include_cleanup,
        validate_client_config,
    )?;
    cfg.complete_with_heartbeat_set(
        presence.client_heartbeat_interval_set,
        presence.client_heartbeat_timeout_set,
    );
    Ok((cfg, presence))
}

// ─── the post-load `--allow-unsafe` gate ──────────────────────────────────────

/// The **post-load** half of the `--allow-unsafe` gate for a server config:
/// refuses an `auth.tokenSource` that needs
/// [`crate::unsafe_features::TOKEN_SOURCE_EXEC`] when the allow-list does not
/// carry it.
///
/// Go runs this predicate from inside validation — `ValidateUnsafeFeature`
/// (`pkg/config/v1/validation/validator.go:22-27`), called for
/// `tokenSource.Type == "exec"` at `pkg/config/v1/validation/auth.go:34-35` —
/// so on Go the gate is part of **load**, and both `frps -c` and
/// `frps verify -c` hit it. frp-rs reaches the predicate
/// ([`crate::auth::validate_token_source_unsafe`], the same function both use
/// here) only from service construction (`frp-server/src/service.rs`), which
/// `verify` never runs. This function is the load-path half that
/// [`load_server_config_checked`] adds, so `verify` refuses exactly what the
/// daemon refuses; the daemon's own refusal is left where it is, because it is
/// the documented `EXIT_AUTH`/3 extension (`tracing::error!` + `process::exit`),
/// not Go's bare stdout line + rc 1.
pub fn check_server_unsafe_features(
    cfg: &ServerConfig,
    unsafe_features: &UnsafeFeatures,
) -> Result<(), String> {
    if let Some(source) = &cfg.auth.token_source {
        crate::auth::validate_token_source_unsafe(source, unsafe_features)?;
    }
    Ok(())
}

/// The client half of [`check_server_unsafe_features`]: the same predicate over
/// the two token sources a client config can carry — `auth.tokenSource` and
/// `auth.oidc.tokenSource`. It is the same field *set* the client daemon gates
/// at construction (`frp-client/src/service.rs`), but not under the same
/// *condition*: this gate is fail-closed, refusing either spelling on `verify`
/// regardless of `auth_method`, while the daemon gates `auth.tokenSource`
/// unconditionally and `auth.oidc_token_source` only inside its
/// `auth_method == AuthMethod::Oidc` branch (`frp-client/src/service.rs:661-664`;
/// measured: with `method = "token"` plus an exec `auth.oidc.tokenSource`,
/// `frpc -c` starts and logs its connection attempts, while `frpc verify` and
/// Go's `frpc -c`/`frpc verify` all exit 1 — the daemon side is the looser of
/// the two, not the parity claim below).
///
/// Go's client validation gates **both** spellings. `auth.tokenSource` is gated
/// by `pkg/config/v1/validation/auth.go` (measured: `frpc verify -c <exec cfg>`
/// is rc 1 on v0.71.0 without the allow-list, rc 0 with it), and
/// `auth.oidc.tokenSource` is gated by Go's `validateOIDCConfig`
/// (`pkg/config/v1/validation/client.go`) — measured on the same binary, a
/// config carrying `[auth.oidc.tokenSource] type = "exec"` prints
/// `unsafe feature "TokenSourceExec" is not enabled. …` and that line
/// disappears once `--allow-unsafe TokenSourceExec` is passed — a config that
/// also sets other `[auth.oidc]` fields keeps Go's own "cannot specify both
/// auth.oidc.tokenSource and any other field of auth.oidc" rc 1, which is not
/// the gate). The two-field *set* gated here is therefore exact Go parity, not a
/// frp-rs extension; the *condition* is this loader's own (fail-closed on
/// `verify` regardless of `auth_method`), not the daemon's, which skips
/// `auth.oidc_token_source` unless `auth_method == AuthMethod::Oidc`.
pub fn check_client_unsafe_features(
    cfg: &ClientConfig,
    unsafe_features: &UnsafeFeatures,
) -> Result<(), String> {
    if let Some(auth) = &cfg.auth {
        if let Some(source) = &auth.token_source {
            crate::auth::validate_token_source_unsafe(source, unsafe_features)?;
        }
        if let Some(source) = &auth.oidc_token_source {
            crate::auth::validate_token_source_unsafe(source, unsafe_features)?;
        }
    }
    Ok(())
}

/// [`load_server_config`], plus [`check_server_unsafe_features`].
///
/// `frps verify` is the caller (`frps/src/main.rs`): the whole point is that a
/// config it certifies is one the daemon will accept. The run path deliberately
/// does **not** use it — its refusal stays the construction-time
/// `EXIT_AUTH`/3 one, and moving the gate into the loader would silently move
/// that refusal to this lane's bare rc 1 (`docs/developing.md` § CLI exit codes
/// records 3 as a frp-rs extension).
pub fn load_server_config_checked(
    path: &str,
    strict_config: bool,
    unsafe_features: &UnsafeFeatures,
) -> Result<ServerConfig, Box<dyn std::error::Error>> {
    let cfg = load_server_config(path, strict_config)?;
    check_server_unsafe_features(&cfg, unsafe_features)?;
    Ok(cfg)
}

/// [`load_server_config_with_presence`], plus [`check_server_unsafe_features`] —
/// the server half of [`load_client_config_with_presence_checked`], and the
/// function `frps verify` now uses so it can report the feature-gated listener
/// ports the loaded file named beside the one-line success message.
pub fn load_server_config_with_presence_checked(
    path: &str,
    strict_config: bool,
    unsafe_features: &UnsafeFeatures,
) -> Result<(ServerConfig, ConfigPresence), Box<dyn std::error::Error>> {
    let (cfg, presence) = load_server_config_with_presence(path, strict_config)?;
    check_server_unsafe_features(&cfg, unsafe_features)?;
    Ok((cfg, presence))
}

/// [`load_client_config_with_presence`], plus [`check_client_unsafe_features`].
///
/// Returns the presence flags with the config because `frpc verify` — the only
/// caller — emits the `[web_server.tls] enable` diagnostic from them, exactly
/// as it did through [`load_client_config_with_presence`].
pub fn load_client_config_with_presence_checked(
    path: &str,
    strict_config: bool,
    unsafe_features: &UnsafeFeatures,
) -> Result<(ClientConfig, ConfigPresence), Box<dyn std::error::Error>> {
    let (cfg, presence) = load_client_config_with_presence(path, strict_config)?;
    check_client_unsafe_features(&cfg, unsafe_features)?;
    Ok((cfg, presence))
}

/// Process `includes` directives in a config: for each glob pattern,
/// find matching files relative to `base_dir`, parse each (with format
/// detection, so `.yaml`/`.yml`/`.json`/`.ini` include files work too), and
/// deep-merge into the main config. Removes the `includes` key after
/// processing.
pub(super) fn process_includes(
    value: &mut toml::Value,
    base_dir: &Path,
    format: ConfigFormat,
    side: ConfigSide,
) -> Result<(), Box<dyn std::error::Error>> {
    use toml::Value;

    let table = match value.as_table_mut() {
        Some(t) => t,
        None => return Ok(()),
    };

    // A legacy `.ini` with `[common]` is not parsed as v1 by Go at all: the
    // presence of that section selects the legacy reader (`DetectLegacyINIFormat`,
    // `pkg/config/load.go:65`; `strict` is never passed to that branch), and the
    // reader skips `ini.DefaultSection` (`pkg/config/legacy/client.go:204`),
    // taking its include list from `[common]` alone
    // (`IncludeConfigFiles []string \`ini:"includes"\``,
    // `pkg/config/legacy/client.go:166`). A scalar `includes = 1` in the
    // section-less top level — or nested in `[common]` — is therefore inert on
    // Go: rc 0 in both loader modes (measured on v0.71.0). frp-rs carried it into
    // the v1 `includes: Vec<String>` decode and refused the file
    // (`invalid type: integer \`1\`, expected a sequence`, rc 1 in both modes).
    // Scrub the scalar spellings here, while the raw dialect is still visible:
    // after the `[common]` hoist at `frp-core/src/config/normalize.rs:1185-1189`
    // the two spellings are indistinguishable, and a `.ini` *without* `[common]`
    // goes down Go's v1 path too, so its type error (`includes = 1` there is rc 1
    // in both modes) must stay.
    if format == ConfigFormat::Ini && matches!(table.get("common"), Some(Value::Table(_))) {
        drop_ini_scalar_include_keys(table);
    }

    // Extract includes list (support both "includes" and "include" keys). Only
    // the v1 shapes — a string or an array — are a file list; any other value is
    // left where it is. In the legacy `.ini` dialect a *table* is an ordinary
    // section, not a directive: Go reads its include list from the `[common]`
    // section (`IncludeConfigFiles []string \`ini:"includes"\``,
    // `pkg/config/legacy/client.go:166`) and treats every other section as a
    // legacy proxy or visitor named after its header. Removing a table here made
    // real user config vanish: `[includes] local_port = 8080 remote_port = 18080`
    // silently dropped the tcp proxy named `includes` that Go v0.71.0 registers
    // (rc 0 in both modes), and `[includes] role = "visitor" server_name = s` hid
    // the section from the typeless-visitor refusal (Go rc 1 in both modes,
    // `failed to parse visitor includes, err: type shouldn't be empty`). A
    // table-shaped `includes` in TOML/JSON/YAML now reaches the decoder as well,
    // which is what Go's own `cannot unmarshal object into []string` does.
    let is_file_list =
        |v: Option<&Value>| matches!(v, Some(Value::String(_)) | Some(Value::Array(_)));

    // The legacy `.ini` **client** reader fills its include list from `[common]`
    // alone (`UnmarshalClientConfFromIni` reads only that section,
    // `pkg/config/legacy/client.go:172-200`; `ParseClientConfig` then renders
    // `cfg.IncludeConfigFiles`, `pkg/config/legacy/parse.go:50`), so a
    // `[common] includes` has to be expanded even though it sits one table
    // below the top level. Reading it here — before the `[common]` hoist at
    // `frp-core/src/config/normalize.rs:1185` — is what orders the walk the way
    // Go orders it (common first, included sections after). The section-less
    // top-level spelling below stays an frp-rs extension: Go skips
    // `ini.DefaultSection` (`pkg/config/legacy/client.go:204`) and ignores it
    // (measured: rc 0, zero proxies), which the pin
    // `legacy_ini_default_section_string_include_is_still_expanded` records.
    // Client only: the legacy `[common]` include list is read on the client load
    // alone. Go's server path never reads it: `LoadServerConfig`
    // (`pkg/config/load.go:295`) maps `[common]` onto
    // `legacy.ServerCommonConf` (`pkg/config/legacy/server.go:220`), a struct
    // with no `includes` field, and the only expansion
    // (`LoadAdditionalClientConfigs`, `pkg/config/load.go:381-382`) is inside
    // `LoadClientConfigResult` (`pkg/config/load.go:346`). A `[common] includes`
    // in a frps config is therefore inert on Go — measured rc 0 in both loader
    // modes, with a valid include, a missing include directory and an include
    // holding a server setting alike. Extracting it here made frps (which
    // defaults to strict) refuse files Go and the pre-`[common]`-include frp-rs
    // both accept, and silently merged a server key in the non-strict mode.
    //
    // The spelling is Go's exactly: only the **string** key `includes`
    // (`IncludeConfigFiles []string \`ini:"includes"\``,
    // `pkg/config/legacy/client.go:166`). Measured on v0.71.0: `include =
    // "<file>"` yields rc 0 with zero proxies (a key Go never maps), and
    // `includes = ["<file>"]` does too for a *bare* relative name (the array is
    // the literal bracketed string to Go's reader, so it matches no file) —
    // though with a `./`-prefixed or absolute entry Go is rc 1 `include:
    // directory of [...] not exist`, a pre-existing frp-rs divergence — while
    // the string and a string glob (`includes = "sub*.ini"`,
    // `getIncludeContents`'s `filepath.Match`,
    // `pkg/config/legacy/parse.go:87`) both expand. Leaving the two ignored
    // spellings in place keeps the pre-fix behaviour; the earlier `is_file_list`
    // widening let them expand where Go yields nothing.
    let legacy_common_includes = if side == ConfigSide::Client && format == ConfigFormat::Ini {
        match table.get_mut("common").and_then(Value::as_table_mut) {
            Some(common) if matches!(common.get("includes"), Some(Value::String(_))) => {
                common.remove("includes")
            }
            _ => None,
        }
    } else {
        None
    };
    let includes = if is_file_list(table.get("includes")) {
        table.remove("includes")
    } else if is_file_list(table.get("include")) {
        table.remove("include")
    } else {
        None
    };
    // The list is kept verbatim, empty entries included. Go maps `includes = ""`
    // to `[]string{""}` and hands it to `getIncludeContents`, where
    // `filepath.Dir("")` = `"."` and `filepath.Base("")` = `"."` make it match
    // nothing (`pkg/config/legacy/parse.go:71`, `:87`), so an empty pattern is
    // "no includes" by Go's own rule and needs no filter. Round 4 dropped the
    // empties here instead, which repaired the empty-parent guard but only for
    // this exact string: every other separator-less spelling (`"."`, `"./"`,
    // `"././"`, and any bare name under `-c <name>`) still tripped it, and the
    // filter also hid the section-less top-level `includes = ""` from the
    // resolver. Both lists carry their entries now;
    // [`go_dir`]/[`go_base`] resolve them below.
    let mut patterns: Vec<String> = Vec::new();
    for includes in [legacy_common_includes, includes] {
        match includes {
            Some(Value::Array(arr)) => patterns.extend(arr.into_iter().filter_map(|v| match v {
                Value::String(s) => Some(s),
                _ => None,
            })),
            Some(Value::String(s)) => patterns.push(s),
            _ => {}
        }
    }

    if patterns.is_empty() {
        return Ok(());
    }

    for pattern in &patterns {
        // Go resolves the **pattern's own** directory, not the parent of the
        // joined path: `absDir = filepath.Abs(filepath.Dir(pattern))`, then
        // `os.Stat(absDir)` (`pkg/config/legacy/parse.go:69-72`,
        // `pkg/config/load.go:506-512`), with the pattern's last element used as
        // the match name (`filepath.Base`, `pkg/config/legacy/parse.go:87`).
        // `base_dir.join(pattern).parent()` was the wrong rule and made the
        // guard below fire on every shape where `Path::join` produces a path
        // with no separator before its last component: the empty pattern
        // (`"." + ""` → `"./"`), `"."`/`"./"`/`"././"`, and — the same bug, not
        // a separate one — any separator-less pattern under `-c <name>`, where
        // `base_dir` itself is empty. All of them are `"."` to Go.
        let pattern_dir = go_dir(pattern);
        let search_dir = if pattern_dir.is_absolute() {
            pattern_dir
        } else {
            base_dir.join(pattern_dir)
        };

        // Go frp fails hard when an include's directory is missing
        // (pkg/config/load.go `LoadAdditionalClientConfigs`: `os.Stat(absDir)`
        // error; legacy/client.go:393 "include: directory of %s not exist").
        // frp-rs resolves relative patterns against the main config file's
        // directory (documented divergence, docs/config.md) but mirrors the
        // fatal error: a missing directory is a config bug, not a silent
        // merge-nothing. A glob that matches nothing in an EXISTING dir stays
        // silent, exactly like Go's zero-match loop.
        if !search_dir.exists() || !search_dir.is_dir() {
            return Err(format!(
                "include: directory of {} not exist (included by pattern {pattern})",
                search_dir.display()
            )
            .into());
        }
        // Directory read errors are fatal too (Go `os.ReadDir` error).
        let paths = glob_in_dir(&search_dir, &go_base(pattern))?;

        for path in &paths {
            let content = std::fs::read_to_string(path).map_err(|e| {
                format!("include: read included file {} error: {e}", path.display())
            })?;
            // Parse the include file with format detection (extension-based),
            // so `.yaml`/`.yml` include files go through the same
            // YAML→TOML→merge pipeline as the main config. A parse error in a
            // matched file aborts loading (Go "load additional config from
            // %s error"), never silently drops the file.
            let format = detect_format(path.to_string_lossy().as_ref());
            let inc_value: Value = parse_to_toml_value(&content, format).map_err(|e| {
                format!("include: parse included file {} error: {e}", path.display())
            })?;

            // Deep-merge included config into main config
            deep_merge_toml(value, &inc_value);
            tracing::debug!(path = %path.display(), "Merged include file: {}", path.display());
        }
    }

    Ok(())
}

/// The `normalize` step for the server load: [`normalize_server_config`], then the
/// legacy-`.ini` include cleanup.
///
/// [`process_includes`] leaves a table-shaped `includes`/`include` where it is so
/// that the legacy guard and collector can see it, but the server has no
/// collector: Go's legacy server reader reads only `[common]` and ignores every
/// other section, so such a table is nothing either reader turns into a setting
/// and it must not reach `ServerConfig::includes`
/// (`frp-core/src/config/server.rs:165`). `.ini` only; in TOML/JSON/YAML a table
/// there is a type error in Go too.
fn normalize_server_config_with_legacy_include_cleanup(
    value: &mut toml::Value,
    format: ConfigFormat,
) -> Result<(), String> {
    normalize_server_config(value, format)?;
    drop_legacy_ini_include_tables(value, format);
    Ok(())
}

/// The client half of [`normalize_server_config_with_legacy_include_cleanup`].
///
/// The client's collector (`collect_legacy_ini_proxy_sections`) has already turned
/// the sections Go turns into proxies or visitors into `proxies`/`visitors`
/// entries and removed them; this drops what it did **not** consume — a
/// `[includes] foo = 1` section, which Go v0.71.0 loads and ignores (rc 0 in both
/// loader modes) but which would otherwise fail the `includes: Vec<String>` decode
/// at `frp-core/src/config/client.rs:256`.
fn normalize_client_config_with_legacy_include_cleanup(
    value: &mut toml::Value,
    format: ConfigFormat,
) -> Result<(), String> {
    normalize_client_config(value, format)?;
    drop_legacy_ini_include_tables(value, format);
    Ok(())
}

/// Drop a table-shaped `includes`/`include` that survived normalization.
///
/// In the legacy `.ini` dialect such a table is an ordinary section, not a file
/// list ([`process_includes`] deliberately leaves it in place); once the legacy
/// guard and collector have run, whatever is still there is a section neither Go
/// reader acts on, so it must not reach the v1 `includes: Vec<String>` decode.
fn drop_legacy_ini_include_tables(value: &mut toml::Value, format: ConfigFormat) {
    use toml::Value;
    if format != ConfigFormat::Ini {
        return;
    }
    if let Some(table) = value.as_table_mut() {
        for key in ["includes", "include"] {
            if matches!(table.get(key), Some(Value::Table(_))) {
                table.remove(key);
            }
        }
    }
}

/// Remove a scalar `includes`/`include` from a legacy `.ini` with `[common]`.
///
/// Covers both spellings of the section-less top level and the `[common]`
/// section itself; see the call site in [`process_includes`] for the Go
/// readings. A string or an array is the v1 file list (removed and processed
/// there instead) and a table is an ordinary legacy section
/// ([`drop_legacy_ini_include_tables`] handles what survives normalization), so
/// only the remaining scalar shapes are inert.
fn drop_ini_scalar_include_keys(table: &mut toml::Table) {
    use toml::Value;
    let is_scalar = |v: Option<&Value>| {
        matches!(
            v,
            Some(Value::Integer(_) | Value::Float(_) | Value::Boolean(_) | Value::Datetime(_))
        )
    };
    for key in ["includes", "include"] {
        if is_scalar(table.get(key)) {
            table.remove(key);
        }
    }
    if let Some(Value::Table(common)) = table.get_mut("common") {
        for key in ["includes", "include"] {
            if is_scalar(common.get(key)) {
                common.remove(key);
            }
        }
    }
}

// Known bounds in this area — pre-existing divergences measured during round 4
// (Go v0.71.0 binaries, both loader modes). The detector used throughout is the
// two-line body `[p1]` + `role = "visitor"` — usually written as the file
// `sub_bad.ini`: Go's legacy reader refuses it with `failed to parse visitor
// p1, err: type shouldn't be empty`, so a reader that merges the file must fail
// on it. Fixtures below reuse that body under other file names; the detector is
// the body, not the name. None of the remaining ones is introduced by the
// legacy-`.ini` parity work and none is pinned by a test — they are recorded
// here because this is where the include handling lives, and so that a later
// fix knows it is changing measured behaviour rather than "cleaning up".
//
// (The `[common] includes = "<file>"` gap this list originally opened with is
// fixed: [`process_includes`] expands that list on the **client** load, matching
// Go, and ignores it on the **server** load, also matching Go. Pins:
// `legacy_ini_common_include_is_expanded_like_go`,
// `legacy_ini_common_include_missing_dir_refuses_like_go`,
// `legacy_ini_common_include_glob_is_expanded_like_go`,
// `legacy_ini_common_include_ignored_spellings_both_modes`,
// `legacy_ini_server_ignores_common_includes_both_modes`.)
// * The mirror shape: a top-level `includes = "<file>"` in a file that also has
//   `[common]`. Go never reads it (only `[common]` is mapped by
//   `UnmarshalClientConfFromIni`), while frp-rs expands it here and merges the
//   file — rc 1 in both modes with `sub_bad.ini` against Go's rc 0, and rc 0 in
//   both when the include is valid (frp-rs loads a proxy Go does not).
// * A `.ini` *without* `[common]` plus `includes = "<valid file>"`: frp-rs
//   expands the pattern and merges (rc 0 in both modes), where Go's v1 decode
//   refuses the string (rc 1 in both modes: strict `json: cannot unmarshal
//   string into Go value of type v1.rawClientConfig`, non-strict `error
//   unmarshaling JSON: while decoding JSON: json: cannot unmarshal string into
//   Go value of type v1.ClientConfig`). This is the shape the new scalar pins
//   deliberately exclude: their no-`[common]` case uses `includes = 1`, which
//   both readers refuse.
// * `[includes] type = "custom"` (no ports): Go's legacy collector turns the
//   section into a proxy and refuses its type (`failed to parse proxy includes,
//   err: invalid type [custom]`, rc 1 in both modes), while here the section is
//   skipped by the collector and then dropped as an inert table by
//   [`drop_legacy_ini_include_tables`] (rc 0 in both modes).
// * **The glob is not `filepath.Match`: `?`, `[...]` and `\` are matched as
//   literals.** Go matches each directory entry against
//   `filepath.Match(filepath.Join(absDir, filepath.Base(pattern)), absFile)`
//   (`pkg/config/legacy/parse.go:87`, repeated at `pkg/config/load.go:513-522`),
//   while [`glob_in_dir`] implements exactly one `*` (first-star split, then a
//   prefix/suffix test). One fixture reproduces every cell below: a directory
//   holding `z.ini`, `zz.ini`, `sub.ini` and `sub_bad.ini`, each with the
//   detector body, plus `[common] includes = "<pat>"`; measured on Go v0.71.0
//   and the round-7 build, both loader modes and all three `-c` forms:
//     pattern        GO  HEAD  why
//     `?.ini`        1   0     `?` is a `Match` metachar; HEAD wants a literal `?`
//     `[z].ini`      1   0     `[z]` is a class, and `z.ini` is in it
//     `z?.ini`       1   0     `?` after a literal
//     `[!z].ini`     1   0     `!` is *not* `Match` negation — it is an ordinary
//                              class member, so `[!z]` matches `z.ini`. Go
//                              negates with `[^...]`
//                              (`$GOROOT/src/path/filepath/match.go:141`)
//     `[^z].ini`     0   0     the negation that *does* work, and it matches
//                              nothing in this fixture
//     `*z*.ini`      1   0     a second `*`; HEAD keeps the literal `z*` in its
//                              suffix, which no entry satisfies
//     `s*b*.ini`     1   0     a second `*`; HEAD wants a name ending `b*.ini`
//     `z*.ini`       1   1     one `*` — the subset both implement
//     `sub*.ini`     1   1     one `*` — the subset both implement
//   `\` is `Match`'s escape, so `sub\*.ini` matches nothing unless the literal
//   file `sub*.ini` is in the directory. Adding that one file flips two rows:
//   `sub\*.ini` becomes GO rc 1 (it matches the literal) / HEAD rc 0 (HEAD's
//   prefix is the literal `sub\`), and `s*b*.ini` becomes rc 1 **at HEAD too**,
//   because the literal is a name HEAD's naive prefix/suffix test accepts — so
//   no single fixture produces both "`s*b*.ini` HEAD rc 0" and "`sub\*.ini`
//   `GO rc 1`". MID `6d801655` and BASE `f679e822` are rc 0 on every GO-rc-1
//   row above except `z*.ini`/`sub*.ini` (rc 1 at MID, rc 0 at BASE), so the
//   bound is pre-existing, and even a bare `*` started matching only at MID.
//   Two further cells belong to this row and were measured during the round-7
//   review; they are the same "the whole absolute path is matched" bound, seen
//   from the two ends:
//     * A `Match` metacharacter in the **resolved directory path**. With the
//       detector in the directory `a[bc]/z.ini` and `[common] includes =
//       "a[bc]/z*.ini"` — or even the star-less `"a[bc]/z.ini"` and
//       `"a[bc]/*.ini"` — Go matches `filepath.Join(absDir, base)` with
//       `filepath.Match`, whose `[bc]` is a **class** that cannot match the
//       literal `[`/`]` characters of the real directory name, so nothing
//       matches: GO rc 0. HEAD never interprets metacharacters in the
//       directory part — the pattern is split at its last separator and only
//       cleaned, never `Match`-interpreted — and the entry name is
//       compared against `go_base(pattern)` (`z.ini`, or the `*.ini`
//       prefix/suffix) — so it merges the detector and fails: rc 1.
//     * A file literally named `[z].ini` with `includes = "[z].ini"`. `Match`
//       reads `[z]` as a class and never matches the literal brackets: GO
//       rc 0. HEAD's star-less branch compares the entry name for equality and
//       merges it: rc 1. (In the row's main fixture `[z].ini` is GO rc 1 only
//       because a real `z.ini` is present and the class matches *that*.)
//   Both cells are GO 0 / HEAD 1 at r6, r7 and r8, MID `6d801655` 1 and BASE
//   `f679e822` 0, in all three `-c` forms and both loader modes — MID already
//   had them, so like the rest of the row the bound predates this work.
//   Implementing `Match` is out of scope for the legacy-`.ini` residue work;
//   this row exists so a later fix changes measured behaviour knowingly.
//
// The empty-parent resolution bug measured during round 4 is fixed by
// [`go_dir`]/[`go_base`]: the pattern's own directory is resolved (Go's
// `filepath.Dir`), not the parent of `base_dir.join(pattern)`. That covers
// `includes = ""`, `"."`, `"./"`, `"././"`, `".."`, `"../"` and the
// `-c <bare relative name>` empty-`base_dir` case, all in the three `-c` forms
// and both loader modes; `includes = ".."` no longer globs the config's
// directory into itself. Pins:
// `legacy_ini_common_include_dot_spellings_both_modes`,
// `legacy_ini_common_include_dot_spellings_bare_config_both_modes`,
// `legacy_ini_common_include_dotdot_is_not_a_wildcard_both_modes`.
//
// The interior-`..` residue measured during round 5 is fixed in the same helper:
// [`go_clean`] now folds `..` with Go's `Clean` rule, so
// `Dir("a/../b") = "."` and the guard sees an existing directory. Pin:
// `legacy_ini_common_include_interior_dotdot_is_cleaned_like_go`. The
// separator-terminated pattern naming a regular file, `includes = "sub.ini/"`,
// is a *message* difference only: GO rc 1 `getIncludeContents error: open
// <abs>/sub.ini: not a directory` against HEAD rc 1 `include: directory of
// ./sub.ini not exist (included by pattern sub.ini/)` — the `:410` guard
// collapses Go's stat-missing and `ReadDir`-ENOTDIR failure modes into one
// message, and `..../sub.ini` likewise prints the cleaned dir where Go prints
// the raw pattern. That shape is **not** the area's only remaining bound: the
// glob row above is the other, still rc-divergent one. The symlink shapes that
// were a third bound (`includes = "lnk"` to a directory, `includes =
// "dangling.ini"`, and the globs `l*` / `dang*.ini`) are rc-parity as of round
// 7 — [`glob_in_dir`] skips directories by the entry's own type, so Go and
// frp-rs both try to read them and both fail (rc 1).
//
// The same round-7 fix also made a **FIFO** (named pipe) include match, because
// the entry's own type is not a directory; reading it then blocks forever,
// exactly as Go's `os.ReadFile` does. Measured with `mkfifo fifo.ini` and
// `[common] includes = "fifo.ini"` (and `"f*.ini"`): GO v0.71.0, r7 and r8 all
// still have no exit after 4 s. r6 and MID returned rc 0 on the `./c.ini` and
// absolute forms, and BASE returned rc 0 on every form. r6 skips the FIFO as a
// non-regular file — with a *regular* `fifo.ini` it is rc 1 — whereas BASE does
// not honour the legacy `[common] includes` key at all and is rc 0 even when the
// included entry is an ordinary readable file. MID additionally returns rc 1 on
// the bare `c.ini` form, but that is MID's bare-name path resolution, not the
// pipe — with `-c c.ini` MID is rc 1 with no matching entry at all, with a
// regular `fifo.ini`, and with a FIFO alike. Blocking is Go's behaviour, so this
// is not a divergence — but it is an unlisted behaviour change of the round-7
// fix, and it means the loader has no termination bound on a tree that contains
// such a name; a caller that needs one must impose its own timeout.

/// Go's `filepath.Dir` (`internal/filepathlite/path.go`, `Dir`): scan back to
/// the last path separator and `Clean` everything up to **and including** it; a
/// pattern with no separator at all leaves an empty prefix, and `Clean("")` is
/// `"."`.
///
/// This is the rule the include walk has to use in place of `Path::parent()`.
/// `base_dir.join(pattern).parent()` produced a `Some("")` — which
/// `Path::exists()` reports as missing — for exactly the shapes Go resolves to
/// the current directory: the empty pattern, `"."`, `"./"`, `"././"`, and any
/// separator-less pattern when `base_dir` is empty (`-c <name>`). Measured Go
/// v0.71.0 (`Dir`): `""`→`"."`, `"."`→`"."`, `"./"`→`"."`, `"././"`→`"."`,
/// `".."`→`"."`, `"../"`→`".."`, `"sub"`→`"."`, `"sub/"`→`"sub"`,
/// `"*.ini"`→`"."`, `"sub/*.ini"`→`"sub"`, `"nonexistent/"`→`"nonexistent"`,
/// and — the interior-`..` shapes [`go_clean`] now folds — `"a/../b"`→`"."`,
/// `"./x/../y"`→`"."`, `"x/../sub.ini"`→`"."`,
/// `"nonexistent/../sub.ini"`→`"."`, `"a/../../b"`→`".."`.
fn go_dir(pattern: &str) -> std::path::PathBuf {
    let bytes = pattern.as_bytes();
    let mut i: isize = bytes.len() as isize - 1;
    while i >= 0 && !is_path_separator(bytes[i as usize]) {
        i -= 1;
    }
    // `pattern[..i + 1]` is the prefix through the last separator, or `""` when
    // there is no separator (`i == -1`); the byte at `i` is ASCII when >= 0.
    std::path::PathBuf::from(go_clean(&pattern[..(i + 1) as usize]))
}

/// Go's `filepath.Base` (`internal/filepathlite/path.go`, `Base`): the final
/// element with trailing separators stripped; `""` and slash-only spellings
/// yield `"."`.
///
/// `Path::file_name()` is `None` for `"."`, `".."` and every trailing-separator
/// spelling, and the glob's `unwrap_or("*")` raised that to `"*"` — so
/// `includes = ".."` merged every file of the config's directory (Go matches
/// nothing: `filepath.Match(Join(absDir, ".."), absFile)` never equals an entry)
/// and `includes = "sub/"` matched a file named `sub` in `sub/`. Measured Go
/// v0.71.0 (`Base`): `""`→`"."`, `"."`→`"."`, `"./"`→`"."`, `"././"`→`"."`,
/// `".."`→`".."`, `"../"`→`".."`, `"sub"`→`"sub"`, `"sub/"`→`"sub"`,
/// `"nonexistent/"`→`"nonexistent"`.
fn go_base(pattern: &str) -> String {
    let bytes = pattern.as_bytes();
    if bytes.is_empty() {
        return ".".to_string();
    }
    let mut end = bytes.len();
    while end > 0 && is_path_separator(bytes[end - 1]) {
        end -= 1;
    }
    // Go's `Base` also drops a volume name here; no include pattern in the frp
    // corpus is volume-qualified, and [`Path::is_absolute`] already routes one
    // down the absolute branch of the walk above.
    let trimmed = &pattern[..end];
    let start = trimmed.rfind(is_sep_char).map_or(0, |p| p + 1);
    let base = &trimmed[start..];
    if base.is_empty() {
        std::path::MAIN_SEPARATOR.to_string()
    } else {
        base.to_string()
    }
}

/// Host path separator, for the byte-wise scans above (Go's
/// `IsPathSeparator`: `/` everywhere, plus `\` on Windows).
fn is_path_separator(b: u8) -> bool {
    #[cfg(windows)]
    {
        b == b'/' || b == b'\\'
    }
    #[cfg(not(windows))]
    {
        b == b'/'
    }
}

/// Char form of [`is_path_separator`], for `str::split`/`rfind`.
fn is_sep_char(c: char) -> bool {
    c.is_ascii() && is_path_separator(c as u8)
}

/// Go's `filepath.Clean` in full (`internal/filepathlite/path.go`, `Clean`):
/// drop empty and `.` elements, rebuild with the host separator, keep one
/// leading separator for a rooted path, and **fold `..` back over the preceding
/// element**.
///
/// The fold is load-bearing, not cosmetic. Round 5 left it out on the theory
/// that `"a/../b"` and `"b"` "spell the same directory, so `exists()`/`read_dir`
/// agree"; they do not, because the guard only ever sees the spelling. Go's
/// `filepath.Abs` Cleans `Dir` (`pkg/config/legacy/parse.go:71`), so
/// `Dir("a/../b") = Clean("a/../") = "."` and `os.Stat(".")` succeeds even
/// though `a` does not exist — while the unfolded `"a/.."` is a path whose
/// `exists()` is false, so frp-rs refused with
/// `include: directory of ./a/.. not exist`. Measured on Go v0.71.0, the four
/// interior-`..` spellings (`a/../b`, `./x/../y`, `x/../sub.ini`,
/// `nonexistent/../sub.ini`) are rc 0 in all three `-c` forms and both loader
/// modes once the fold is in place, and were rc 1 at `c5b4f9ed`. Pin:
/// `legacy_ini_common_include_interior_dotdot_is_cleaned_like_go`.
///
/// Go's rule for the two `..` shapes: `..` cancels the previous element when
/// there is one and it is not itself `..` (`"a/.."` → `"."`, `"a/../b"` →
/// `"b"`), and otherwise survives as a literal `..` (`"../x/../"` → `".."`,
/// `"a/../../b"` → `"../b"`, `"x/../../.."` → `"../.."`); a rooted path never
/// yields a `..` (`"/.."` → `"/"`). Every spelling below is measured on Go
/// v0.71.0; [`go_clean_has_go_clean_semantics`] pins them.
pub(super) fn go_clean(path: &str) -> String {
    let sep = std::path::MAIN_SEPARATOR;
    let rooted = path.starts_with(is_sep_char);
    let mut out: Vec<&str> = Vec::new();
    for part in path.split(is_sep_char) {
        match part {
            "" | "." => {}
            ".." => match out.last() {
                Some(&last) if last != ".." => {
                    out.pop();
                }
                // Go keeps a leading `..` only when the path is not rooted.
                Some(_) => out.push(part),
                None if !rooted => out.push(part),
                None => {}
            },
            _ => out.push(part),
        }
    }
    let joined = out.join(&sep.to_string());
    if rooted {
        // A rooted path is `"/" + rest`; an empty `rest` is still `"/"`.
        format!("{sep}{joined}")
    } else if joined.is_empty() {
        ".".to_string()
    } else {
        joined
    }
}

/// `filepath.Match`-style single-`*` glob over the entries **directly inside**
/// `dir` — the `os.ReadDir(absDir)` + `filepath.Match(filepath.Join(absDir,
/// filepath.Base(pattern)), absFile)` loop of
/// `pkg/config/legacy/parse.go:78-95`, which `pkg/config/load.go:513-522`
/// repeats verbatim for the v1 path. Callers pass the directory from [`go_dir`]
/// and the name from [`go_base`], so `name_pattern` carries no separator (Go's
/// only separator-bearing `Base` result is the slash-only `"/"`, which matches
/// no entry).
///
/// The loop mirrors Go's filter exactly, and that filter is `parse.go:83`
/// `if fi.IsDir() { continue }` — the **`DirEntry`'s own type**, which never
/// follows a symlink. The distinction is observable and was a real divergence
/// until round 7: `Path::is_file()` *does* follow symlinks, so it silently
/// dropped (a) a symlink that resolves to a directory and (b) a dangling
/// symlink, while Go keeps both, tries to read them, and fails the load
/// (rc 1). Measured on Go v0.71.0 (`/private/tmp/frp_0.71.0_darwin_arm64/frpc`)
/// against this build, in a scratch directory holding `realdir/` (a real
/// directory), `lnk -> realdir`, `dangling.ini -> nowhere.ini` and a second
/// symlink `sub -> realdir`, with `[common] includes = "<pat>"`, both loader
/// modes and all three `-c` forms: `lnk`, `l*`, `dangling.ini`, `dang*.ini`,
/// `sub` and `s*` are GO rc 1 against HEAD rc 0 *before* the fix and GO rc 1 /
/// HEAD rc 1 after it (36/36 cells agree: 6 patterns × 3 `-c` forms × 2 loader
/// modes), while the real directory `realdir`
/// and the glob `reald*` stay rc 0 in both. Pins:
/// `legacy_ini_common_include_symlink_to_dir_refuses_like_go`,
/// `legacy_ini_common_include_dangling_symlink_refuses_like_go`,
/// `legacy_ini_common_include_symlink_globs_refuse_like_go`.
///
/// Go reaches this enumeration even when the pattern carries no `*`: `Match`
/// degenerates to string equality with the entry name, so the no-wildcard
/// branch compares the entry's own name rather than stat-ing
/// `dir.join(pattern)`. `"."`/`".."` are never returned by `ReadDir`, so they
/// match nothing, as in Go. That comparison is `name.to_string_lossy() ==
/// name_pattern`, which is a raw-byte comparison in Go; the lossy conversion can
/// only differ for a *non-UTF-8* file name, which APFS refuses to create at all
/// (EILSEQ), so it is latent on this platform and can only surface on a
/// filesystem that allows such names (e.g. Linux under a non-UTF-8 locale).
///
/// The `dir` guard above is unreachable in the current tree: the only caller
/// ([`process_includes`], `file.rs:424-430`) refuses a missing or non-directory
/// `search_dir` with Go's `include: directory of … not exist` error first.
/// Measured by deleting the guard and running `cargo test -p frp-core --lib`:
/// the suite stays green (1071 passed), including
/// `legacy_ini_common_include_missing_dir_refuses_like_go`, which still reports
/// the caller's message. The guard is **not** a fidelity win: its
/// `Ok(Vec::new())` → rc 0 is itself a divergence, since Go's `os.Stat` then
/// `os.ReadDir` (`pkg/config/legacy/parse.go:75-81`) returns an error → rc 1.
/// It is kept only as a cheap total-function backstop on the one path where it
/// can still run — a TOCTOU race between the caller's pre-check and this
/// enumeration — where dropping it would in fact be the more Go-faithful shape.
///
/// Returns sorted list of matching file paths.
/// (`results.sort()` mirrors `os.ReadDir`, whose entries come back ordered by
/// file name — pin `test_include_glob_entries_are_processed_in_sorted_order`.)
fn glob_in_dir(
    dir: &Path,
    name_pattern: &str,
) -> Result<Vec<std::path::PathBuf>, Box<dyn std::error::Error>> {
    if !dir.exists() || !dir.is_dir() {
        return Ok(Vec::new());
    }

    let has_star = name_pattern.contains('*');

    // Build prefix/suffix for matching
    let (prefix, suffix) = if let Some(pos) = name_pattern.find('*') {
        (&name_pattern[..pos], &name_pattern[pos + 1..])
    } else {
        (name_pattern, "")
    };

    let ext = Path::new(name_pattern).extension().and_then(|s| s.to_str());

    let mut results = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        // Go's `fi.IsDir()` — the directory entry's own type, no symlink
        // follow, so a symlink→dir and a dangling symlink are *not* skipped.
        if entry.file_type()?.is_dir() {
            continue;
        }
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !has_star {
            // No wildcard — `filepath.Match` degenerates to string equality
            // with the entry name.
            if name == name_pattern {
                results.push(path);
            }
            continue;
        }
        // Match extension
        if let Some(ext) = ext {
            if Path::new(name.as_ref())
                .extension()
                .and_then(|s| s.to_str())
                != Some(ext)
            {
                continue;
            }
        }
        // Match prefix and suffix
        if name.starts_with(prefix) && name.ends_with(suffix) {
            results.push(path);
        }
    }

    results.sort();
    Ok(results)
}

/// Deep-merge two TOML values. `base` is mutated to include all keys from `overlay`.
/// - Scalars: overlay replaces base
/// - Tables: recursively merged
/// - Arrays: concatenated (base + overlay)
fn deep_merge_toml(base: &mut toml::Value, overlay: &toml::Value) {
    use toml::Value;

    match (base, overlay) {
        (Value::Table(ref mut base_table), Value::Table(ref overlay_table)) => {
            for (key, val) in overlay_table {
                match base_table.get_mut(key) {
                    Some(base_val) => {
                        deep_merge_toml(base_val, val);
                    }
                    None => {
                        base_table.insert(key.clone(), val.clone());
                    }
                }
            }
        }
        (Value::Array(ref mut base_arr), Value::Array(ref overlay_arr)) => {
            base_arr.extend(overlay_arr.clone());
        }
        (base_val, _) => {
            *base_val = overlay.clone();
        }
    }
}

/// Collect all non-directory entries from a directory tree (recursive walk).
/// Returns file paths in sorted order. Used for `--config-dir` mode.
pub fn collect_config_files(
    dir: &Path,
) -> Result<Vec<std::path::PathBuf>, Box<dyn std::error::Error>> {
    let mut files = Vec::new();
    // Canonicalized directories seen so far. `--config-dir` trees may
    // contain symlinked subdirectories (e.g. a deploy dir that symlinks a
    // shared config subdir); a cycle (dir → ancestor → dir) would otherwise
    // recurse forever and blow the stack (SIGSEGV under panic=abort,
    // uncatchable). Canonicalize-then-track terminates the walk: the first
    // visit descends, any repeat visit returns immediately. Same-directory
    // symlink aliases are visited once (their files are collected under the
    // first path), matching the "walk the tree once" contract.
    let mut visited = std::collections::HashSet::new();
    collect_config_files_inner(dir, &mut files, &mut visited)?;
    files.sort();
    Ok(files)
}

fn collect_config_files_inner(
    dir: &Path,
    files: &mut Vec<std::path::PathBuf>,
    visited: &mut std::collections::HashSet<std::path::PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    // `path.is_dir()` follows symlinks — that is exactly the cycle vector.
    // Track the canonicalized directory: a symlink pointing at an ancestor
    // resolves to an already-visited canonical path and stops the walk.
    let canonical = std::fs::canonicalize(dir)?;
    if !visited.insert(canonical) {
        return Ok(());
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_config_files_inner(&path, files, visited)?;
        } else if path
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| {
                // Case-insensitive, matching `detect_format` (e.g. `CONFIG.YAML`).
                matches!(
                    ext.to_ascii_lowercase().as_str(),
                    "toml" | "ini" | "json" | "yaml" | "yml"
                )
            })
        {
            files.push(path);
        }
    }
    Ok(())
}
