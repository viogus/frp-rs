use std::path::Path;

use super::client::ClientConfig;
use super::format::{detect_format, parse_to_toml_value};
use super::loader::{validate_client_config, validate_server_config, ConfigPresence};
use super::normalize::{load_config_from_file, normalize_client_config, normalize_server_config};
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
        known_server_keys,
        normalize_server_config,
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
        known_client_keys,
        normalize_client_config,
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
/// `auth.oidc.tokenSource` — which is exactly the pair the client daemon gates
/// at construction (`frp-client/src/service.rs`).
///
/// Go's client validation gates **both** spellings. `auth.tokenSource` is gated
/// by `pkg/config/v1/validation/auth.go` (measured: `frpc verify -c <exec cfg>`
/// is rc 1 on v0.71.0 without the allow-list, rc 0 with it), and
/// `auth.oidc.tokenSource` is gated by Go's `validateOIDCConfig`
/// (`pkg/config/v1/validation/client.go`) — measured on the same binary, a
/// config carrying `[auth.oidc.tokenSource] type = "exec"` prints
/// `unsafe feature "TokenSourceExec" is not enabled. …` and that line
/// disappears once `--allow-unsafe TokenSourceExec` is passed (Go's remaining
/// rc 1 there is its own "cannot specify both auth.oidc.tokenSource and any
/// other field of auth.oidc" rule, not the gate). The two-field set here is
/// therefore exact Go parity, not a frp-rs extension, and it is also the pair
/// the client daemon gates at construction (`frp-client/src/service.rs`).
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
) -> Result<(), Box<dyn std::error::Error>> {
    use toml::Value;

    let table = match value.as_table_mut() {
        Some(t) => t,
        None => return Ok(()),
    };

    // Extract includes list (support both "includes" and "include" keys)
    let patterns: Vec<String> = match table.remove("includes").or_else(|| table.remove("include")) {
        Some(Value::Array(arr)) => arr
            .into_iter()
            .filter_map(|v| match v {
                Value::String(s) => Some(s),
                _ => None,
            })
            .collect(),
        Some(Value::String(s)) => vec![s],
        _ => Vec::new(),
    };

    if patterns.is_empty() {
        return Ok(());
    }

    for pattern in &patterns {
        let full_pattern = if Path::new(pattern).is_absolute() {
            pattern.clone()
        } else {
            base_dir.join(pattern).to_string_lossy().to_string()
        };

        let full_path = Path::new(&full_pattern);
        // Go frp fails hard when an include's directory is missing
        // (pkg/config/load.go `LoadAdditionalClientConfigs`: `os.Stat(absDir)`
        // error; legacy/client.go:393 "include: directory of %s not exist").
        // frp-rs resolves relative patterns against the main config file's
        // directory (documented divergence, docs/config.md) but mirrors the
        // fatal error: a missing directory is a config bug, not a silent
        // merge-nothing. A glob that matches nothing in an EXISTING dir stays
        // silent, exactly like Go's zero-match loop.
        let parent = full_path.parent().unwrap_or(Path::new("."));
        if !parent.exists() || !parent.is_dir() {
            return Err(format!(
                "include: directory of {} not exist (included by pattern {pattern})",
                parent.display()
            )
            .into());
        }
        // Directory read errors are fatal too (Go `os.ReadDir` error).
        let paths = simple_glob(&full_pattern)?;

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

/// Simple glob matching that supports a single `*` wildcard per path component.
/// Returns sorted list of matching file paths.
fn simple_glob(pattern: &str) -> Result<Vec<std::path::PathBuf>, Box<dyn std::error::Error>> {
    let pattern_path = Path::new(pattern);

    // Split into: base directory (non-wildcard prefix) + wildcard component
    let parent = pattern_path.parent().unwrap_or(Path::new("."));
    let filename_part = pattern_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("*");

    if !filename_part.contains('*') {
        // No wildcard — check if exact file exists
        let path = Path::new(pattern);
        if path.is_file() {
            return Ok(vec![path.to_path_buf()]);
        }
        return Ok(Vec::new());
    }

    if !parent.exists() || !parent.is_dir() {
        return Ok(Vec::new());
    }

    // Build prefix/suffix for matching
    let (prefix, suffix) = if let Some(pos) = filename_part.find('*') {
        (&filename_part[..pos], &filename_part[pos + 1..])
    } else {
        (filename_part, "")
    };

    let ext = pattern_path.extension().and_then(|s| s.to_str());

    let mut results = Vec::new();
    for entry in std::fs::read_dir(parent)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        // Match extension
        if let Some(ext) = ext {
            if path.extension().and_then(|s| s.to_str()) != Some(ext) {
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
