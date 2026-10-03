use super::client::{AuthClientConfig, ClientConfig, ProxyConfig, VisitorConfig};
use super::format::ConfigFormat;
use super::normalize::{
    expand_env_vars, expand_template_functions, normalize_client_config, normalize_server_config,
    toml_to_json,
};
use super::server::{PortsRange, ServerConfig, ValueSource};
use crate::feature_gate::VIRTUAL_NET;

/// Parse a bandwidth limit string like "1MB", "500KB", "100KB".
/// Returns bytes per second, or None if unparseable.
/// Go frp compat: only supports "MB" and "KB" suffixes (case-insensitive).
/// Bare numbers, single-letter suffixes ("M", "K"), and "GB" are rejected.
/// Empty string returns Some(0) (no limit, Go compat).
///
/// Note: Empty string returns `Some(0)` (not `None`) so callers using `is_some()`
/// will treat empty as a valid config value. This matches Go frp's behavior where
/// an empty bandwidth limit field means "no limit" (effectively 0). Callers that
/// need to distinguish "not set" from "set to 0" should check `is_empty()` before
/// calling this function.
/// Parse a bandwidth limit like Go frp `types.BandwidthQuantity`:
/// - case-SENSITIVE "KB"/"MB" suffix ("kb"/"mb" are rejected like Go's
///   "unit not support");
/// - bare numbers and other suffixes are invalid;
/// - an empty string, or a non-positive number, means NO limit
///   (returns Some(0); Go's limiter treats bytes <= 0 as no limiter).
pub fn parse_bandwidth_limit(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.is_empty() {
        return Some(0);
    }
    let (num_str, mult) = {
        if let Some(fstr) = s.strip_suffix("MB") {
            (fstr.trim(), 1_048_576u64)
        } else {
            let fstr = s.strip_suffix("KB")?;
            (fstr.trim(), 1024u64)
        }
    };
    let num: f64 = num_str.parse().ok()?;
    if num <= 0.0 {
        // Go: 0 / negative values mean no limit (NewBandwidthLimiter returns
        // nil for bytes <= 0).
        return Some(0);
    }
    Some((num * mult as f64) as u64)
}

/// Parse a comma-separated port range string into a list of [`PortsRange`].
///
/// Supports Go frp v0.70.1 syntax: `"10000-20000,30000,{single=40000}"`.
/// Returns an empty vec when the string is empty; **invalid entries are an
/// error** (Go's config validation rejects them rather than silently
/// disabling the restriction).
pub fn parse_allow_ports(s: &str) -> Result<Vec<PortsRange>, String> {
    if s.trim().is_empty() {
        return Ok(vec![]);
    }
    let mut out = Vec::new();
    for part in s.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        // {single=N} form.
        if let Some(inner) = part.strip_prefix('{').and_then(|p| p.strip_suffix('}')) {
            let single = inner
                .strip_prefix("single=")
                .and_then(|v| v.trim().parse::<u16>().ok())
                .ok_or_else(|| format!("invalid allow_ports entry '{part}'"))?;
            out.push(PortsRange {
                start: single,
                end: single,
                single,
            });
            continue;
        }
        if let Some((a, b)) = part.split_once('-') {
            let start: u16 = a
                .trim()
                .parse()
                .map_err(|_| format!("invalid allow_ports entry '{part}'"))?;
            let end: u16 = b
                .trim()
                .parse()
                .map_err(|_| format!("invalid allow_ports entry '{part}'"))?;
            if start == 0 || end == 0 {
                return Err(format!(
                    "invalid allow_ports entry '{part}': port 0 is not allowed"
                ));
            }
            // Go frp v0.70.1 compat (util.ParseRangeNumbers): a reversed range
            // (max < min) is a config error, not silently swapped (audit task
            // 9 finding 7).
            if end < start {
                return Err(format!(
                    "invalid allow_ports entry '{part}': range number is invalid"
                ));
            }
            out.push(PortsRange {
                start,
                end,
                single: 0,
            });
        } else {
            // Single port: treat as start=end.
            let p: u16 = part
                .parse()
                .map_err(|_| format!("invalid allow_ports entry '{part}'"))?;
            if p == 0 {
                return Err(format!(
                    "invalid allow_ports entry '{part}': port 0 is not allowed"
                ));
            }
            out.push(PortsRange {
                start: p,
                end: p,
                single: 0,
            });
        }
    }
    Ok(out)
}

/// Compute the total number of ports across all ranges.
pub fn count_ports(ranges: &[PortsRange]) -> u16 {
    ranges
        .iter()
        .map(|r| {
            if r.single > 0 {
                1u32
            } else {
                r.end.saturating_sub(r.start) as u32 + 1
            }
        })
        .fold(0u32, |acc, n| acc.saturating_add(n))
        .min(u16::MAX as u32) as u16
}

/// Normalize a parsed TOML value from Go frp format to frp-rs format.
/// Handles:
/// - `[common]` section → flatten to top level
/// - Flat auth_*, log_*, web_server_*, transport_* → nested structs
/// - Field name differences (protocol → transport_protocol, etc.)
pub fn load_server_config_from_str(
    content: &str,
) -> Result<ServerConfig, Box<dyn std::error::Error>> {
    let mut value: toml::Value =
        toml::from_str(content).map_err(|e| format!("TOML parse error: {e}"))?;
    expand_env_vars(&mut value);
    expand_template_functions(&mut value);
    let web_server_tls_enable_set = ConfigPresence::web_server_tls_enable_set_in(&value);
    let server_tls_enable_set = ConfigPresence::server_tls_enable_set_in(&value);
    // TOML cannot carry a legacy `.ini` section, so the collector's refusal
    // (a typeless `role = "visitor"` section — see
    // `collect_legacy_ini_proxy_sections`) is unreachable on this path.
    normalize_server_config(&mut value, ConfigFormat::Toml)
        .expect("TOML has no legacy INI sections");
    let mut presence = ConfigPresence::from_normalized_value(&value);
    presence.web_server_tls_enable_set = web_server_tls_enable_set;
    // Kept in lockstep with `load_config_from_file`'s capture. This entry point
    // returns no `ConfigPresence`, so nothing can warn *from here* — it exists
    // for embedders and the unit tests — but the two loaders must not disagree
    // about what "the user wrote the key" means.
    presence.server_tls_enable_set = server_tls_enable_set;
    let json_value = toml_to_json(value);
    let mut cfg: ServerConfig =
        serde_json::from_value(json_value).map_err(|e| format!("config validation error: {e}"))?;
    validate_server_config(&mut cfg)?;
    cfg.transport
        .complete_with_heartbeat_timeout_set(presence.server_heartbeat_timeout_set);
    cfg.complete();
    Ok(cfg)
}

pub fn load_client_config_from_str(
    content: &str,
) -> Result<ClientConfig, Box<dyn std::error::Error>> {
    let mut value: toml::Value =
        toml::from_str(content).map_err(|e| format!("TOML parse error: {e}"))?;
    expand_env_vars(&mut value);
    expand_template_functions(&mut value);
    let web_server_tls_enable_set = ConfigPresence::web_server_tls_enable_set_in(&value);
    // Same as the server path above: not the legacy `.ini` dialect, so the
    // collector's visitor refusal cannot fire here.
    normalize_client_config(&mut value, ConfigFormat::Toml)
        .expect("TOML has no legacy INI sections");
    let mut presence = ConfigPresence::from_normalized_value(&value);
    presence.web_server_tls_enable_set = web_server_tls_enable_set;
    let mut cfg: ClientConfig = serde_json::from_value(toml_to_json(value))
        .map_err(|e| format!("config validation error: {e}"))?;
    validate_client_config(&mut cfg)?;
    cfg.complete_with_heartbeat_set(
        presence.client_heartbeat_interval_set,
        presence.client_heartbeat_timeout_set,
    );
    Ok(cfg)
}

/// Presence flags for fields whose Go default depends on whether the user
/// explicitly configured them. Computed from the normalized TOML value so
/// serde defaults cannot be confused with explicit values.
///
/// Two flags are the exception to "from the normalized value":
/// `[webServer.tls]` / `[web_server.tls]` `enable` is **removed** by
/// `normalize_web_server_section`, and the flat `tls_enable` key is
/// **synthesized** by the server normalizer from the legacy `[transport.tls]`
/// section, so `ConfigPresence::web_server_tls_enable_set_in` and
/// `ConfigPresence::server_tls_enable_set_in` both have to read the value
/// *before* normalization. See each flag's own doc.
///
/// Public because the binaries own the diagnostics that the loader can no longer
/// emit: on the `-c` path the config is loaded **before** `init_logging`, so a
/// `tracing::warn` from inside the loader has no subscriber to reach. The
/// binaries re-emit them after `init_logging` via
/// [`ConfigPresence::warn_inert_web_server_tls_enable`] and
/// [`ConfigPresence::warn_inert_server_tls_enable`].
#[derive(Debug, Clone, Copy, Default)]
pub struct ConfigPresence {
    pub(super) server_heartbeat_timeout_set: bool,
    pub(super) client_heartbeat_interval_set: bool,
    pub(super) client_heartbeat_timeout_set: bool,
    /// `[webServer.tls]` / `[web_server.tls]` — top-level or under `[common]`,
    /// in either key case, in an `.ini` file, or in an `includes` file — wrote
    /// an `enable` key. The **value** is deliberately not carried: the loader
    /// drops the key before serde, and the diagnostic is about the key being
    /// inert in every combination (`enable = true` with no pair is the one that
    /// silently serves plaintext HTTP; `enable = false` beside a valid pair is
    /// the one where TLS stays on against the written value). See
    /// [`ConfigPresence::web_server_tls_enable_set_in`] for how the two section
    /// spellings and their `[common]` forms resolve.
    pub(super) web_server_tls_enable_set: bool,
    /// Flat `tls_enable` — top-level, under `[common]`, or in an `includes` file
    /// — was **written** by the user. The **value** is deliberately not carried:
    /// the field is inert either way, so the diagnostic is about the key being
    /// present. Read from the raw, pre-normalization value, because
    /// `normalize_server_config` *synthesizes* `tls_enable = true` from the
    /// legacy `[transport.tls]` section (`force`, `certFile`, `keyFile`), which
    /// is not a written key and must stay silent. See
    /// [`ConfigPresence::server_tls_enable_set_in`].
    pub(super) server_tls_enable_set: bool,
    /// `kcp_bind_port` / `kcpBindPort` — at the top level, under `[common]`
    /// (flattened into the root by `normalize_server_config` before this is
    /// read), in an `.ini` file, or in an `includes` file — was written with a
    /// **non-zero** port in a build whose `kcp` feature is off, so
    /// `ServerConfig` has no such field, serde drops the key, and
    /// `frp-server`'s KCP listener is not compiled: the port the file names
    /// stays closed. Only a value other than the integer `0` counts, because
    /// `0` is the documented "disabled" value and every build shape honours it
    /// identically (`docs/config.md`, the three gated listener rows). See
    /// [`ConfigPresence::warn_unhonoured_server_feature_keys`].
    #[cfg(not(feature = "kcp"))]
    pub(super) server_kcp_bind_port_unhonoured: bool,
    /// The `quic` twin of [`Self::server_kcp_bind_port_unhonoured`].
    #[cfg(not(feature = "quic"))]
    pub(super) server_quic_bind_port_unhonoured: bool,
    /// The `websocket` twin of [`Self::server_kcp_bind_port_unhonoured`]
    /// (`websocket_port` / `websocketPort`).
    #[cfg(not(feature = "websocket"))]
    pub(super) server_websocket_port_unhonoured: bool,
    /// `web_server.port` / `webServer.port` — at the top level, under
    /// `[common]`, in an `.ini` file, in an `includes` file, or via the legacy
    /// top-level `dashboard_port` spelling `normalize_server_config` moves into
    /// the section — was written with a **non-zero** port.
    ///
    /// Unlike the three ports above, this key's reader is **not** in `frp-core`:
    /// `web_server` is read by `frp-server`'s `dashboard` feature, and the field
    /// is **unconditional** in `ServerConfig`, so a dashboard-less build
    /// deserializes the key and then never reads it. `frp-core` cannot observe
    /// that feature, so the flag is computed in **every** build and the caller's
    /// [`ListenerPortReader`] decides whether it is emitted. See
    /// [`ConfigPresence::warn_inert_web_server_port`].
    pub(super) web_server_port_unhonoured: bool,
    /// The `ssh_tunnel_gateway.bind_port` / `sshTunnelGateway.bindPort` twin of
    /// [`Self::web_server_port_unhonoured`]: read by `frp-server`'s `ssh`
    /// feature, unconditional in `ServerConfig`. See
    /// [`ConfigPresence::warn_inert_ssh_tunnel_gateway_bind_port`].
    pub(super) ssh_tunnel_gateway_bind_port_unhonoured: bool,
}

/// Which **web server** a build compiles (if any), and whether that web server
/// can serve HTTPS — the two facts that decide which `[web_server.tls] enable`
/// diagnostic tells the truth, resolved by the crate that owns both features.
///
/// The `web_server` section's only readers are `frp-server`'s `dashboard`
/// feature and `frp-client`'s `admin` feature, and the acceptor that makes
/// either of them serve HTTPS is gated on that **same crate's** `tls` feature
/// (`frp-server/src/service.rs`, `frp-client/src/admin.rs`); `frp-core` owns
/// neither, so it cannot resolve this itself and takes the answer as an
/// argument.
///
/// It must come from the owning crate, **not** from the binary's own `cfg!`:
/// `frpc`'s `tls` feature is off in every default build (its `full` forwards
/// `frp-client/default`, while `frpc/tls` is a separate switch — the same trap
/// `frps/tls` has), so `cfg!(feature = "tls")` inside `frpc/src/main.rs` is
/// `false` in a build whose admin server *can* serve HTTPS. The binaries
/// therefore ask the owning crate — `frp_client::web_server_tls_enable_reader`
/// and `frp_server::service::web_server_tls_enable_reader` — and pass this value
/// on to [`ConfigPresence::warn_inert_web_server_tls_enable`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebServerTlsEnableReader {
    /// No dashboard/admin web server is compiled into this build: the default
    /// `frps` (`full`, which does not include `frp-server/dashboard`),
    /// `frps-tiny`, `frps-micro`, and a default `frpc` (no `admin`).
    NoWebServer,
    /// A web server **is** compiled, but not the `tls` feature that gates its
    /// acceptor, so it can only ever serve plaintext: a configured
    /// `cert_file` + `key_file` pair is discarded (`frp-client/src/admin.rs`,
    /// the `not(feature = "tls")` arm).
    WebServerNoTls,
    /// A web server is compiled **and** can serve HTTPS, from a non-empty
    /// `cert_file` + `key_file` pair.
    WebServerTls,
}

impl WebServerTlsEnableReader {
    /// The two questions the owning crate answers about itself: does this build
    /// compile a web server, and does it compile the `tls` feature that gates
    /// that server's acceptor?
    pub const fn from_features(has_web_server: bool, has_tls: bool) -> Self {
        match (has_web_server, has_tls) {
            (false, _) => Self::NoWebServer,
            (true, false) => Self::WebServerNoTls,
            (true, true) => Self::WebServerTls,
        }
    }

    /// The one text that is true of this build — see
    /// [`WEB_SERVER_TLS_ENABLE_INERT_WARNING`] and its two siblings.
    const fn warning(self) -> &'static str {
        match self {
            Self::NoWebServer => WEB_SERVER_TLS_ENABLE_INERT_WARNING_NO_DASHBOARD,
            Self::WebServerNoTls => WEB_SERVER_TLS_ENABLE_INERT_WARNING_NO_TLS,
            Self::WebServerTls => WEB_SERVER_TLS_ENABLE_INERT_WARNING,
        }
    }
}

/// Whether the crate that reads a feature-gated **listener port** compiles the
/// feature that reads it.
///
/// The two ports this answers for — `web_server.port` and
/// `ssh_tunnel_gateway.bind_port` — are read only by `frp-server` (its
/// `dashboard` and `ssh` features), and both fields are **unconditional** in
/// `ServerConfig`, so `frp-core` always deserializes them and can never resolve
/// this itself. Exactly like [`WebServerTlsEnableReader`], the owning crate is
/// asked (`frp_server::service::web_server_port_reader` /
/// `ssh_tunnel_gateway_bind_port_reader`) and the answer is passed to
/// [`ConfigPresence::warn_inert_web_server_port`] /
/// [`ConfigPresence::warn_inert_ssh_tunnel_gateway_bind_port`].
///
/// This is the deliberate difference from the three `#[cfg]`-gated kcp / quic /
/// websocket ports: there the *field* is compiled out, so the presence flag
/// itself carries the build shape ([`ConfigPresence::warn_unhonoured_server_feature_keys`]);
/// here the field is always present and only the reader is missing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListenerPortReader {
    /// The feature that reads the port is compiled: a non-zero port is honoured
    /// and the diagnostic stays silent.
    Present,
    /// The feature is not compiled: the key is accepted by serde and then
    /// silently ignored — no listener is bound.
    Absent,
}

impl ListenerPortReader {
    /// The owning crate's answer to its own one question: does this build
    /// compile the feature that reads the port?
    pub const fn from_features(has_reader: bool) -> Self {
        if has_reader {
            Self::Present
        } else {
            Self::Absent
        }
    }
}

/// The reader-gated listener **ports** a CLI overlay actually applied.
///
/// The config-file path resolves the same question inside
/// [`ConfigPresence::from_normalized_value`] (`sub_port_requested`, which counts
/// only a **non-zero** port). The CLI overlay, however, runs *after* that load —
/// `FrpsArgs::override_server_config` writes `cfg.web_server.port` directly — so
/// its writes are a second source of the same request and have to be merged into
/// the same presence flag. Without that, `frps --dashboard-port 7500` (with no
/// `-c`/`--config-dir`) binds no dashboard and says nothing, while the identical
/// `[web_server] port = 7500` in a file warns.
///
/// **The whole family, enumerated**, because `web_server.port` is not obviously
/// alone: `web_server.port` is reachable from the overlay through
/// `--dashboard-port`, which `svr_dashboard` registers on **every** shape, so
/// flag and warning are always reachable together. The other reader-gated ports
/// cannot be applied by the overlay at all — `ssh_tunnel_gateway.bind_port` and
/// `websocket_port` have no CLI flag, and `--kcp-bind-port`/`--quic-bind-port`
/// exist only under `cfg(feature = "kcp")`/`cfg(feature = "quic")`, so in the
/// shapes whose reader is compiled out they are an unknown-flag error rather
/// than a silent ignore.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AppliedReaderGatedPorts {
    /// A **non-zero** `--dashboard-port` wrote `web_server.port`, whose only
    /// reader is `frp-server`'s `dashboard` feature.
    pub web_server_port: bool,
}

/// The `[web_server.tls] enable` diagnostic for a build that **compiles a
/// dashboard**, in one place so `frps` and `frpc` cannot drift. Callers gate it
/// on [`ConfigPresence::web_server_tls_enable_set`]; it is emitted **after**
/// `init_logging`, which is the whole point of the presence flag.
///
/// **Three variants, picked by the caller.** The `web_server` section is read
/// only by code behind `frp-server`'s `dashboard` feature (the dashboard) and
/// `frp-client`'s `admin` feature (the client's admin server), while this
/// diagnostic lives in `frp-core`, which has **no** such feature — a
/// `#[cfg(feature = "dashboard")]` here is constant `false` in every
/// configuration and would pin nothing. The awareness is therefore supplied by
/// the caller: [`ConfigPresence::warn_inert_web_server_tls_enable`] takes the
/// build's answer ([`WebServerTlsEnableReader`]) and emits *this* constant,
/// [`WEB_SERVER_TLS_ENABLE_INERT_WARNING_NO_DASHBOARD`] or
/// [`WEB_SERVER_TLS_ENABLE_INERT_WARNING_NO_TLS`]. That mirrors
/// `frp-server`'s `server_reader_present`, which resolves the features that
/// crate owns.
///
/// The sites that call it are the ones with a log sink: `frps`'s two startup
/// paths, `frpc`'s two startup paths plus `frpc verify`, and the two in-process
/// **reloads** (`frp-server`'s `Service::reload`, `frp-client`'s
/// `reload_from_sources`) — one record per load, so a reload adds one rather than
/// replacing the startup record.
///
/// The `frpc` admin API's config **GET** is the exception, because it is the only
/// **polled** site: `frp_client::admin::config_from_file` emits on a **state
/// change**, not per request. Its `AdminState` cell is seeded from the file at
/// admin-server startup, so a file that already wrote the key produces **0**
/// extra records on the first GET (the startup load's record is not repeated) and
/// only a later edit that adds the key emits — where "later" means after the
/// admin server has started: an edit landing between the startup load and the
/// spawn is baselined, because the seed reads the file at spawn. The one site
/// that stays silent is
/// the one with no sink at all: `frps verify` (it never installs a subscriber),
/// which is why its one-line output stays one line.
pub const WEB_SERVER_TLS_ENABLE_INERT_WARNING: &str = "web_server.tls.enable has no \
     effect: the dashboard HTTPS server is enabled by a non-empty `cert_file` + `key_file` \
     pair; without that pair the dashboard serves plaintext HTTP";

/// The same diagnostic for a build that compiles **no dashboard** — the default
/// `frps` (`full`, which does not include `frp-server/dashboard`), `frps-tiny`,
/// `frps-micro`, and a default `frpc` (no `admin` feature).
///
/// It names the build's own inertness — nothing **in this build** reads the key
/// — and carefully names **no dashboard behaviour**: this build has no dashboard
/// listener to be plaintext or TLS, so it must not inherit the pair/plaintext
/// clause of [`WEB_SERVER_TLS_ENABLE_INERT_WARNING`]. It is the counterpart of
/// `SERVER_TLS_ENABLE_INERT_WARNING`'s `not(feature = "tls")` variant, which
/// likewise says "no TLS support ... never builds a TLS acceptor" rather than
/// describing a TLS acceptor.
pub const WEB_SERVER_TLS_ENABLE_INERT_WARNING_NO_DASHBOARD: &str = "web_server.tls.enable \
     has no effect: this build has no dashboard support, so nothing reads the key and no \
     dashboard HTTPS server is built";

/// The same diagnostic for a build that compiles a **web server without the
/// `tls` feature** that gates its HTTPS acceptor — `frpc` built
/// `--no-default-features --features micro,admin`. It is
/// the third answer, and neither of the other two is true here: the dashboard
/// clause would describe an acceptor this build never compiles (the pair is
/// *discarded*, `frp-client/src/admin.rs`, the `not(feature = "tls")` arm),
/// while the no-dashboard clause would deny the web server the build in fact
/// has. So it names what is true — nothing reads the key, and this build cannot
/// build an HTTPS server at all — the same shape as
/// `SERVER_TLS_ENABLE_INERT_NO_TLS_CLAUSES`, which likewise says "no TLS
/// support" rather than describing an acceptor. It deliberately names neither
/// the `cert_file` + `key_file` pair nor `plaintext HTTP`: those are the
/// dashboard clause's facts, and this text must stay disjoint from both siblings
/// because the pins dispatch on substrings.
///
/// Pinned by `the_no_tls_build_names_no_tls_behaviour`
/// (`frp-core/tests/web_server_tls_enable_warning.rs`) and, in a real
/// admin-without-tls binary build, by
/// `frp-client/tests/reload_warning_delivery.rs`.
pub const WEB_SERVER_TLS_ENABLE_INERT_WARNING_NO_TLS: &str = "web_server.tls.enable has no \
     effect: nothing reads the key, and this build has no TLS support, so the dashboard/admin \
     HTTPS server is never built";

/// The server-side flat `tls_enable` diagnostic, in one place so `frps` and
/// `frp-server` cannot drift. Callers gate it on
/// [`ConfigPresence::server_tls_enable_set`]; it is emitted **after**
/// `init_logging`, which is the whole point of the presence flag.
///
/// Only the **server**-config load sites call it, and only those with a log
/// sink: `frps`'s two startup paths (`-c`, `--config-dir`) and `frp-server`'s
/// `Service::reload` — one record per load, so a reload adds one rather than
/// replacing the startup record. `frps verify` stays silent (it never installs a
/// subscriber).
///
/// The `frpc` / `frp-client` sites deliberately do **not** call it even though
/// they call the sibling: they load `ClientConfig`, whose `tls_enable` is
/// **live** — `frp-client/src/control.rs` reads it to decide whether the control
/// connection is encrypted and warns when it is not — so emitting "no effect"
/// there would be false. `tls_enable` is inert only on `ServerConfig`.
///
/// **Two variants, selected by the `tls` feature**, because the certificate
/// clauses are false in a build with no TLS: `frp-server`'s whole acceptor block
/// is `#[cfg(feature = "tls")]` (`frp-server/src/service.rs:603`) while this
/// warning is not, and `release.yml` ships `frps-micro` / `frps-tiny` (tiny keeps
/// `tls`; **micro does not**). Measured on a real `frps-micro`
/// (`/tmp/tls-warn-probe/run-micro.sh`): `tls_enable = true` + only
/// `tls_cert_file` exits **0**, logs `frps listener started on 0.0.0.0:27331`
/// and emits this record — no refusal — and with neither file there is no
/// auto-generated line either. So the no-TLS variant says only what is true
/// there (the key is inert and no acceptor is ever built) and names **no**
/// certificate behaviour.
///
/// In a `tls` build the pair clause covers both delivery paths, measured on the
/// real `frps` (`/tmp/tls-warn-probe/run-reload.sh`): at startup a half-written
/// pair exits **1** (`TLS requires both cert_file and key_file to be set; got
/// only one`), and so does an unreadable pair (`open cert file: No such file or
/// directory`); on a SIGUSR1 reload the same shapes keep the server running and
/// report `TLS certificate reload FAILED: … (keeping old config)`. The text
/// therefore says "refused at startup", not "the server refuses to start".
///
/// **Reachable build shapes.** This split is keyed on **frp-core's** `tls`,
/// because frp-core cannot observe `frp-server`'s features. One hand-rolled
/// per-package mix therefore compiles a shape no shipped lane builds:
/// `cargo check -p frps -p frpc --no-default-features --features
/// "frps/micro,frpc/tls"` exits 0, with frp-core's `tls` on (via frpc →
/// frp-client) while frp-server's stays off. Measured with `cargo tree -p frps
/// -p frpc --no-default-features --features "frps/micro,frpc/tls" -e features -i
/// frp-core`, which ends `frp-core feature "tls"` (reached from `frpc feature
/// "tls" (command-line)` → `frp-client feature "tls"`); the same command with
/// `-i frp-server` shows frp-server's only branch as `frps feature "micro"
/// (command-line)`, with no `tls` feature. That binary gates the acceptor off
/// (`frp-server/src/service.rs:603` is `#[cfg(feature = "tls")]`, with the
/// no-acceptor branch at `:635`), so this variant's certificate clauses would
/// describe a path it cannot take. Every lane builds at the
/// workspace root with `tiny`/`micro`
/// (`.github/workflows/release.yml:100/102/108/110/159/162/210/213` and
/// `.github/workflows/ci.yml:3653`/`.github/workflows/ci.yml:3657`), where the
/// two crates' `tls` agree, so the mixed shape is a known, unshipped one.
#[cfg(feature = "tls")]
pub const SERVER_TLS_ENABLE_INERT_TLS_CLAUSES: [&str; 2] = [
    "tls_enable has no effect on the server: nothing in frp-server or frps reads it.",
    "The server's TLS switch is `tls_only` (Go's `transport.tls.force`); the TLS \
     acceptor is built from `tls_cert_file` + `tls_key_file` — a half-written (only \
     one of the two) or unreadable pair is refused at startup, a reload reports the \
     failure and keeps the running acceptor, and with neither set the server \
     auto-generates a self-signed certificate pair",
];

/// The no-TLS variant of the server `tls_enable` diagnostic, as its clauses. The
/// `tls`-build clauses (and the measurements behind the split) are on
/// [`SERVER_TLS_ENABLE_INERT_TLS_CLAUSES`] above; this one names no certificate
/// behaviour, because a build without the `tls` feature never builds a TLS
/// acceptor.
#[cfg(not(feature = "tls"))]
pub const SERVER_TLS_ENABLE_INERT_NO_TLS_CLAUSES: [&str; 2] = [
    "tls_enable has no effect on the server: nothing in frp-server or frps reads it.",
    "This build has no TLS support (frp-core's `tls` feature is off), so the server \
     never builds a TLS acceptor",
];

/// The written-`tls_enable` server diagnostic: this build shape's clause array
/// ([`SERVER_TLS_ENABLE_INERT_TLS_CLAUSES`] /
/// [`SERVER_TLS_ENABLE_INERT_NO_TLS_CLAUSES`]) joined with a single space, so the
/// text is defined **once**. A `&str` const cannot join, hence the one-time
/// `LazyLock`.
///
/// `frp-core/tests/server_tls_enable_warning.rs` derives its whole-text assertion
/// from the same array, so a reworded clause cannot leave a copied literal behind
/// in the test; the clause **count** is pinned there too, so a clause appended or
/// dropped from the array still reds.
pub static SERVER_TLS_ENABLE_INERT_WARNING: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| {
        #[cfg(feature = "tls")]
        let clauses = SERVER_TLS_ENABLE_INERT_TLS_CLAUSES;
        #[cfg(not(feature = "tls"))]
        let clauses = SERVER_TLS_ENABLE_INERT_NO_TLS_CLAUSES;
        clauses.join(" ")
    });

/// The written-but-unhonourable `kcp_bind_port` diagnostic, as its clauses, in
/// the only build shape that has one — `kcp` off, where `ServerConfig` has no
/// `kcp_bind_port` field, serde drops the key, and `frp-server` never builds the
/// KCP listener. The text is **not** the `tls_enable` wording, because the two
/// keys fail differently: `tls_enable` is a compiled field that no code reads
/// (inert in every build shape), while `kcp_bind_port` is a live field that this
/// build *cannot parse at all* and would honour as soon as the feature came
/// back. See [`SERVER_KCP_BIND_PORT_UNHONOURED_WARNING`].
#[cfg(not(feature = "kcp"))]
pub const SERVER_KCP_BIND_PORT_UNHONOURED_CLAUSES: [&str; 2] = [
    "kcp_bind_port has no effect in this build: frp-core's `kcp` feature is off, \
     so ServerConfig has no such field and frp-server never creates the KCP \
     listener the port names.",
    "Write `kcp_bind_port = 0` (the documented \"disabled\" value) to say so in the \
     file, or rebuild frps with the `kcp` feature to listen on it.",
];

/// The `quic` twin of [`SERVER_KCP_BIND_PORT_UNHONOURED_CLAUSES`].
#[cfg(not(feature = "quic"))]
pub const SERVER_QUIC_BIND_PORT_UNHONOURED_CLAUSES: [&str; 2] = [
    "quic_bind_port has no effect in this build: frp-core's `quic` feature is off, \
     so ServerConfig has no such field and frp-server never creates the QUIC \
     listener the port names.",
    "Write `quic_bind_port = 0` (the documented \"disabled\" value) to say so in the \
     file, or rebuild frps with the `quic` feature to listen on it.",
];

/// The `websocket` twin of [`SERVER_KCP_BIND_PORT_UNHONOURED_CLAUSES`]
/// (`websocket_port` / the Go-inspired `websocketPort` alias).
#[cfg(not(feature = "websocket"))]
pub const SERVER_WEBSOCKET_PORT_UNHONOURED_CLAUSES: [&str; 2] = [
    "websocket_port has no effect in this build: frp-core's `websocket` feature is \
     off, so ServerConfig has no such field and frp-server never creates the \
     WebSocket listener the port names.",
    "Write `websocket_port = 0` (the documented \"disabled\" value) to say so in the \
     file, or rebuild frps with the `websocket` feature to listen on it.",
];

/// The written `kcp_bind_port` diagnostic: [`SERVER_KCP_BIND_PORT_UNHONOURED_CLAUSES`]
/// joined with a single space, so the text is defined **once** (a `&str` const
/// cannot join, hence the one-time `LazyLock`). Exists only in a `kcp`-off build;
/// a build that compiles the field has nothing to report, and the presence flag
/// it would read is not compiled either.
#[cfg(not(feature = "kcp"))]
pub static SERVER_KCP_BIND_PORT_UNHONOURED_WARNING: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| SERVER_KCP_BIND_PORT_UNHONOURED_CLAUSES.join(" "));

/// The `quic` twin of [`SERVER_KCP_BIND_PORT_UNHONOURED_WARNING`].
#[cfg(not(feature = "quic"))]
pub static SERVER_QUIC_BIND_PORT_UNHONOURED_WARNING: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| SERVER_QUIC_BIND_PORT_UNHONOURED_CLAUSES.join(" "));

/// The `websocket` twin of [`SERVER_KCP_BIND_PORT_UNHONOURED_WARNING`].
#[cfg(not(feature = "websocket"))]
pub static SERVER_WEBSOCKET_PORT_UNHONOURED_WARNING: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| SERVER_WEBSOCKET_PORT_UNHONOURED_CLAUSES.join(" "));

/// The written-but-unhonoured `web_server.port` diagnostic, in one place so
/// `frps` and `frp-server` cannot drift. Callers gate it on
/// [`ConfigPresence::web_server_port_unhonoured`] **and** on their own
/// [`ListenerPortReader`] being [`ListenerPortReader::Absent`]; it is emitted
/// after `init_logging` on the run paths, and on stdout by `frps verify` (whose
/// path has no subscriber at all).
///
/// `web_server.port` is **unconditional** in `ServerConfig` — unlike the three
/// `#[cfg]`-gated kcp/quic/websocket ports — so the key always deserializes and
/// only the reader can be missing: in a build without `frp-server`'s
/// `dashboard` feature nothing ever reads it and the port the file names stays
/// closed. The text therefore names the missing **reader**, not a missing field.
pub const WEB_SERVER_PORT_UNHONOURED_WARNING: &str = "web_server.port has no effect: this \
     build has no dashboard support, so nothing reads the key and no dashboard listener is \
     bound";

/// The `ssh_tunnel_gateway.bind_port` (`sshTunnelGateway.bindPort`) twin of
/// [`WEB_SERVER_PORT_UNHONOURED_WARNING`].
pub const SSH_TUNNEL_GATEWAY_BIND_PORT_UNHONOURED_WARNING: &str = "ssh_tunnel_gateway.bind_port \
     has no effect: this build has no SSH tunnel gateway support, so nothing reads the key \
     and no SSH listener is bound";

/// Does one written value ask for a listener?
///
/// The documented "disabled" value is the integer `0` (`docs/config.md`, the
/// three gated listener rows), and every build shape honours it identically, so
/// it is not a request. A **legacy `.ini`** file can spell that same disabled
/// request more than one way: the INI reader infers an integer only for text
/// that round-trips through both renderers
/// (`frp-core/src/config/format.rs`, `infer_ini_value_depth`), so `+0`, `00`
/// and the quoted `"0"` stay `toml::Value::String`, and the lenient integer
/// reader then parses those to zero (`frp-core/src/config/ini_lenient.rs`,
/// `s.parse::<i64>()`). They name the disabled value just as `0` does, so
/// reporting them would be a false record. Everything else — a non-zero
/// integer, a string that parses to a non-zero value or does not parse at all,
/// any other type — names a listener this build may not create.
fn port_value_requests_a_listener(value: &toml::Value) -> bool {
    match value {
        toml::Value::Integer(0) => false,
        toml::Value::String(text) => !matches!(text.parse::<i64>(), Ok(0)),
        _ => true,
    }
}

/// The section-scoped form of [`port_requested`]: was `section.snake` (or
/// `section.camel`) written with a value that asks for a listener? Used by the
/// two ports whose key lives in a sub-table (`web_server.port`,
/// `ssh_tunnel_gateway.bind_port`) and whose **reader** is resolved by the
/// calling crate.
///
/// Both key spellings are required, like [`port_requested`]:
/// `normalize_server_config` renames the section (`sshTunnelGateway` →
/// `ssh_tunnel_gateway`) but not the keys inside it, so `bindPort` survives
/// normalization and is read only thanks to `SshTunnelGatewayConfig`'s serde
/// `alias` — a presence check that knew only the snake key would record
/// `[sshTunnelGateway] bindPort = N` as no request.
fn sub_port_requested(table: &toml::Table, section: &str, snake: &str, camel: &str) -> bool {
    let Some(sub) = table.get(section).and_then(toml::Value::as_table) else {
        return false;
    };
    [snake, camel]
        .iter()
        .any(|key| sub.get(*key).is_some_and(port_value_requests_a_listener))
}

/// Did a written listener-port key ask for a listener?
///
/// `snake` and `camel` are the two spellings serde accepts for one field
/// (`#[serde(alias = …)]`); both are read because `normalize_server_config`
/// leaves them alone — it neither renames the Go spelling nor drops it — and the
/// caller reads the **normalized** table, where `[common]` has already been
/// flattened into the root.
///
/// The value-level rule, the `.ini` zero spellings included, is
/// [`port_value_requests_a_listener`]'s.
#[cfg(not(all(feature = "kcp", feature = "quic", feature = "websocket")))]
fn port_requested(table: &toml::Table, snake: &str, camel: &str) -> bool {
    [snake, camel]
        .iter()
        .any(|key| table.get(*key).is_some_and(port_value_requests_a_listener))
}

impl ConfigPresence {
    pub(super) fn from_normalized_value(value: &toml::Value) -> Self {
        let mut presence = Self::default();
        let Some(table) = value.as_table() else {
            return presence;
        };
        presence.client_heartbeat_interval_set =
            table.contains_key("heartbeat_interval") || table.contains_key("heartbeatInterval");
        presence.client_heartbeat_timeout_set =
            table.contains_key("heartbeat_timeout") || table.contains_key("heartbeatTimeout");
        presence.server_heartbeat_timeout_set = presence.client_heartbeat_timeout_set
            || table
                .get("transport")
                .and_then(toml::Value::as_table)
                .is_some_and(|transport| {
                    transport.contains_key("heartbeat_timeout")
                        || transport.contains_key("heartbeatTimeout")
                });
        // The three feature-gated listener ports: only the builds that cannot
        // deserialize the field carry the flag, so a capable build holds no
        // `false`-forever field (`dead_code`) and cannot emit the record.
        #[cfg(not(feature = "kcp"))]
        {
            presence.server_kcp_bind_port_unhonoured =
                port_requested(table, "kcp_bind_port", "kcpBindPort");
        }
        #[cfg(not(feature = "quic"))]
        {
            presence.server_quic_bind_port_unhonoured =
                port_requested(table, "quic_bind_port", "quicBindPort");
        }
        #[cfg(not(feature = "websocket"))]
        {
            presence.server_websocket_port_unhonoured =
                port_requested(table, "websocket_port", "websocketPort");
        }
        // The two listener ports whose **reader** lives in `frp-server`, not
        // here. The field is unconditional in `ServerConfig`, so every build
        // deserializes it and only the owning crate can say whether anything
        // reads it: the flag is computed in every build and the caller's
        // `ListenerPortReader` gates the record. Read from the **normalized**
        // table, where `[webServer]` has been merged into `web_server`, the
        // legacy `dashboard_port` has been moved into it, `[common]` has been
        // flattened, and `sshTunnelGateway` has been renamed.
        presence.web_server_port_unhonoured =
            sub_port_requested(table, "web_server", "port", "port");
        presence.ssh_tunnel_gateway_bind_port_unhonoured =
            sub_port_requested(table, "ssh_tunnel_gateway", "bind_port", "bindPort");
        presence
    }

    /// Did the file write `[webServer.tls]` / `[web_server.tls]` `enable`?
    ///
    /// Must be called on the **raw, pre-normalization** value: both normalizers
    /// remove the nested `tls` table's mapped keys and `enable`
    /// (`normalize_web_server_section`), so after normalization the key is
    /// unrecoverable.
    ///
    /// The two section spellings can each arrive at the top level or under
    /// `[common]`, and the normalizers resolve them in two steps that this
    /// mirrors:
    ///
    /// 1. `[common]`'s flatten is `table.entry(k).or_insert(v)`, so a top-level
    ///    key wins over the `[common]` one **whole** — for each of
    ///    `web_server` and `webServer` independently. Only the *same* spelling
    ///    is discarded: `[common.web_server.tls] enable` beside a top-level
    ///    `[webServer]` still warns (measured 1, both binaries), because the
    ///    two spellings are different keys to the flatten and merge afterwards;
    /// 2. the surviving `webServer` is then **merged per key** into the
    ///    surviving `web_server` (`merge_section_into`), with the snake_case
    ///    section winning each key it defines and nested tables merging
    ///    recursively.
    ///
    /// So `enable` counts when the effective `web_server.tls` table carries it
    /// *or* the effective `webServer.tls` table does — with the same two
    /// structural exceptions the merge has:
    ///
    /// * `web_server` present but **not a table**: `webServer` is dropped whole
    ///   by `merge_section_into` and cannot contribute;
    /// * `web_server` a table whose `tls` key is present but **not a table**:
    ///   `or_insert_deep` drops the camelCase `tls` sub-table, so only the
    ///   (non-table) primary counts — nothing. Without this arm the detector
    ///   claimed a key the loader had dropped (`[web_server] tls = "scalar"`
    ///   beside `[webServer.tls] enable = true` emitted 1 record while both
    ///   modes loaded all-default), which is exactly the invariant this function
    ///   exists to keep.
    ///
    /// `.ini` matches: the INI reader expands a dotted section header into
    /// nested tables before this runs (`ini_to_toml` in
    /// `frp-core/src/config/format.rs`), so `[web_server.tls]` is a real
    /// nested table like it is in every other format.
    pub(super) fn web_server_tls_enable_set_in(value: &toml::Value) -> bool {
        let Some(table) = value.as_table() else {
            return false;
        };
        let common = table.get("common").and_then(toml::Value::as_table);
        let pick = |key: &str| -> Option<&toml::Value> {
            table.get(key).or_else(|| common.and_then(|c| c.get(key)))
        };
        /// The `tls` value of a candidate section, whatever its type.
        fn tls_of(section: Option<&toml::Value>) -> Option<&toml::Value> {
            section
                .and_then(toml::Value::as_table)
                .and_then(|ws| ws.get("tls"))
        }
        let has_enable = |tls: Option<&toml::Value>| -> bool {
            tls.and_then(toml::Value::as_table)
                .is_some_and(|t| t.contains_key("enable"))
        };
        let snake = pick("web_server");
        let camel = pick("webServer");
        if snake.is_some_and(|v| v.as_table().is_none()) {
            // `web_server` present but not a table: the camelCase section is
            // dropped whole by `merge_section_into`.
            return false;
        }
        let snake_tls = tls_of(snake);
        if snake_tls.is_some_and(|t| t.as_table().is_none()) {
            // `web_server.tls` present but not a table: `or_insert_deep` drops
            // the camelCase `tls` sub-table whole.
            return false;
        }
        has_enable(snake_tls) || has_enable(tls_of(camel))
    }

    /// Whether the loaded file wrote `[webServer.tls]` / `[web_server.tls]`
    /// `enable` — top-level or under `[common]`, in either key case — the
    /// condition for [`Self::warn_inert_web_server_tls_enable`].
    pub fn web_server_tls_enable_set(&self) -> bool {
        self.web_server_tls_enable_set
    }

    /// Did the file write the flat `tls_enable` key — top-level, under
    /// `[common]`, or as a literal `tls_enable` inside `[transport.tls]`?
    ///
    /// Must be called on the **raw, pre-normalization** value:
    /// `normalize_server_config` flattens `[common]` into the top level and then
    /// *synthesizes* `tls_enable = true` from the legacy `[transport.tls]`
    /// section when it carries `force = true`, `certFile` or `keyFile`
    /// (`frp-core/src/config/normalize.rs:865-884`, `table.entry(…).or_insert(…)`),
    /// so after normalization a written key and a synthesized one are
    /// indistinguishable.
    ///
    /// Three spellings count, one of them conditionally (see the next
    /// paragraph). `[common]`'s flatten is
    /// `table.entry(k).or_insert(v)` **on the whole value**
    /// (`frp-core/src/config/normalize.rs:652-655`), so a written top-level key
    /// wins over a written `[common]` one — either way the key was **written**
    /// and the flag is `true`. An `includes` file counts too:
    /// `process_includes` deep-merges before this runs. The `[transport.tls]`
    /// lift renames five Go keys
    /// (`force`/`certFile`/`keyFile`/`trustedCaFile`/`serverName`, the match at
    /// `frp-core/src/config/normalize.rs:869-878`) and passes every other key
    /// through unchanged, so a literal `tls_enable` written *inside* that section
    /// is hoisted onto the same inert field — a third written spelling, measured
    /// on the v0.71.0 `frps`: `tls_enable = "yes"` there fails with
    /// `invalid type: string "yes", expected a boolean` (exit 1) while
    /// `tls_enable = true` is accepted (exit 0) and warns.
    ///
    /// **The `[common]` nested spelling is conditional on the flatten.** Because
    /// that flatten is `or_insert` on the whole `transport` value, a written
    /// top-level `transport` key — table or not — wins and `[common]`'s
    /// `transport` (nested `tls` table and all) is discarded before the lift can
    /// hoist anything. So a nested `tls_enable` under `[common.transport.tls]`
    /// counts **only** when no top-level `transport` key is written; otherwise
    /// the key never reaches the field and claiming it would violate the
    /// invariant the sibling [`Self::web_server_tls_enable_set_in`] keeps
    /// ("without this arm the detector claimed a key the loader had dropped").
    /// A flat `[common] tls_enable` is a different key and survives that
    /// competing table, so it still counts. The "not a table" half is vacuous in
    /// practice: a top-level `transport = 30` fails the load with
    /// `invalid type: integer 30, expected struct ServerTransportConfig` (exit 1,
    /// measured) before any warning can be emitted.
    ///
    /// `tlsEnable` never matches: `ServerConfig::tls_enable` carries no serde
    /// alias (unlike `bind_port`'s `bindPort`), and `"tlsEnable"` is not in
    /// `known_server_keys()`, so the lenient loader silently drops the key and
    /// the strict one refuses it. `[transport.tls] enable` never matches either:
    /// the **server** lift has no `"enable"` arm
    /// (`frp-core/src/config/normalize.rs:869-878`; only the **client** lift maps
    /// it, at `frp-core/src/config/normalize.rs:1429-1437`), so it stays a
    /// top-level key literally named `enable`. Neither is a documented spelling.
    pub(super) fn server_tls_enable_set_in(value: &toml::Value) -> bool {
        let Some(table) = value.as_table() else {
            return false;
        };
        // A written flat key, at whatever level the caller passes in.
        let flat = |t: &toml::Table| t.contains_key("tls_enable");
        // `[transport.tls]` keeps only its five *renamed* Go spellings; every
        // other key — including a literal `tls_enable` — reaches the top level
        // unchanged and lands on the same inert field.
        let nested = |t: &toml::Table| {
            t.get("transport")
                .and_then(toml::Value::as_table)
                .and_then(|transport| transport.get("tls"))
                .and_then(toml::Value::as_table)
                .is_some_and(|tls| tls.contains_key("tls_enable"))
        };
        // `[common]`'s nested spelling only survives the flatten when the
        // top-level `transport` key is absent, so consulting it unconditionally
        // would claim a dropped key (see the doc comment).
        let common_nested_survives = table.get("transport").is_none()
            && table
                .get("common")
                .and_then(toml::Value::as_table)
                .is_some_and(nested);
        flat(table)
            || nested(table)
            || table
                .get("common")
                .and_then(toml::Value::as_table)
                .is_some_and(flat)
            || common_nested_survives
    }

    /// Whether the loaded file wrote the flat `tls_enable` key — top-level,
    /// under `[common]`, or as a literal `tls_enable` inside `[transport.tls]` —
    /// the condition for [`Self::warn_inert_server_tls_enable`].
    pub fn server_tls_enable_set(&self) -> bool {
        self.server_tls_enable_set
    }

    /// Emit [`SERVER_TLS_ENABLE_INERT_WARNING`] when the key was written, once
    /// per load.
    ///
    /// Called by the three **server**-config load sites that have a log sink:
    /// `frps`'s two startup paths (`-c`, `--config-dir`) and `frp-server`'s
    /// `Service::reload`. `frps verify` stays silent (no subscriber), and no
    /// `frpc` / `frp-client` site calls it: those load `ClientConfig`, where
    /// `tls_enable` is live. See the const doc.
    ///
    /// **Warned whenever the key is written, `true` or `false`.** The field is
    /// inert in both cases, so a value gate would only hide the `false` case,
    /// which is the one a user is most likely to believe turned something off.
    /// The Go spellings `force`/`certFile`/`keyFile` are *synthesized*, not
    /// written, and stay silent; a literal `tls_enable` inside `[transport.tls]`
    /// **is** written and warns. [`Self::server_tls_enable_set_in`] reads the raw
    /// value precisely so the two cannot be confused. Pinned by
    /// `written_server_tls_enable_warns_once_and_stays_inert` and its siblings
    /// (`frp-core/tests/server_tls_enable_warning.rs`).
    pub fn warn_inert_server_tls_enable(&self) {
        if self.server_tls_enable_set {
            tracing::warn!("{}", SERVER_TLS_ENABLE_INERT_WARNING.as_str());
        }
    }

    /// Emit the build-shape diagnostic for each feature-gated server listener
    /// port the file named **and** this build cannot honour, once per load.
    ///
    /// A `#[cfg(feature = "kcp")]` / `quic` / `websocket` field is invisible to
    /// this build's serde: `websocket_port = 7500` in a `--no-default-features`
    /// build parses without error and binds nothing, so before this diagnostic
    /// the only trace of the key was the port that never opened. Each flag is
    /// computed where the field would have been deserialized (see
    /// [`ConfigPresence::from_normalized_value`]), so the key is recognised in
    /// every spelling the file may use — snake_case, the Go-inspired camelCase
    /// alias, `[common]` (flattened before the read), `.ini`, `includes`.
    ///
    /// **Only a non-zero value warns.** `0` is the documented "disabled" value
    /// for all three ports (`docs/config.md`), a capable build's reader gates on
    /// `> 0` as well, and no build shape can tell `= 0` apart from an absent key
    /// in its effect — so a presence-driven record would report a key that is
    /// fully honoured. This is the one deliberate difference from
    /// [`Self::warn_inert_server_tls_enable`], which warns on presence: that
    /// field is inert **either way**, this one is inert only in this build shape
    /// and only for a value that asks for a listener.
    ///
    /// Called by the three **server**-config load sites that have a log sink —
    /// `frps`'s two startup paths (`-c`, `--config-dir`) and `frp-server`'s
    /// `Service::reload` — beside the `tls_enable` call. `frps verify` does not
    /// use this method, because it has no subscriber; it reads
    /// [`Self::unhonoured_server_feature_key_records`] and prints the same texts
    /// to stdout itself. No `frpc`/`frp-client` site calls it, because this is a
    /// `ServerConfig` fact only. Pinned in both build shapes by
    /// `feature_gated_server_ports_*` in `frp-core/src/config/tests.rs`.
    pub fn warn_unhonoured_server_feature_keys(&self) {
        for record in self.unhonoured_server_feature_key_records() {
            tracing::warn!("{record}");
        }
    }

    /// The `kcp`/`quic`/`websocket` unhonoured-port texts for **this** build, in
    /// emission order — the single source both delivery paths read:
    /// [`Self::warn_unhonoured_server_feature_keys`] logs them and `frps verify`
    /// prints them directly (that path installs no subscriber, so a
    /// `tracing::warn!` there would reach nobody).
    pub fn unhonoured_server_feature_key_records(&self) -> Vec<String> {
        // The pushes below are each `#[cfg]`-gated, so in a build that compiles
        // all three features `mut` is genuinely unused; the allow is scoped to
        // this binding rather than the whole function.
        #[allow(unused_mut)]
        let mut records: Vec<String> = Vec::new();
        #[cfg(not(feature = "kcp"))]
        if self.server_kcp_bind_port_unhonoured {
            records.push(SERVER_KCP_BIND_PORT_UNHONOURED_WARNING.clone());
        }
        #[cfg(not(feature = "quic"))]
        if self.server_quic_bind_port_unhonoured {
            records.push(SERVER_QUIC_BIND_PORT_UNHONOURED_WARNING.clone());
        }
        #[cfg(not(feature = "websocket"))]
        if self.server_websocket_port_unhonoured {
            records.push(SERVER_WEBSOCKET_PORT_UNHONOURED_WARNING.clone());
        }
        records
    }

    /// Emit the `[web_server.tls] enable` diagnostic when the key was written,
    /// once per load.
    ///
    /// `reader` is the **caller's** build answer, not this crate's: every caller
    /// is a crate that actually owns the gate (`frps`/`frp-server`:
    /// `frp_server::service::web_server_tls_enable_reader`, its `dashboard` +
    /// `tls`; `frpc`/`frp-client`:
    /// `frp_client::web_server_tls_enable_reader`, its `admin` + `tls`),
    /// so it passes [`WebServerTlsEnableReader::WebServerTls`] when the emitted
    /// message may describe an HTTPS server and one of the other two when it
    /// must name the missing piece instead. It is the **owning crate's** `cfg!`
    /// that decides, never the binary's: `frpc/tls` is off in every default
    /// build while `frp-client/tls` is on, so a binary-local
    /// `cfg!(feature = "tls")` would answer for a different crate. See
    /// [`WEB_SERVER_TLS_ENABLE_INERT_WARNING_NO_DASHBOARD`] for why the choice
    /// cannot live in this crate. Pinned by
    /// `the_no_dashboard_build_names_no_dashboard_behaviour` and
    /// `the_no_tls_build_names_no_tls_behaviour`
    /// (`frp-core/tests/web_server_tls_enable_warning.rs`).
    ///
    /// Called by each load site that has a log sink — `frps`'s two startup
    /// paths, `frpc`'s two startup paths, `frpc verify`, both in-process
    /// reloads, and the `frpc` admin API's config GET (which additionally
    /// deduplicates, because that endpoint is polled) — because the loader
    /// itself cannot emit it (see the type doc). One site does not call it:
    /// `frps verify` (no subscriber). See the type doc for the measurement.
    ///
    /// **Warned whenever the key is written, pair or no pair.** The key is inert
    /// in all four combinations, so "does the key do anything" is false in all
    /// four; gating on the pair would silence `enable = false` beside a valid
    /// pair, which is the shape where TLS stays **on** against the written value
    /// (the reason the "wire `enable` to the pair" alternative was rejected) and
    /// where this warning is the only signal. The cost of that choice is one
    /// inert-but-harmless record for `enable = false` with no pair; the message
    /// text is written to be true in every combination. Pinned by
    /// `nested_web_server_tls_enable_warns_once_and_stays_inert`
    /// (`frp-core/tests/web_server_tls_enable_warning.rs`).
    pub fn warn_inert_web_server_tls_enable(&self, reader: WebServerTlsEnableReader) {
        if self.web_server_tls_enable_set {
            tracing::warn!("{}", reader.warning());
        }
    }

    /// Record the reader-gated listener ports a **CLI overlay** applied, so the
    /// overlay's writes are reported by the same
    /// [`Self::warn_inert_web_server_port`] path as the config file's.
    ///
    /// The caller is `frps`, between the `cli.cli_overrides_enabled()` overlay
    /// and the `warn_inert_*` calls (see `frps/src/main.rs`), and the argument is
    /// what `FrpsArgs::override_server_config` reports it wrote — never a value
    /// derived from the overlay's absence. See [`AppliedReaderGatedPorts`] for
    /// why `web_server.port` is the only port this can carry.
    pub fn record_applied_reader_gated_ports(&mut self, applied: AppliedReaderGatedPorts) {
        self.web_server_port_unhonoured |= applied.web_server_port;
    }

    /// Emit the `web_server.port` record when the file named a **non-zero** port
    /// and the **caller's** build does not compile its reader, once per load.
    ///
    /// Unlike [`Self::warn_inert_server_tls_enable`], the presence flag is not
    /// enough: `web_server.port` is live in a build that compiles `frp-server`'s
    /// `dashboard` feature, so the record has to be **suppressed** there. `reader`
    /// is that build answer, taken from the owning crate
    /// (`frp_server::service::web_server_port_reader`), never from the binary's
    /// own `cfg!` — `frps`'s `dashboard` feature is off in every default build
    /// while the field it gates is unconditional, the same trap
    /// [`WebServerTlsEnableReader`] documents. Pinned in both build shapes by the
    /// reader tests in `frp-server/src/service.rs` and by the spawn tests in
    /// `frps/tests/warn_delivery.rs`.
    ///
    /// Called by the load sites that have a sink: `frps`'s two startup paths
    /// (`-c`, `--config-dir`), `frp-server`'s `Service::reload`, and — with a
    /// direct `println!` instead, because it installs no subscriber — `frps
    /// verify`. `frpc`/`frp-client` never call it: `web_server` on the client is
    /// the admin server, whose reader is the `admin` feature, and no client load
    /// site is wired to this record.
    pub fn warn_inert_web_server_port(&self, reader: ListenerPortReader) {
        self.warn_reader_gated_ports(reader, ListenerPortReader::Present);
    }

    /// The `ssh_tunnel_gateway.bind_port` twin of
    /// [`Self::warn_inert_web_server_port`], resolved by
    /// `frp_server::service::ssh_tunnel_gateway_bind_port_reader`.
    pub fn warn_inert_ssh_tunnel_gateway_bind_port(&self, reader: ListenerPortReader) {
        self.warn_reader_gated_ports(ListenerPortReader::Present, reader);
    }

    fn warn_reader_gated_ports(&self, web: ListenerPortReader, ssh: ListenerPortReader) {
        for record in self.unhonoured_reader_gated_port_records(web, ssh) {
            tracing::warn!("{record}");
        }
    }

    /// The reader-gated listener-port texts this build cannot honour, in
    /// emission order (`web_server.port` before `ssh_tunnel_gateway.bind_port`).
    ///
    /// This is the single source both delivery paths read:
    /// [`Self::warn_inert_web_server_port`] /
    /// [`Self::warn_inert_ssh_tunnel_gateway_bind_port`] log them, and `frps
    /// verify` — which installs no subscriber — prints them to stdout itself.
    /// `reader` is the **calling crate's** build answer in every case (see
    /// [`ListenerPortReader`]); a listener the build does honour produces no
    /// record, which is what keeps this warning off in the build shapes that
    /// bind the port.
    pub fn unhonoured_reader_gated_port_records(
        &self,
        web_server_reader: ListenerPortReader,
        ssh_reader: ListenerPortReader,
    ) -> Vec<&'static str> {
        let mut records: Vec<&'static str> = Vec::new();
        if self.web_server_port_unhonoured && web_server_reader == ListenerPortReader::Absent {
            records.push(WEB_SERVER_PORT_UNHONOURED_WARNING);
        }
        if self.ssh_tunnel_gateway_bind_port_unhonoured && ssh_reader == ListenerPortReader::Absent
        {
            records.push(SSH_TUNNEL_GATEWAY_BIND_PORT_UNHONOURED_WARNING);
        }
        records
    }
}

/// Validate proxy configs after deserialization. Catches invalid bandwidth
/// limits, CR/LF in response headers, and other semantic issues that serde
/// cannot express.
fn validate_proxy_configs(proxies: &[ProxyConfig]) -> Result<(), String> {
    const VALID_PROXY_TYPES: &[&str] = &[
        "tcp", "udp", "http", "https", "stcp", "xtcp", "sudp", "tcpmux",
    ];
    for p in proxies {
        // Validate proxy_type
        if !VALID_PROXY_TYPES.contains(&p.proxy_type.as_str()) {
            return Err(format!(
                "proxy '{}': invalid proxy_type '{}'. Valid types: tcp, udp, http, https, stcp, xtcp, sudp, tcpmux",
                p.name, p.proxy_type
            ));
        }

        // Go frp v0.70.1 compat: validation.ValidateProxyConfigurerForClient
        // (pkg/config/v1/validation/proxy.go), ported per-type checks
        // (audit task 9 finding 8).

        // c.Name == "" → "name should not be empty".
        if p.name.is_empty() {
            return Err("proxy: name should not be empty".into());
        }

        // proxyProtocolVersion must be "", "v1", or "v2".
        if !matches!(p.proxy_protocol_version.as_str(), "" | "v1" | "v2") {
            return Err(format!(
                "proxy '{}': not support proxy protocol version: {}",
                p.name, p.proxy_protocol_version
            ));
        }

        // healthCheck.type must be "", "tcp", or "http"; "http" requires a path.
        if !matches!(p.health_check_type.as_str(), "" | "tcp" | "http") {
            return Err(format!(
                "proxy '{}': not support health check type: {}",
                p.name, p.health_check_type
            ));
        }
        if p.health_check_type == "http" && p.health_check_url.is_empty() {
            return Err(format!(
                "proxy '{}': health check path should not be empty",
                p.name
            ));
        }

        // HTTP/HTTPS/TCPMux proxies need subdomain or custom domains
        // (validateDomainConfigForClient: "subdomain and custom domains
        // should not be both empty").
        if matches!(p.proxy_type.as_str(), "http" | "https" | "tcpmux")
            && p.subdomain.is_empty()
            && p.custom_domains.is_empty()
        {
            return Err(format!(
                "proxy '{}': subdomain and custom domains should not be both empty",
                p.name
            ));
        }

        // '.' and '*' are not supported in subdomain (validateDomainConfigForServer).
        if (p.subdomain.contains('.') || p.subdomain.contains('*'))
            && matches!(p.proxy_type.as_str(), "http" | "https" | "tcpmux")
        {
            return Err(format!(
                "proxy '{}': '.' and '*' are not supported in subdomain",
                p.name
            ));
        }

        // Validate response headers: no CR or LF in names or values
        for (name, value) in &p.response_headers {
            if name.contains('\r') || name.contains('\n') {
                return Err(format!(
                    "proxy '{}': response header name contains CR/LF: {name:?}",
                    p.name
                ));
            }
            if value.contains('\r') || value.contains('\n') {
                return Err(format!(
                    "proxy '{}': response header value for {name:?} contains CR/LF",
                    p.name
                ));
            }
        }

        // Validate health check HTTP headers too (same CR/LF risk)
        for h in &p.health_check_http_headers {
            let name = &h.name;
            let value = &h.value;
            if name.contains('\r') || name.contains('\n') {
                return Err(format!(
                    "proxy '{}': health check header name contains CR/LF: {name:?}",
                    p.name
                ));
            }
            if value.contains('\r') || value.contains('\n') {
                return Err(format!(
                    "proxy '{}': health check header value for {name:?} contains CR/LF",
                    p.name
                ));
            }
        }

        // Validate proxy headers field (injected into forwarded requests)
        for (name, value) in &p.headers {
            if name.contains('\r') || name.contains('\n') {
                return Err(format!(
                    "proxy '{}': header name in 'headers' contains CR/LF: {name:?}",
                    p.name
                ));
            }
            if value.contains('\r') || value.contains('\n') {
                return Err(format!(
                    "proxy '{}': header value in 'headers' for {name:?} contains CR/LF",
                    p.name
                ));
            }
        }

        // Validate host_header_rewrite (injected into Host header)
        if p.host_header_rewrite.contains('\r') || p.host_header_rewrite.contains('\n') {
            return Err(format!(
                "proxy '{}': host_header_rewrite contains CR/LF",
                p.name
            ));
        }

        // Validate bandwidth_limit: non-empty strings must parse
        if !p.bandwidth_limit.is_empty() && parse_bandwidth_limit(&p.bandwidth_limit).is_none() {
            let hint = if p.bandwidth_limit == "0" || p.bandwidth_limit == "0KB" {
                "value must be positive; use empty string for no limit"
            } else {
                "must be a positive number followed by KB, MB, or GB"
            };
            return Err(format!(
                "proxy '{}': invalid bandwidth_limit: {:?} ({})",
                p.name, p.bandwidth_limit, hint
            ));
        }

        // Validate bandwidth_limit_mode: must be "client" or "server" (Go frp compat).
        if !p.bandwidth_limit_mode.is_empty()
            && p.bandwidth_limit_mode != "client"
            && p.bandwidth_limit_mode != "server"
        {
            return Err(format!(
                "proxy '{}': invalid bandwidth_limit_mode: {:?}, must be \"client\" or \"server\"",
                p.name, p.bandwidth_limit_mode
            ));
        }
    }
    Ok(())
}

/// Validate token/tokenSource mutual exclusivity and source structure.
/// Go frp v0.70.1 compat: validation/auth.go validateAuthTokenSource.
pub fn validate_auth_token_source(
    token: &str,
    token_source: &Option<ValueSource>,
) -> Result<(), String> {
    if !token.is_empty() && token_source.is_some() {
        return Err("cannot specify both auth.token and auth.tokenSource".into());
    }
    if let Some(source) = token_source {
        source
            .validate()
            .map_err(|e| format!("invalid auth.tokenSource: {e}"))?;
    }
    Ok(())
}

/// Go frp v0.70.1 compat: `validation.ValidateOIDCClientCredentialsConfig`
/// (`/tmp/frp-src-0.70.1/pkg/config/v1/validation/oidc.go`) plus the
/// `tokenSource` mutual-exclusivity check from `validateOIDCConfig`
/// (`client.go:84-94`).
fn validate_oidc_client_config(auth: &AuthClientConfig) -> Result<(), String> {
    // auth.oidc.tokenSource is mutually exclusive with every other field
    // of auth.oidc (Go client.go:89-94).
    if let Some(source) = &auth.oidc_token_source {
        if !auth.oidc_client_id.is_empty()
            || !auth.oidc_client_secret.is_empty()
            || !auth.oidc_audience.is_empty()
            || !auth.oidc_scope.is_empty()
            || !auth.oidc_token_endpoint.is_empty()
            || !auth.additional_endpoint_params.is_empty()
            || !auth.oidc_tls_trusted_ca_file.is_empty()
            || auth.oidc_tls_insecure_skip_verify
            || !auth.oidc_proxy_url.is_empty()
        {
            return Err(
                "cannot specify both auth.oidc.tokenSource and any other field of auth.oidc".into(),
            );
        }
        return source
            .validate()
            .map_err(|e| format!("invalid auth.oidc.tokenSource: {e}"));
    }

    // Client-credentials validation only applies to the OIDC method. The
    // comparison is exact, and that is now the *validated* form of the field:
    // `validate_client_config` has already run the one
    // `crate::auth::complete_auth_method` + `parse_auth_method` policy over
    // it, so `method` here is exactly `"token"` or `"oidc"` (or the field is
    // absent). Before that, `method = "OIDC"` skipped this whole block and the
    // config loaded with no `clientID`.
    if auth.method != "oidc" {
        return Ok(());
    }

    if auth.oidc_client_id.is_empty() {
        return Err("auth.oidc.clientID is required".into());
    }
    if auth.oidc_token_endpoint.is_empty() && auth.oidc_issuer.is_empty() {
        return Err(
            "auth.oidc.tokenEndpointURL is required (or auth.oidc.issuer for discovery)".into(),
        );
    }
    if !auth.oidc_token_endpoint.is_empty() {
        let ep = &auth.oidc_token_endpoint;
        let rest = if let Some(r) = ep.strip_prefix("https://") {
            r
        } else if let Some(r) = ep.strip_prefix("http://") {
            r
        } else {
            return Err("auth.oidc.tokenEndpointURL must use http or https".into());
        };
        let host = rest.split('/').next().unwrap_or("");
        if host.is_empty() {
            return Err("auth.oidc.tokenEndpointURL must be an absolute http or https URL".into());
        }
    }
    if auth.additional_endpoint_params.contains_key("scope") {
        return Err(
            "auth.oidc.additionalEndpointParams.scope is not allowed; use auth.oidc.scope instead"
                .into(),
        );
    }
    if !auth.oidc_audience.is_empty() && auth.additional_endpoint_params.contains_key("audience") {
        return Err(
            "cannot specify both auth.oidc.audience and auth.oidc.additionalEndpointParams.audience"
                .into(),
        );
    }
    Ok(())
}

pub(super) fn validate_server_config(cfg: &mut ServerConfig) -> Result<(), String> {
    // `auth.method` first, in Go's order: `ServerConfig.Complete()` runs
    // `Auth.Complete()` — the empty→token fill, `pkg/config/v1/server.go:136-139`
    // — and only then does `ValidateServerConfig` (`validation/server.go:31`)
    // check the value. The load path must fill before it checks, or
    // `method = ""` (Go's "use the default", and the state of every config with
    // no `[auth] method` key at all, since serde's string default is `""`) would
    // be rejected as an unrecognised method.
    cfg.auth.complete()?;
    crate::auth::parse_auth_method(&cfg.auth.method)?;
    validate_auth_token_source(&cfg.auth.token, &cfg.auth.token_source)?;
    // Go frp v0.71.0: unknown feature gates are config errors, not a silent
    // fail-open (featuregate SetFromMap "unrecognized feature gate").
    if !cfg.feature.gates.is_empty() {
        crate::feature_gate::validate_keys(&cfg.feature.gates)
            .map_err(|e| format!("server config: {e}"))?;
    }
    // Go frp v0.71.0: a negative transport.maxPoolCount is invalid.
    if cfg.transport.max_pool_count < 0 {
        return Err(format!(
            "server config: invalid transport.maxPoolCount {}, must be non-negative",
            cfg.transport.max_pool_count
        ));
    }
    // An http_plugins entry with neither addr nor path would produce a
    // malformed "http://?version=..." request at runtime — fail at load time.
    for plugin in &cfg.http_plugins {
        // A path alone would produce the malformed "http:///x" — Go's
        // HTTPPluginOptions.Addr is required. Also reject degenerate addrs
        // like "http://" or "/" that strip to nothing after the scheme.
        let bare = plugin
            .addr
            .trim_start_matches("http://")
            .trim_start_matches("https://")
            .trim_matches('/');
        if plugin.addr.is_empty() || bare.is_empty() {
            return Err(format!(
                "server config: http_plugins entry '{}' has no addr",
                plugin.name
            ));
        }
    }
    // Go frp compat: invalid allow_ports entries are config errors, not a
    // silent disable of the restriction (validation/PortsRange).
    if !cfg.allow_ports.trim().is_empty() {
        parse_allow_ports(&cfg.allow_ports).map_err(|e| format!("server config: {e}"))?;
    }
    // ServerConfig has no inline proxy definitions — proxies are registered
    // by clients at runtime. No proxy-level validation to do here.
    Ok(())
}

pub(super) fn validate_client_config(cfg: &mut ClientConfig) -> Result<(), String> {
    validate_proxy_configs(&cfg.proxies)?;
    validate_no_duplicate_names(&cfg.proxies, &cfg.visitors)?;
    // Go frp v0.71.0 validation/visitor.go:42-63 (round 10 MEDIUM): visitors
    // were never validated — an empty name/serverName or bindPort==0 loaded
    // silently and the visitor never connected. Mirror Go's checks exactly:
    // bindPort -1 (no-bind) and positive ports pass; only 0 is rejected.
    for v in &cfg.visitors {
        if v.name.is_empty() {
            return Err("visitor config: name is required".to_string());
        }
        // Go's wording is `visitor %s: %v` — the name is interpolated **without**
        // quotes (`pkg/config/v1/validation/client.go:216` wraps with
        // `fmt.Errorf("visitor %s: %v", c.GetBaseConfig().Name, err)`, message
        // text in `pkg/config/v1/validation/visitor.go`). Measured on Go v0.71.0
        // for a missing `serverName` / `bindPort` in TOML and for the legacy
        // `.ini` spellings: `visitor v: server name is required` /
        // `visitor v: bind port is required`. These two messages previously
        // quoted the name (`visitor 'v': …`), which made a legacy `.ini` refusal
        // that reaches this validator — the reserved-root visitor of
        // `collect_legacy_ini_proxy_sections` — differ from Go's text for no
        // reason. The empty-name arm above keeps its own wording, and the
        // unknown-type arm below keeps the v1 wording the strict-mode pins
        // assert; both are disclosed divergences, not parity.
        if v.server_name.is_empty() {
            return Err(format!("visitor {}: server name is required", v.name));
        }
        if v.bind_port == 0 {
            return Err(format!("visitor {}: bind port is required", v.name));
        }
        // Round-8 blocker: Go v0.71.0 dispatches visitors by a type switch
        // over stcp/sudp/xtcp (validation/visitor.go ValidateVisitorConfigurer)
        // — any other type, including empty, fails with "unknown visitor
        // config type". A `type = "typo"` visitor used to load silently and
        // never connect. Mirrors frp-client/src/store.rs VALID_VISITOR_TYPES.
        if !matches!(v.visitor_type.as_str(), "stcp" | "sudp" | "xtcp") {
            return Err(format!(
                "visitor '{}': unknown visitor type '{}'",
                v.name, v.visitor_type
            ));
        }
        if v.visitor_type == "xtcp" && v.protocol != "kcp" && v.protocol != "quic" {
            return Err(format!(
                "visitor '{}': protocol should be kcp or quic",
                v.name
            ));
        }
    }
    // Negative poolCount: Go frp v0.71.0 has NO client-side check —
    // Go frpc loads the config fine and the SERVER rejects the negative at
    // login (server/control.go:438 "invalid pool count %d, must be
    // non-negative"), which frp-rs already mirrors (control/login.rs
    // "Login rejected: negative pool_count"). This is a deliberate
    // fail-fast divergence: frp-rs frpc refuses the misconfig at load
    // instead of dialing first. 0 keeps its "use the default" semantics
    // (complete_with_heartbeat_set maps 0 → 1, Go util.EmptyOr — pinned by
    // test_explicit_zero_client_pool_count_and_keepalive_use_go_defaults).
    if cfg.pool_count < 0 {
        return Err(format!(
            "client config: invalid poolCount {}, must be non-negative",
            cfg.pool_count
        ));
    }
    // Go frp v0.71.0: unknown feature gates are config errors (featuregate
    // SetFromMap "unrecognized feature gate").
    if !cfg.feature.gates.is_empty() {
        crate::feature_gate::validate_keys(&cfg.feature.gates)
            .map_err(|e| format!("client config: {e}"))?;
    }
    // Split borrows on purpose (`&cfg.token`, `&mut cfg.auth`): the
    // deprecated flat `token` key is read, never copied — the auth token is a
    // secret and this file does not clone it into a local.
    let flat_token = &cfg.token;
    if let Some(auth) = cfg.auth.as_mut() {
        // Go's `ClientCommonConfig.Complete()` runs `Auth.Complete()` — the
        // empty→token fill — at `pkg/config/v1/client.go:91`
        // (`AuthClientConfig.Complete`, `:206-209`) and *then* validation
        // checks the method (`validation/client.go:101`, reached from
        // `ValidateAllClientConfig`). So the fill has to precede the check, and
        // filling `cfg.auth` itself (not a local copy) is what makes
        // `method = ""` both start as token and hand the completed value on to
        // the service. This is the site the old `auth.method != "oidc"`
        // early-return lived at: it skipped client-credentials validation for
        // every non-exact spelling, so `method = "OIDC"` with an empty
        // `clientID` loaded silently. It is now rejected with the same text the
        // other three sites use.
        auth.complete()?;
        crate::auth::parse_auth_method(&auth.method)?;
        // `cfg.token` is the deprecated flat spelling; the nested
        // `[auth] token` wins only when the flat one is empty.
        let token: &str = if flat_token.is_empty() {
            auth.token.as_str()
        } else {
            flat_token.as_str()
        };
        validate_auth_token_source(token, &auth.token_source)?;
        validate_oidc_client_config(auth)?;
    }
    if (!cfg.virtual_net.address.is_empty()
        || cfg.visitors.iter().any(is_virtual_net_visitor)
        || cfg.proxies.iter().any(is_virtual_net_proxy_plugin))
        && !cfg.feature.gates.get(VIRTUAL_NET).copied().unwrap_or(false)
    {
        return Err(format!(
            "VirtualNet feature is not enabled; enable it by setting [featureGates] {VIRTUAL_NET} = true"
        ));
    }
    for p in cfg
        .proxies
        .iter()
        .filter(|p| is_virtual_net_proxy_plugin(p))
    {
        if p.proxy_type != "tcp" {
            return Err(format!(
                "proxy '{}': virtual_net plugin requires proxy type tcp",
                p.name
            ));
        }
        if cfg.virtual_net.address.is_empty() {
            return Err(format!(
                "proxy '{}': virtual_net plugin requires [virtualNet] address",
                p.name
            ));
        }
        if cfg
            .virtual_net
            .address
            .parse::<std::net::Ipv4Addr>()
            .is_err()
        {
            return Err(format!(
                "proxy '{}': invalid [virtualNet] address [{}]",
                p.name, cfg.virtual_net.address
            ));
        }
    }
    for v in cfg.visitors.iter().filter(|v| is_virtual_net_visitor(v)) {
        let Some(plugin) = &v.plugin else {
            continue;
        };
        if plugin.destination_ip.is_empty() {
            return Err(format!(
                "visitor '{}': virtual_net plugin requires destinationIP",
                v.name
            ));
        }
        if plugin.destination_ip.parse::<std::net::IpAddr>().is_err() {
            return Err(format!(
                "visitor '{}': invalid destination IP address [{}]",
                v.name, plugin.destination_ip
            ));
        }
    }
    Ok(())
}

fn is_virtual_net_visitor(v: &VisitorConfig) -> bool {
    v.plugin
        .as_ref()
        .is_some_and(|p| p.plugin_type == "virtual_net")
}

fn is_virtual_net_proxy_plugin(p: &ProxyConfig) -> bool {
    p.plugin
        .as_ref()
        .is_some_and(|pl| pl.plugin_type == "virtual_net")
}

/// Reject duplicate proxy or visitor names. Go frp v0.70.0 compat:
/// proxies and visitors are keyed by name, and duplicates would otherwise
/// be silently overwritten with no error (Go) or logged as a warning (Rust).
///
/// Cross-type duplicates (same name used for a proxy AND a visitor) are
/// allowed because they live in separate namespaces (Go frp behavior).
pub(super) fn validate_no_duplicate_names(
    proxies: &[ProxyConfig],
    visitors: &[VisitorConfig],
) -> Result<(), String> {
    let mut seen = std::collections::HashSet::with_capacity(proxies.len());
    for p in proxies {
        if !seen.insert(&p.name) {
            return Err(format!("proxy name [{}] is duplicated", p.name));
        }
    }

    seen.clear();
    for v in visitors {
        if !seen.insert(&v.name) {
            return Err(format!("visitor name [{}] is duplicated", v.name));
        }
    }

    Ok(())
}
