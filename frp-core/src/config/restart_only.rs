//! The server's `ServerConfig`-shaped **restart-only** field list.
//!
//! `frps`'s `SIGUSR1` reload (`frp_server::service::Service::reload`) can
//! re-key exactly a handful of settings in place. Everything else in
//! [`ServerConfig`] is read once, at startup, and can only change on a restart —
//! so a reload that changes only those fields must **name** them rather than
//! answer `config reloaded: no changes detected`.
//!
//! [`ServerConfig::restart_only_changes`] is that list. It is the counterpart of
//! `note_auth_restart_changes` (`frp-server/src/service.rs`), which owns the
//! `[auth]` section.
//!
//! # Why this lives in `frp-core` and not next to the reload
//!
//! The list is enforced by *destructuring* both configs with **no `..`**: a
//! field added to [`ServerConfig`] (or to one of its sub-structs) makes this
//! module fail to compile — E0027, "pattern does not mention the field" — until
//! the new field is named and classified. A list of named reads
//! (`old.x != new.x`) has no such property.
//!
//! That pattern can only live where the struct's `#[cfg]` attributes are
//! evaluated. Three `ServerConfig` fields — `kcp_bind_port`, `quic_bind_port`
//! and `websocket_port` — are `#[cfg(feature = …)]`-gated on **frp-core's**
//! features, while a pattern written in `frp-server` could only be gated on
//! *frp-server's* own features. Cargo unifies those independently, and both
//! directions occur in the workspace's own lanes:
//!
//! * `cargo test -p frp-server --no-default-features --all-targets`
//!   (`.github/workflows/ci.yml`): the dev-dependency `frp-client` enables
//!   `frp-core/kcp`, so the field **exists**, while `frp-server/kcp` is off, so
//!   a `#[cfg(feature = "kcp")]` pattern entry is stripped → **E0027**.
//! * `cargo check --workspace --no-default-features --features tiny`
//!   (`.github/workflows/ci.yml`): `frp-core/kcp` is off, the field **does not
//!   exist**, so an unconditional pattern entry → **E0026** ("struct does not
//!   have a field named …"; measured on this tree — an earlier version of these
//!   notes said E0028, which is the wrong code).
//!
//! Both were measured against a draft of this list written in `frp-server`;
//! this module is the same list where the gates match the struct exactly. The
//! *reader* gates stay in `frp-server`, which is the crate that owns those
//! readers: see [`ServerReader`] — and note that the same unification means the
//! three ports' reader gates are `frp-server`'s features, not `frp-core`'s.

use std::fmt::Display;

use super::{
    FeatureConfig, LogConfig, ObservabilityConfig, ServerConfig, ServerTransportConfig,
    SshTunnelGatewayConfig, WebServerConfig, WebServerTlsConfig,
};

/// The cfg feature a restart-only field's **only reader** is gated on.
///
/// The classification is part of the field's shape: a field whose sole reader is
/// compiled out has no effect at all in that build, so a restart cannot make a
/// change to it take effect and reporting one "restart required" would be false.
/// `frp-server` resolves each variant against its own features (it owns the
/// readers); this crate only says which one to ask about.
///
/// The gates are **`frp-server`'s**, not `frp-core`'s, and Cargo unifies the two
/// independently — see the module docs for the lane that made that concrete.
/// `Kcp`, `Quic` and `Websocket` are the three listener fields whose *presence*
/// is `frp-core`-gated but whose reader is `frp-server`-gated: in a build where
/// `frp-core/kcp` is on through another crate while `frp-server/kcp` is off, the
/// field exists and this crate reports it, and only `frp-server`'s resolution of
/// the gate can suppress the line. They must not be `Any`.
///
/// **The dashboard is not a second reader for any of them**, which an earlier
/// version of this list got wrong by classing `kcp_bind_port` / `quic_bind_port`
/// as a `…OrDashboard` disjunction. `frp-server/src/dashboard.rs` is an
/// `frp-server` file, so its own `#[cfg(feature = "kcp")]` / `#[cfg(feature =
/// "quic")]` (`:501-502`, `:2491-2494`) are *this* crate's features: it prints
/// `kcpBindPort` / `quicBindPort` only in a build that already has the listener
/// compiled. A dashboard-only build's `/api/v2/system/info` contains neither key
/// (measured; the same build with `kcp,quic` added contains both — the configs
/// differ only in the `cfg`, not in serde), so the dashboard can only ever have
/// *added* a false "restart required", never a reader.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerReader {
    /// A reader exists in every build of `frp-server`.
    Any,
    /// The dashboard block of `frp_server::service::Service::run`
    /// (`#[cfg(feature = "dashboard")]`).
    Dashboard,
    /// The SSH tunnel gateway (`Service::run`, `#[cfg(feature = "ssh")]`, via
    /// `SshListener::new`).
    Ssh,
    /// The KCP listener (`Service::run`, `#[cfg(feature = "kcp")]`).
    Kcp,
    /// The QUIC listener (`Service::run`, `#[cfg(feature = "quic")]`).
    Quic,
    /// The WebSocket listener (`Service::run`, `#[cfg(feature = "websocket")]`).
    Websocket,
    /// `frps`'s `init_logging` (`#[cfg(feature = "otel")]` on the binary, which
    /// forwards `frp-core/otel`).
    Otel,
}

/// One restart-only field whose value differs between the running and the loaded
/// config.
///
/// The rendering is done here, the line is not: `frp-server` owns the summary's
/// wording (`name: old -> new (restart required)` / `name changed (restart
/// required)`), this crate owns the field list and the values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestartOnlyChange {
    /// Dotted path using the struct's own field names, e.g.
    /// `transport.heartbeat_timeout`.
    pub name: &'static str,
    /// The running value, rendered.
    pub old: String,
    /// The value just loaded from the file, rendered.
    pub new: String,
    /// Print the name only, never the values: the field is credential-shaped
    /// (`web_server.password`) or may embed a credential
    /// (`http_plugins`'s `addr` can be `http://user:pass@host`), and the summary
    /// is logged and echoed back through the reload path. Set for
    /// `http_plugins` too because [`HttpPluginConfig`] has neither `PartialEq`
    /// nor `Display` — it is compared through its `Debug` rendering, which is
    /// too long for a `; `-joined summary.
    ///
    /// [`HttpPluginConfig`]: super::HttpPluginConfig
    pub name_only: bool,
    /// Which build feature has to be on for this field's only reader to exist.
    pub reader: ServerReader,
}

/// Render an `Option<u32>`-shaped server limit: `None` prints as `<unset>`.
///
/// **Why a renderable form.** `Option<T>` implements `Debug`, not `Display`, so
/// the `PartialEq + Display` bound below cannot take one directly. This
/// rendering is injective — `<unset>` is not a number and `u32::to_string` is
/// exact — so it can neither miss a `None`/`Some` or `Some(a)`/`Some(b)`
/// difference nor invent one.
///
/// It is a **rendering**, not the comparison: the two limits below are compared
/// as the values the server actually runs with (an absent key and its default
/// are the same setting, so they must not be reported as a change). `<unset>` is
/// therefore only ever printed next to a value that *differs in effect* from it.
fn show_opt_u32(v: &Option<u32>) -> String {
    match v {
        None => "<unset>".to_string(),
        Some(n) => n.to_string(),
    }
}

/// The connection-semaphore size `max_connections` resolves to — the same
/// function `frp-server`'s `resolve_max_connections` is, and the reason that one
/// now delegates here rather than repeating the constant.
///
/// `Some(0)` means unlimited and MUST resolve to 0 (not `usize::MAX`):
/// `AppState::new` builds `Semaphore::new(n)` whenever n > 0, and tokio panics on
/// `usize::MAX` (batch_semaphore asserts permits <= MAX_PERMITS); with
/// panic=abort in release, `usize::MAX` would crash frps at boot on the
/// documented "0 = unlimited" setting (audit H1). `None` is the 512 default.
///
/// Used by [`ServerConfig::restart_only_changes`] so that an absent
/// `max_connections` and an explicit `max_connections = 512` compare equal: they
/// are one setting, and reporting the pair as a change would be a false "restart
/// required" (measured on the first round of this fix).
pub fn effective_max_connections(max_connections: Option<u32>) -> usize {
    match max_connections {
        Some(0) => 0, // 0 = unlimited → no semaphore
        Some(n) => n as usize,
        None => 512, // default
    }
}

/// The accept-rate the server runs with: `None` is 0 = no limit, which is what
/// `Service::run` computes with `unwrap_or(0)`.
///
/// Same purpose as [`effective_max_connections`]: an absent `max_accept_rate` and
/// an explicit `max_accept_rate = 0` are one setting and must not be reported as
/// a change.
pub fn effective_max_accept_rate(max_accept_rate: Option<u32>) -> u32 {
    max_accept_rate.unwrap_or(0)
}

/// Push a change entry when `old != new`.
fn push<T: PartialEq + Display>(
    out: &mut Vec<RestartOnlyChange>,
    old: &T,
    new: &T,
    name: &'static str,
    reader: ServerReader,
) {
    if *old != *new {
        out.push(RestartOnlyChange {
            name,
            old: old.to_string(),
            new: new.to_string(),
            name_only: false,
            reader,
        });
    }
}

/// Push a name-only entry when the `Debug` renderings differ.
///
/// **What this can and cannot detect.** For a plain-data value (numbers,
/// strings, `Vec<String>`, nested plain-data structs) the derived `Debug` output
/// is injective, so this detects every difference and invents none — the
/// guarantee `PartialEq` would give. It is **not** valid for a `HashMap`-shaped
/// value: `HashMap`'s iteration order is seeded per instance, so two equal maps
/// can render differently. Nothing routed through this helper is a `HashMap`;
/// the one `HashMap` in the server config (`feature.gates`) is not compared at
/// all (see its entry in [`ServerConfig::restart_only_changes`]).
fn push_redacted<T: std::fmt::Debug>(
    out: &mut Vec<RestartOnlyChange>,
    old: &T,
    new: &T,
    name: &'static str,
    reader: ServerReader,
) {
    if format!("{old:?}") != format!("{new:?}") {
        out.push(RestartOnlyChange {
            name,
            old: String::new(),
            new: String::new(),
            name_only: true,
            reader,
        });
    }
}

/// Every restart-only `[log]` difference.
///
/// **What this models.** `frps` reads all five fields exactly once, in
/// `init_logging` (`frps/src/main.rs`), through
/// `logging::resolve_log_level` / `resolve_log_file` / `resolve_log_max_days` /
/// `resolve_log_format` / `resolve_ansi`: the subscriber, the file appender and
/// the retention policy are all built there, before the reload path exists. So a
/// restart is the only way any of them can take effect, and the reload must name
/// them.
///
/// **What keeps it complete.** Both patterns name all five fields with no `..`.
///
/// **What it does not cover.** A CLI flag that overrides the file
/// (`--log-level`, `--log-file`, `--log-max-days`, `--disable-log-color`) is not
/// part of this comparison: the running value came from the CLI, so a config
/// change under a flag is masked in both directions.
fn log_restart_changes(out: &mut Vec<RestartOnlyChange>, old: &LogConfig, new: &LogConfig) {
    let LogConfig {
        level: old_level,
        file: old_file,
        max_days: old_max_days,
        format: old_format,
        disable_print_color: old_disable_print_color,
    } = old;
    let LogConfig {
        level: new_level,
        file: new_file,
        max_days: new_max_days,
        format: new_format,
        disable_print_color: new_disable_print_color,
    } = new;

    push(out, old_level, new_level, "log.level", ServerReader::Any);
    push(out, old_file, new_file, "log.file", ServerReader::Any);
    push(
        out,
        old_max_days,
        new_max_days,
        "log.max_days",
        ServerReader::Any,
    );
    push(out, old_format, new_format, "log.format", ServerReader::Any);
    push(
        out,
        old_disable_print_color,
        new_disable_print_color,
        "log.disable_print_color",
        ServerReader::Any,
    );
}

/// Every restart-only `[web_server]` difference.
///
/// **What this models.** `web_server.custom_404_page` is read unconditionally at
/// startup (`Service::with_unsafe_features`, whose body the VHost and TCPMux 404
/// paths serve from). The rest are read only by the dashboard block of
/// `Service::run` — `addr`, `port`, `user`, `password`, `enable_prometheus`,
/// `assets_dir` and the TLS cert/key pair (flat `tls_cert_file`/`tls_key_file`,
/// which is where both spellings of the nested `tls.cert_file`/`tls.key_file`
/// land, via `WebServerConfig::tls_cert`/`tls_key`) — so they carry
/// [`ServerReader::Dashboard`] and `frp-server` omits them in a build without
/// that feature.
///
/// **What keeps it complete.** Both patterns name all thirteen fields with no
/// `..`, and the nested `tls` section is destructured the same way.
///
/// **What it does not cover.** `pprof_enable`, the flat `tls_ca_file` /
/// `tls_server_name` and every field of the nested `tls` section are not
/// reported: the first three are read by nothing in `frp-server` (measured:
/// `grep -rn 'pprof_enable' frp-server/src` finds no reader, and neither
/// `WebServerConfig::tls_ca_file` nor `WebServerConfig::tls_server_name` is read
/// outside the config struct), so a restart cannot make them take effect — the
/// same disposition `[auth].useEncryption` has in `note_auth_restart_changes`.
/// The nested section's *fields* are likewise unreachable (see the destructure
/// below: `normalize_web_server_section` removes the table's mapped keys — and
/// `enable` — before serde, so `WebServerTlsConfig` is default-`false`/empty in
/// every loaded config; only a genuinely unmapped key survives in `tls`, and
/// none of them matches a field), but
/// its **values** are not lost — both spelling families are hoisted onto the
/// flat `tls_cert_file` / `tls_key_file` / `tls_ca_file` / `tls_server_name`
/// entries, and the first two of those **are** reported. `password` is compared
/// but never printed.
fn web_server_restart_changes(
    out: &mut Vec<RestartOnlyChange>,
    old: &WebServerConfig,
    new: &WebServerConfig,
) {
    let WebServerConfig {
        addr: old_addr,
        port: old_port,
        user: old_user,
        password: old_password,
        enable_prometheus: old_enable_prometheus,
        assets_dir: old_assets_dir,
        // No reader anywhere in `frp-server` (the `pprof` exporter is gone).
        pprof_enable: _old_pprof_enable,
        tls_cert_file: old_tls_cert_file,
        tls_key_file: old_tls_key_file,
        tls: old_tls,
        // No reader anywhere in `frp-server`.
        tls_ca_file: _old_tls_ca_file,
        tls_server_name: _old_tls_server_name,
        custom_404_page: old_custom_404_page,
    } = old;
    let WebServerConfig {
        addr: new_addr,
        port: new_port,
        user: new_user,
        password: new_password,
        enable_prometheus: new_enable_prometheus,
        assets_dir: new_assets_dir,
        pprof_enable: _new_pprof_enable,
        tls_cert_file: new_tls_cert_file,
        tls_key_file: new_tls_key_file,
        tls: new_tls,
        tls_ca_file: _new_tls_ca_file,
        tls_server_name: _new_tls_server_name,
        custom_404_page: new_custom_404_page,
    } = new;
    // **Every** field of the nested section is unreachable through the loader:
    // `normalize_web_server_section` removes the `web_server.tls` table's mapped
    // keys (and `enable`) before serde sees it, so `WebServerTlsConfig` is always
    // `Default` in a loaded config — only unmapped keys survive in the table, and
    // serde ignores those. Its *values* are not lost — the hoist maps both spelling families
    // onto the flat `tls_cert_file` / `tls_key_file` entries, which **are**
    // pushed below, and drops `tls.enable` (inert; see the function's doc
    // comment). Measured 2026-09-29 by loading each shape as a real file
    // through `load_server_config(path, strict)` in both modes (probe kept at
    // `/tmp/wstls-probe/src/main.rs`; the table is in
    // `/tmp/wstls-report.md`):
    //   * `[web_server.tls] cert_file = "/snake/cert.pem"` and
    //     `certFile = "/camel/cert.pem"` both load with
    //     `web_server.tls_cert_file == "<that path>"`, `tls_cert()` equal to it,
    //     and the nested struct at its default — so either spelling reaches the
    //     reported flat entry;
    //   * `[web_server.tls] enable = true` loads with the nested struct still
    //     at its default and changes nothing;
    //   * the flat spellings load normally.
    // So no loaded `ServerConfig` can carry a non-default `WebServerTlsConfig`,
    // and the four flat entries above cover every spelling that can reach the
    // struct. They are named here — not omitted — so a new field in this section
    // is still a compile error.
    let WebServerTlsConfig {
        enable: _old_tls_enable,
        cert_file: _old_tls_cert_file_nested,
        key_file: _old_tls_key_file_nested,
        trusted_ca_file: _old_tls_trusted_ca_file,
        server_name: _old_tls_server_name_nested,
    } = old_tls;
    let WebServerTlsConfig {
        enable: _new_tls_enable,
        cert_file: _new_tls_cert_file_nested,
        key_file: _new_tls_key_file_nested,
        trusted_ca_file: _new_tls_trusted_ca_file,
        server_name: _new_tls_server_name_nested,
    } = new_tls;

    // Read in every build, by `Service::with_unsafe_features`.
    push(
        out,
        old_custom_404_page,
        new_custom_404_page,
        "web_server.custom_404_page",
        ServerReader::Any,
    );
    let reader = ServerReader::Dashboard;
    push(out, old_addr, new_addr, "web_server.addr", reader);
    push(out, old_port, new_port, "web_server.port", reader);
    push(out, old_user, new_user, "web_server.user", reader);
    // Never a value: this summary is logged (`reload()` → `info!` → `SIGUSR1:
    // {summary}`) and returned through the reload path.
    push_redacted(
        out,
        old_password,
        new_password,
        "web_server.password",
        reader,
    );
    push(
        out,
        old_enable_prometheus,
        new_enable_prometheus,
        "web_server.enable_prometheus",
        reader,
    );
    push(
        out,
        old_assets_dir,
        new_assets_dir,
        "web_server.assets_dir",
        reader,
    );
    push(
        out,
        old_tls_cert_file,
        new_tls_cert_file,
        "web_server.tls_cert_file",
        reader,
    );
    push(
        out,
        old_tls_key_file,
        new_tls_key_file,
        "web_server.tls_key_file",
        reader,
    );
}

/// Every restart-only `[transport]` difference.
///
/// **What this models.** All of these are read once: the mux / dead-timeout /
/// heartbeat / keepalive / buffer fields by `AppState::new` (from
/// `Service::with_unsafe_features`), `quic_options` by the QUIC listener in
/// `Service::run`, and `max_pool_count` from the startup
/// `ServerConfigSnapshot` at login. None is re-keyed by the reload.
///
/// **What keeps it complete.** Both patterns name all nine fields with no `..`
/// (the `#[cfg]` on `quic_options` is this crate's own gate, so it matches the
/// struct exactly).
///
/// **What it does not cover.** Two fields are compared as the **effective** value
/// the runtime resolves, not as the raw `Option`, because the raw shapes can
/// differ while the running value is identical: `tcp_mux` is `unwrap_or(true)`
/// at `Service::with_unsafe_features`, and `quic_options` is
/// `unwrap_or_default()` in `Service::run`. An absent `tcp_mux` rewritten as
/// `tcp_mux = true` therefore reports nothing — correct, since a restart would
/// change nothing.
fn transport_restart_changes(
    out: &mut Vec<RestartOnlyChange>,
    old: &ServerTransportConfig,
    new: &ServerTransportConfig,
) {
    let ServerTransportConfig {
        tcp_mux: old_tcp_mux,
        tcp_mux_keepalive_interval: old_tcp_mux_keepalive_interval,
        tcp_mux_keepalive_timeout: old_tcp_mux_keepalive_timeout,
        heartbeat_timeout: old_heartbeat_timeout,
        max_pool_count: old_max_pool_count,
        tcp_keepalive: old_tcp_keepalive,
        tcp_send_buffer_size: old_tcp_send_buffer_size,
        tcp_recv_buffer_size: old_tcp_recv_buffer_size,
        quic_options: old_quic_options,
    } = old;
    let ServerTransportConfig {
        tcp_mux: new_tcp_mux,
        tcp_mux_keepalive_interval: new_tcp_mux_keepalive_interval,
        tcp_mux_keepalive_timeout: new_tcp_mux_keepalive_timeout,
        heartbeat_timeout: new_heartbeat_timeout,
        max_pool_count: new_max_pool_count,
        tcp_keepalive: new_tcp_keepalive,
        tcp_send_buffer_size: new_tcp_send_buffer_size,
        tcp_recv_buffer_size: new_tcp_recv_buffer_size,
        quic_options: new_quic_options,
    } = new;

    let any = ServerReader::Any;
    push(
        out,
        &old_tcp_mux.unwrap_or(true),
        &new_tcp_mux.unwrap_or(true),
        "transport.tcp_mux",
        any,
    );
    push(
        out,
        old_tcp_mux_keepalive_interval,
        new_tcp_mux_keepalive_interval,
        "transport.tcp_mux_keepalive_interval",
        any,
    );
    push(
        out,
        old_tcp_mux_keepalive_timeout,
        new_tcp_mux_keepalive_timeout,
        "transport.tcp_mux_keepalive_timeout",
        any,
    );
    push(
        out,
        old_heartbeat_timeout,
        new_heartbeat_timeout,
        "transport.heartbeat_timeout",
        any,
    );
    push(
        out,
        old_max_pool_count,
        new_max_pool_count,
        "transport.max_pool_count",
        any,
    );
    push(
        out,
        old_tcp_keepalive,
        new_tcp_keepalive,
        "transport.tcp_keepalive",
        any,
    );
    push(
        out,
        old_tcp_send_buffer_size,
        new_tcp_send_buffer_size,
        "transport.tcp_send_buffer_size",
        any,
    );
    push(
        out,
        old_tcp_recv_buffer_size,
        new_tcp_recv_buffer_size,
        "transport.tcp_recv_buffer_size",
        any,
    );
    #[cfg(feature = "quic")]
    push_redacted(
        out,
        &old_quic_options.clone().unwrap_or_default(),
        &new_quic_options.clone().unwrap_or_default(),
        "transport.quic_options",
        ServerReader::Quic,
    );
    // Without this crate's `quic` feature the field does not exist: the pattern
    // entry above is stripped along with it.
    #[cfg(not(feature = "quic"))]
    let _ = (old_quic_options, new_quic_options);
}

/// Every restart-only `[ssh_tunnel_gateway]` difference.
///
/// **What this models.** `Service::run` starts the gateway under
/// `#[cfg(feature = "ssh")]`, hands it a clone of the whole `ServerConfig`, and
/// `SshListener::new` reads all seven fields from it once
/// (`frp-server/src/ssh_gateway.rs`): the port, the bind address, the host-key
/// pair, the authorized-keys file, the session idle timeout and `allowNoneAuth`.
/// The credential the gateway authenticates with is the **live**
/// `auth_cfg.token`, which the reload does re-key — that is why nothing here
/// reports the token.
///
/// **What keeps it complete.** Both patterns name all seven fields with no `..`.
///
/// **What it does not cover.** In a build without `frp-server`'s `ssh` feature
/// the gateway is never started, so no field here has a reader; they carry
/// [`ServerReader::Ssh`] and `frp-server` omits them.
fn ssh_gateway_restart_changes(
    out: &mut Vec<RestartOnlyChange>,
    old: &SshTunnelGatewayConfig,
    new: &SshTunnelGatewayConfig,
) {
    let SshTunnelGatewayConfig {
        bind_port: old_bind_port,
        bind_addr: old_bind_addr,
        private_key_file: old_private_key_file,
        auto_gen_private_key_path: old_auto_gen_private_key_path,
        authorized_keys_file: old_authorized_keys_file,
        ssh_session_idle_timeout: old_ssh_session_idle_timeout,
        allow_none_auth: old_allow_none_auth,
    } = old;
    let SshTunnelGatewayConfig {
        bind_port: new_bind_port,
        bind_addr: new_bind_addr,
        private_key_file: new_private_key_file,
        auto_gen_private_key_path: new_auto_gen_private_key_path,
        authorized_keys_file: new_authorized_keys_file,
        ssh_session_idle_timeout: new_ssh_session_idle_timeout,
        allow_none_auth: new_allow_none_auth,
    } = new;

    let reader = ServerReader::Ssh;
    push(
        out,
        old_bind_port,
        new_bind_port,
        "ssh_tunnel_gateway.bind_port",
        reader,
    );
    push(
        out,
        old_bind_addr,
        new_bind_addr,
        "ssh_tunnel_gateway.bind_addr",
        reader,
    );
    push(
        out,
        old_private_key_file,
        new_private_key_file,
        "ssh_tunnel_gateway.private_key_file",
        reader,
    );
    push(
        out,
        old_auto_gen_private_key_path,
        new_auto_gen_private_key_path,
        "ssh_tunnel_gateway.auto_gen_private_key_path",
        reader,
    );
    push(
        out,
        old_authorized_keys_file,
        new_authorized_keys_file,
        "ssh_tunnel_gateway.authorized_keys_file",
        reader,
    );
    push(
        out,
        old_ssh_session_idle_timeout,
        new_ssh_session_idle_timeout,
        "ssh_tunnel_gateway.ssh_session_idle_timeout",
        reader,
    );
    push(
        out,
        old_allow_none_auth,
        new_allow_none_auth,
        "ssh_tunnel_gateway.allow_none_auth",
        reader,
    );
}

/// Every restart-only `[observability]` difference.
///
/// **What this models.** The reader is `frps`'s `init_logging`, which builds the
/// OTLP layer from these two fields once at startup. It is `#[cfg(feature =
/// "otel")]` — an `frps` feature forwarding `frp-core/otel` — so the gate is
/// resolved here, in the crate that carries the feature.
///
/// **What keeps it complete.** Both patterns name both fields with no `..`.
///
/// **What it does not cover.** Two things. `OTEL_EXPORTER_OTLP_ENDPOINT` takes
/// precedence over `otlp_endpoint` at init (`frps/src/main.rs`), so with that
/// variable set a config change is masked in both directions. And the gate is
/// `frp-core`'s feature, not `frps`'s: a build that enables `frp-core/otel`
/// through another member (e.g. `frpc`) while the binary under test does not is a
/// build where this group is reported although that binary's `init_logging` does
/// not read it. Both directions of that are recorded in the change report.
fn observability_restart_changes(
    out: &mut Vec<RestartOnlyChange>,
    old: &ObservabilityConfig,
    new: &ObservabilityConfig,
) {
    let ObservabilityConfig {
        otlp_endpoint: old_otlp_endpoint,
        service_name: old_service_name,
    } = old;
    let ObservabilityConfig {
        otlp_endpoint: new_otlp_endpoint,
        service_name: new_service_name,
    } = new;

    // Always emitted; `frp-server` filters on
    // `frp_core::logging::OTEL_ENABLED`, the same way it filters the dashboard,
    // SSH and QUIC gates — one rule for every reader gate.
    let reader = ServerReader::Otel;
    push(
        out,
        old_otlp_endpoint,
        new_otlp_endpoint,
        "observability.otlp_endpoint",
        reader,
    );
    push(
        out,
        old_service_name,
        new_service_name,
        "observability.service_name",
        reader,
    );
}

impl ServerConfig {
    /// Every `ServerConfig` field that differs between the running config
    /// (`self`) and a freshly loaded one (`other`) and that a `SIGUSR1` reload
    /// **cannot apply**, in report order.
    ///
    /// # What this models
    ///
    /// The reload applies, in place: `allow_ports` (and the
    /// `allow_port_start`/`allow_port_end` it falls back to, through
    /// `resolve_allow_ports`), the five `[auth]` fields, and — with the `tls`
    /// feature — the certificate/key/CA paths. It reports `bind_port` and
    /// `bind_addr` itself, and the whole `[auth]` section is
    /// `note_auth_restart_changes`'s. Everything else in `ServerConfig` is named
    /// here, **iff some code in the reloading build reads it** — `reader` says
    /// which build feature that reader needs.
    ///
    /// # What keeps it complete
    ///
    /// Both `let ServerConfig { … }` patterns below name every field with **no
    /// `..`**, and the nested config structs are destructured the same way, so
    /// adding or renaming a field anywhere in this config shape fails this module
    /// to compile (E0027) until the field is named and classified. The
    /// `_`-prefixed bindings keep the "bound but never used" warning off; they
    /// must stay in the pattern.
    ///
    /// # What it does not cover
    ///
    /// * Fields **no reader in `frp-server`** consumes are neither applied nor
    ///   reported, because a restart cannot make them take effect either:
    ///   `tls_enable` (`ServerConfig.tls_enable` — `grep -rn tls_enable
    ///   frp-server/src frps/src` finds no read of it; the hits are only comment
    ///   lines and call sites of the unrelated helper
    ///   `presence.warn_inert_web_server_tls_enable(reader)` (its `reader` comes
    ///   from `web_server_tls_enable_reader()`), which reads a different key,
    ///   `[web_server.tls] enable`. No count is pinned, because
    ///   the comment that states it changes it; Go v0.71.0's server config has
    ///   no such field either, its `TLS.Enable` is a *client* one),
    ///   `tls_server_name` (`ServerConfig::tls_server_name` is a *client* field in
    ///   Go; nothing outside `frp-core`'s client transport reads it),
    ///   `feature.gates` (validated by the loader at load time only;
    ///   `crate::feature_gate::set_from_map` is never called by the server),
    ///   `includes` (a load-time directive consumed by the reload's own
    ///   `load_server_config`, so a change that alters what is loaded shows up on
    ///   the fields below and one that does not is a genuine no-op), and the
    ///   `web_server` fields listed in [`web_server_restart_changes`]. This is
    ///   the disposition `[auth].useEncryption` already has in
    ///   `note_auth_restart_changes`, and it is pinned by tests.
    /// * The `tls` certificate/key/CA paths are skipped here because the reload
    ///   applies them when `frp-server`'s `tls` feature is on and nothing reads
    ///   them when it is off (`frp-server/tls` implies `frp-core/tls`, so there
    ///   is no third state).
    /// * Values the loader completes or normalizes away on both sides: an absent
    ///   key and its default are not a change (`udp_packet_size = 0` → 1500,
    ///   `transport.heartbeat_timeout = 0` → the tcpMux default), and
    ///   `tcp_mux`/`quic_options` are compared as the effective value the runtime
    ///   resolves.
    /// * It compares **config**, not runtime effect. A field whose *effect* is
    ///   bounded elsewhere is still compared by the value the loader left.
    /// * It says nothing about whether an applied field has a sensible new value
    ///   — that is the reload's apply block's business.
    /// * `bind_port`/`bind_addr` are skipped because the reload reports them
    ///   itself. `tls_enable` was previously left in that group and reported by
    ///   `reload()`; it is now in the no-reader group above, because nothing in
    ///   `frp-server`/`frps` reads `ServerConfig.tls_enable` (measured:
    ///   `grep -rn tls_enable frp-server/src frps/src` finds no read) — the same
    ///   shape as the `tls_server_name` case above, and reporting a restart for
    ///   it claimed an effect a restart cannot have.
    pub fn restart_only_changes(&self, other: &ServerConfig) -> Vec<RestartOnlyChange> {
        let mut out: Vec<RestartOnlyChange> = Vec::new();

        let ServerConfig {
            // Reported by the reload itself.
            bind_addr: _old_bind_addr,
            bind_port: _old_bind_port,
            proxy_bind_addr: old_proxy_bind_addr,
            vhost_http_port: old_vhost_http_port,
            vhost_https_port: old_vhost_https_port,
            #[cfg(feature = "kcp")]
                kcp_bind_port: old_kcp_bind_port,
            #[cfg(feature = "quic")]
                quic_bind_port: old_quic_bind_port,
            sudp_port: old_sudp_port,
            tcpmux_httpconnect_port: old_tcpmux_httpconnect_port,
            sub_domain_host: old_sub_domain_host,
            #[cfg(feature = "websocket")]
                websocket_port: old_websocket_port,
            // No reader in `frp-server`/`frps` (`grep -rn tls_enable
            // frp-server/src frps/src` finds no read — only comment lines and
            // call sites of the unrelated helper
            // `presence.warn_inert_web_server_tls_enable(reader)` (its `reader`
            // comes from `web_server_tls_enable_reader()`), which reads a
            // different key, `[web_server.tls] enable`; no count is pinned,
            // since stating it here would itself change it). Inert: neither a
            // reload nor a restart can make a change take effect, so it is
            // neither applied nor reported.
            tls_enable: _old_tls_enable,
            // Applied in place by the reload's TLS hot-reload block.
            tls_cert_file: _old_tls_cert_file,
            tls_key_file: _old_tls_key_file,
            tls_ca_file: _old_tls_ca_file,
            // No reader outside `frp-core`'s client transport.
            tls_server_name: _old_tls_server_name,
            tls_only: old_tls_only,
            // Every `[auth]` field is `note_auth_restart_changes`'s.
            auth: _old_auth,
            log: old_log,
            web_server: old_web_server,
            transport: old_transport,
            // Applied through `resolve_allow_ports` (the group is reported as
            // `allow_ports` when it changes) — including the case where
            // `allow_ports` is empty and these two are the effective range.
            allow_port_start: _old_allow_port_start,
            allow_port_end: _old_allow_port_end,
            allow_ports: _old_allow_ports,
            max_ports_per_client: old_max_ports_per_client,
            max_proxies_per_client: old_max_proxies_per_client,
            max_custom_domains_per_proxy: old_max_custom_domains_per_proxy,
            max_conns_per_proxy: old_max_conns_per_proxy,
            vhost_http_timeout: old_vhost_http_timeout,
            user_conn_timeout: old_user_conn_timeout,
            detailed_errors_to_client: old_detailed_errors_to_client,
            graceful_shutdown_timeout: old_graceful_shutdown_timeout,
            tcp_mux_passthrough: old_tcp_mux_passthrough,
            udp_packet_size: old_udp_packet_size,
            http_plugins: old_http_plugins,
            feature: old_feature,
            // A load-time directive, consumed by the reload's own
            // `load_server_config`.
            includes: _old_includes,
            ssh_tunnel_gateway: old_ssh_tunnel_gateway,
            nat_hole_analysis_data_reserve_hours: old_nat_hole_analysis_data_reserve_hours,
            observability: old_observability,
            max_connections: old_max_connections,
            max_accept_rate: old_max_accept_rate,
        } = self;
        let ServerConfig {
            bind_addr: _new_bind_addr,
            bind_port: _new_bind_port,
            proxy_bind_addr: new_proxy_bind_addr,
            vhost_http_port: new_vhost_http_port,
            vhost_https_port: new_vhost_https_port,
            #[cfg(feature = "kcp")]
                kcp_bind_port: new_kcp_bind_port,
            #[cfg(feature = "quic")]
                quic_bind_port: new_quic_bind_port,
            sudp_port: new_sudp_port,
            tcpmux_httpconnect_port: new_tcpmux_httpconnect_port,
            sub_domain_host: new_sub_domain_host,
            #[cfg(feature = "websocket")]
                websocket_port: new_websocket_port,
            // No reader in `frp-server`/`frps`; see the `old` pattern above.
            tls_enable: _new_tls_enable,
            tls_cert_file: _new_tls_cert_file,
            tls_key_file: _new_tls_key_file,
            tls_ca_file: _new_tls_ca_file,
            tls_server_name: _new_tls_server_name,
            tls_only: new_tls_only,
            auth: _new_auth,
            log: new_log,
            web_server: new_web_server,
            transport: new_transport,
            allow_port_start: _new_allow_port_start,
            allow_port_end: _new_allow_port_end,
            allow_ports: _new_allow_ports,
            max_ports_per_client: new_max_ports_per_client,
            max_proxies_per_client: new_max_proxies_per_client,
            max_custom_domains_per_proxy: new_max_custom_domains_per_proxy,
            max_conns_per_proxy: new_max_conns_per_proxy,
            vhost_http_timeout: new_vhost_http_timeout,
            user_conn_timeout: new_user_conn_timeout,
            detailed_errors_to_client: new_detailed_errors_to_client,
            graceful_shutdown_timeout: new_graceful_shutdown_timeout,
            tcp_mux_passthrough: new_tcp_mux_passthrough,
            udp_packet_size: new_udp_packet_size,
            http_plugins: new_http_plugins,
            feature: new_feature,
            includes: _new_includes,
            ssh_tunnel_gateway: new_ssh_tunnel_gateway,
            nat_hole_analysis_data_reserve_hours: new_nat_hole_analysis_data_reserve_hours,
            observability: new_observability,
            max_connections: new_max_connections,
            max_accept_rate: new_max_accept_rate,
        } = other;

        // `FeatureConfig` has no `PartialEq`/`Display`, and its one `HashMap`
        // cannot be compared by `Debug` (iteration order is seeded per
        // instance); it is also read by nothing in the server. Named here so
        // that a second field is a compile error rather than a silent gap.
        let FeatureConfig {
            gates: _old_feature_gates,
        } = old_feature;
        let FeatureConfig {
            gates: _new_feature_gates,
        } = new_feature;

        // Borrow the accumulator mutably for `push` and the group helpers.
        let out = &mut out;

        let any = ServerReader::Any;
        push(
            out,
            old_proxy_bind_addr,
            new_proxy_bind_addr,
            "proxy_bind_addr",
            any,
        );
        push(
            out,
            old_vhost_http_port,
            new_vhost_http_port,
            "vhost_http_port",
            any,
        );
        push(
            out,
            old_vhost_https_port,
            new_vhost_https_port,
            "vhost_https_port",
            any,
        );
        // The three listener ports are `#[cfg]`-gated in the *struct* on
        // `frp-core`'s features but read only by `frp-server`'s listeners, so
        // their gate is resolved on `frp-server`'s features
        // (`ServerReader::Kcp` / `Quic` / `Websocket`). The dashboard is not a
        // second reader: its own `#[cfg(feature = "kcp")]` is this crate's kcp
        // too, so it prints those keys only where the listener is compiled. `Any`
        // here would report a restart in a build with the listener compiled out —
        // measured in the very lane that motivated this module's location,
        // `cargo test -p frp-server --no-default-features --all-targets`, where
        // `frp-core`'s three features are on through the `frp-client`
        // dev-dependency and `frp-server`'s are off; a `…OrDashboard`
        // disjunction reported the same false line in
        // `--no-default-features --features dashboard`.
        #[cfg(feature = "kcp")]
        push(
            out,
            old_kcp_bind_port,
            new_kcp_bind_port,
            "kcp_bind_port",
            ServerReader::Kcp,
        );
        #[cfg(feature = "quic")]
        push(
            out,
            old_quic_bind_port,
            new_quic_bind_port,
            "quic_bind_port",
            ServerReader::Quic,
        );
        push(out, old_sudp_port, new_sudp_port, "sudp_port", any);
        push(
            out,
            old_tcpmux_httpconnect_port,
            new_tcpmux_httpconnect_port,
            "tcpmux_httpconnect_port",
            any,
        );
        push(
            out,
            old_sub_domain_host,
            new_sub_domain_host,
            "sub_domain_host",
            any,
        );
        #[cfg(feature = "websocket")]
        push(
            out,
            old_websocket_port,
            new_websocket_port,
            "websocket_port",
            ServerReader::Websocket,
        );
        push(out, old_tls_only, new_tls_only, "tls_only", any);

        log_restart_changes(out, old_log, new_log);
        web_server_restart_changes(out, old_web_server, new_web_server);
        transport_restart_changes(out, old_transport, new_transport);

        push(
            out,
            old_max_ports_per_client,
            new_max_ports_per_client,
            "max_ports_per_client",
            any,
        );
        push(
            out,
            old_max_proxies_per_client,
            new_max_proxies_per_client,
            "max_proxies_per_client",
            any,
        );
        push(
            out,
            old_max_custom_domains_per_proxy,
            new_max_custom_domains_per_proxy,
            "max_custom_domains_per_proxy",
            any,
        );
        push(
            out,
            old_max_conns_per_proxy,
            new_max_conns_per_proxy,
            "max_conns_per_proxy",
            any,
        );
        push(
            out,
            old_vhost_http_timeout,
            new_vhost_http_timeout,
            "vhost_http_timeout",
            any,
        );
        push(
            out,
            old_user_conn_timeout,
            new_user_conn_timeout,
            "user_conn_timeout",
            any,
        );
        push(
            out,
            old_detailed_errors_to_client,
            new_detailed_errors_to_client,
            "detailed_errors_to_client",
            any,
        );
        push(
            out,
            old_graceful_shutdown_timeout,
            new_graceful_shutdown_timeout,
            "graceful_shutdown_timeout",
            any,
        );
        push(
            out,
            old_tcp_mux_passthrough,
            new_tcp_mux_passthrough,
            "tcp_mux_passthrough",
            any,
        );
        push(
            out,
            old_udp_packet_size,
            new_udp_packet_size,
            "udp_packet_size",
            any,
        );
        push(
            out,
            old_nat_hole_analysis_data_reserve_hours,
            new_nat_hole_analysis_data_reserve_hours,
            "nat_hole_analysis_data_reserve_hours",
            any,
        );
        // The two `Option<u32>` limits: `Option<u32>` has no `Display`, and the
        // raw spellings are **not** the running value — an absent
        // `max_connections` and `max_connections = 512` both build a 512-permit
        // semaphore, and an absent `max_accept_rate` and `max_accept_rate = 0`
        // both mean "no limit". So the comparison is on the effective values the
        // server resolves (`effective_max_connections` /
        // `effective_max_accept_rate`, the same functions `frp-server` calls), and
        // the raw spelling is only what gets *printed*: `<unset>` appears only
        // when the other side differs in effect from it. Comparing the raw
        // `Option`s was a measured false "restart required"
        // (`max_connections: <unset> -> 512`, `max_accept_rate: <unset> -> 0`
        // where base said `no changes detected`) and it is also the shape
        // `max_connections = 0` (unlimited) deliberately *does* report: 0 and the
        // 512 default are different settings.
        if effective_max_connections(*old_max_connections)
            != effective_max_connections(*new_max_connections)
        {
            out.push(RestartOnlyChange {
                name: "max_connections",
                old: show_opt_u32(old_max_connections),
                new: show_opt_u32(new_max_connections),
                name_only: false,
                reader: any,
            });
        }
        if effective_max_accept_rate(*old_max_accept_rate)
            != effective_max_accept_rate(*new_max_accept_rate)
        {
            out.push(RestartOnlyChange {
                name: "max_accept_rate",
                old: show_opt_u32(old_max_accept_rate),
                new: show_opt_u32(new_max_accept_rate),
                name_only: false,
                reader: any,
            });
        }

        // `HttpPluginConfig` has neither `PartialEq` nor `Display`: compare the
        // `Debug` rendering (injective for this plain-data struct — four strings,
        // a `Vec<String>` and two scalars) and print the name only, because
        // `addr` may carry `http://user:pass@host` credentials and this summary
        // is logged (`reload()` → `info!` → `SIGUSR1: {summary}`).
        push_redacted(out, old_http_plugins, new_http_plugins, "http_plugins", any);

        ssh_gateway_restart_changes(out, old_ssh_tunnel_gateway, new_ssh_tunnel_gateway);
        observability_restart_changes(out, old_observability, new_observability);

        std::mem::take(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A config with a valid, non-default value in every restart-only field the
    /// reload reports in *any* build, so a rewrite of one field is a one-line
    /// diff.
    fn base() -> ServerConfig {
        // The three `#[cfg]`-gated listener ports are left to
        // `ServerConfig::default()` (all zero), so this builds in every feature
        // combination without a `mut` that some of them do not need.
        ServerConfig {
            bind_addr: "127.0.0.1".into(),
            bind_port: 7000,
            proxy_bind_addr: "127.0.0.1".into(),
            vhost_http_port: 0,
            vhost_https_port: 0,
            sudp_port: 0,
            tcpmux_httpconnect_port: 0,
            sub_domain_host: String::new(),
            tls_enable: false,
            tls_cert_file: String::new(),
            tls_key_file: String::new(),
            tls_ca_file: String::new(),
            tls_server_name: String::new(),
            tls_only: false,
            log: LogConfig::default(),
            web_server: WebServerConfig::default(),
            transport: ServerTransportConfig::default(),
            allow_port_start: 1,
            allow_port_end: 65535,
            allow_ports: String::new(),
            max_ports_per_client: 0,
            max_proxies_per_client: 0,
            max_custom_domains_per_proxy: 0,
            max_conns_per_proxy: 0,
            vhost_http_timeout: 60,
            user_conn_timeout: 10,
            detailed_errors_to_client: true,
            graceful_shutdown_timeout: 30,
            tcp_mux_passthrough: false,
            udp_packet_size: 1500,
            http_plugins: Vec::new(),
            feature: FeatureConfig::default(),
            includes: Vec::new(),
            ssh_tunnel_gateway: SshTunnelGatewayConfig::default(),
            nat_hole_analysis_data_reserve_hours: 168,
            observability: ObservabilityConfig::default(),
            max_connections: None,
            max_accept_rate: None,
            ..ServerConfig::default()
        }
    }

    fn names(changes: &[RestartOnlyChange]) -> Vec<&'static str> {
        changes.iter().map(|c| c.name).collect()
    }

    /// The positive control: an unchanged config reports nothing, and a reload
    /// of one field reports exactly that field — the defect this list exists for
    /// (`transport.heartbeat_timeout = 30 -> 60` plus `max_ports_per_client = 0
    /// -> 7` used to answer `config reloaded: no changes detected`).
    #[test]
    fn only_the_changed_field_is_named() {
        let old = base();
        assert!(
            old.restart_only_changes(&old).is_empty(),
            "a config compared against itself must report nothing"
        );

        let mut new = base();
        new.transport.heartbeat_timeout = 60;
        new.max_ports_per_client = 7;
        let changes = old.restart_only_changes(&new);
        assert_eq!(
            names(&changes),
            vec!["transport.heartbeat_timeout", "max_ports_per_client"]
        );
        assert_eq!(changes[0].old, "90");
        assert_eq!(changes[0].new, "60");
        assert_eq!(changes[1].old, "0");
        assert_eq!(changes[1].new, "7");
        assert!(!changes[0].name_only);
    }

    /// Every group reports under its own fields, and the values are the ones
    /// that changed. Guards the one-group-at-a-time shape the shell probe pins
    /// end to end.
    #[test]
    fn each_group_reports_its_own_field() {
        let old = base();

        let mut new = base();
        new.log.level = "debug".into();
        assert_eq!(names(&old.restart_only_changes(&new)), vec!["log.level"]);

        let mut new = base();
        new.web_server.custom_404_page = "<html>gone</html>".into();
        assert_eq!(
            names(&old.restart_only_changes(&new)),
            vec!["web_server.custom_404_page"]
        );

        let mut new = base();
        new.transport.tcp_mux = Some(false);
        assert_eq!(
            names(&old.restart_only_changes(&new)),
            vec!["transport.tcp_mux"]
        );

        let mut new = base();
        new.max_connections = Some(7);
        assert_eq!(
            names(&old.restart_only_changes(&new)),
            vec!["max_connections"]
        );
        assert_eq!(old.restart_only_changes(&new)[0].old, "<unset>");
        assert_eq!(old.restart_only_changes(&new)[0].new, "7");

        let mut new = base();
        new.http_plugins.push(crate::config::HttpPluginConfig {
            name: "p".into(),
            addr: "http://user:pass@127.0.0.1:8080".into(),
            path: "/".into(),
            ops: vec!["login".into()],
            timeout: 5,
            enable_control: false,
            tls_verify: false,
        });
        let changes = old.restart_only_changes(&new);
        assert_eq!(names(&changes), vec!["http_plugins"]);
        assert!(
            changes[0].name_only,
            "a plugin address can embed credentials; it must not be printed"
        );
        assert!(
            changes[0].old.is_empty() && changes[0].new.is_empty(),
            "name-only entries carry no values at all"
        );

        let mut new = base();
        new.tls_only = true;
        assert_eq!(names(&old.restart_only_changes(&new)), vec!["tls_only"]);
    }

    /// The two `Option<u32>` limits are compared as the values the server
    /// **runs with**, not as their raw `Option` spellings.
    ///
    /// `effective_max_connections(None) == effective_max_connections(Some(512))`
    /// and `effective_max_accept_rate(None) == effective_max_accept_rate(Some(0))`,
    /// so those pairs are one setting and must not be reported — comparing the raw
    /// options did report them (`max_connections: <unset> -> 512 (restart
    /// required)`, `max_accept_rate: <unset> -> 0 (restart required)`) where the
    /// base binary said `no changes detected`, and it falsified the module's own
    /// "an absent key and its default are not a change" sentence.
    ///
    /// `max_connections = 0` is **not** an equivalence: 0 means unlimited, not the
    /// 512 default.
    #[test]
    fn unset_limits_and_their_explicit_defaults_are_one_setting() {
        let unset = base();
        assert_eq!(unset.max_connections, None);
        assert_eq!(unset.max_accept_rate, None);

        let mut explicit_defaults = base();
        explicit_defaults.max_connections = Some(512);
        explicit_defaults.max_accept_rate = Some(0);
        assert!(
            unset.restart_only_changes(&explicit_defaults).is_empty(),
            "an absent limit and its explicit default must not be a change"
        );
        assert!(
            explicit_defaults.restart_only_changes(&unset).is_empty(),
            "…and the comparison must be symmetric"
        );

        // The same spelling on both sides is quiet as well.
        assert!(explicit_defaults
            .restart_only_changes(&explicit_defaults)
            .is_empty());

        // `Some(0)` for `max_connections` is "unlimited", which is a different
        // running value from the 512 default, and IS reported.
        let mut unlimited = base();
        unlimited.max_connections = Some(0);
        let changes = unset.restart_only_changes(&unlimited);
        assert_eq!(names(&changes), vec!["max_connections"]);
        assert_eq!(changes[0].old, "<unset>");
        assert_eq!(changes[0].new, "0");

        // A real rate limit differs from "no limit" and is reported.
        let mut limited = base();
        limited.max_accept_rate = Some(10);
        let changes = unset.restart_only_changes(&limited);
        assert_eq!(names(&changes), vec!["max_accept_rate"]);
        assert_eq!(changes[0].old, "<unset>");
        assert_eq!(changes[0].new, "10");
    }

    /// The two effective-value functions are the ones the server resolves with —
    /// `frp-server`'s `resolve_max_connections` and its `Service::run` both
    /// delegate to them now, so a drift would be a compile-time-visible edit at a
    /// single site rather than two constants agreeing by coincidence.
    #[test]
    fn effective_limits_match_the_runtime_resolution() {
        assert_eq!(effective_max_connections(None), 512);
        assert_eq!(effective_max_connections(Some(0)), 0, "0 = unlimited");
        assert_eq!(effective_max_connections(Some(512)), 512);
        assert_eq!(effective_max_connections(Some(5)), 5);
        assert_eq!(effective_max_accept_rate(None), 0);
        assert_eq!(effective_max_accept_rate(Some(0)), 0);
        assert_eq!(effective_max_accept_rate(Some(10)), 10);
    }

    /// The listener/address group (the fields whose readers are the listeners
    /// `Service::run` binds once) is named too. Only the fields present in every
    /// feature combination are changed, so the expected list is feature-free.
    #[test]
    fn listener_port_and_address_changes_are_named() {
        let old = base();
        let mut new = base();
        new.proxy_bind_addr = "10.0.0.1".into();
        new.vhost_http_port = 8080;
        new.vhost_https_port = 8443;
        new.sudp_port = 12500;
        new.tcpmux_httpconnect_port = 7001;
        new.sub_domain_host = "example.com".into();
        new.tls_only = true;
        assert_eq!(
            names(&old.restart_only_changes(&new)),
            vec![
                "proxy_bind_addr",
                "vhost_http_port",
                "vhost_https_port",
                "sudp_port",
                "tcpmux_httpconnect_port",
                "sub_domain_host",
                "tls_only",
            ]
        );
    }

    /// The dispositions of the fields that must **not** be reported, each for its
    /// own reason. A change here produces no line — which is the claim, not an
    /// accident: a restart cannot make one take effect either.
    #[test]
    fn unreported_fields_stay_unreported() {
        let old = base();

        // Applied in place by the reload (`resolve_allow_ports`, the TLS
        // hot-reload block).
        let mut new = base();
        new.allow_ports = "10000-20000".into();
        new.allow_port_start = 10000;
        new.allow_port_end = 20000;
        assert!(old.restart_only_changes(&new).is_empty());

        let mut new = base();
        new.tls_cert_file = "/tmp/cert.pem".into();
        new.tls_key_file = "/tmp/key.pem".into();
        new.tls_ca_file = "/tmp/ca.pem".into();
        assert!(old.restart_only_changes(&new).is_empty());

        // Reported by the reload itself.
        let mut new = base();
        new.bind_port = 7001;
        new.bind_addr = "0.0.0.0".into();
        assert!(old.restart_only_changes(&new).is_empty());

        // No reader in `frp-server`… (`tls_enable` is inert: the reload no
        // longer reports it — measured `grep -rn tls_enable frp-server/src
        // frps/src` finds no read — and a restart would change nothing either).
        let mut new = base();
        new.tls_enable = true;
        new.tls_server_name = "frps.example.com".into();
        new.web_server.pprof_enable = true;
        new.web_server.tls_ca_file = "/tmp/dash-ca.pem".into();
        new.web_server.tls_server_name = "dash.example.com".into();
        new.web_server.tls.enable = true;
        new.web_server.tls.trusted_ca_file = "/tmp/dash-trust.pem".into();
        new.web_server.tls.server_name = "dash-nested.example.com".into();
        // …and the nested section's cert/key pair, which is additionally
        // **unreachable** through the loader (`normalize_web_server_section`
        // removes the table's mapped keys before serde, so no loaded config
        // carries a non-default `WebServerTlsConfig` — its values are hoisted
        // onto the flat fields instead): a difference here cannot come from a
        // config file, and the flat `tls_cert_file` / `tls_key_file` entries are
        // what a reload reports for `[web_server.tls] certFile` / `cert_file`
        // alike. Measured in the change report §the before/after table (both
        // spellings, both loader modes, both table orders).
        new.web_server.tls.cert_file = "/tmp/nested-cert.pem".into();
        new.web_server.tls.key_file = "/tmp/nested-key.pem".into();
        assert!(
            old.restart_only_changes(&new).is_empty(),
            "no reader, and the nested cert/key pair cannot even be loaded"
        );

        // A load-time directive and a load-time validation input.
        let mut new = base();
        new.includes = vec!["extra.toml".into()];
        new.feature.gates.insert("VirtualNet".into(), true);
        assert!(
            old.restart_only_changes(&new).is_empty(),
            "includes is consumed by the reload's own load; feature gates are \
             validated at load time and read by nothing at runtime"
        );
    }

    /// The reader gates are the build's, not the field's: every gate either
    /// resolves to a reader in this build or is filtered out by the caller. What
    /// this test pins is that the five `ServerReader` variants are exactly the
    /// ones `frp-server` resolves, and that a field's gate does not change when
    /// its value does.
    #[test]
    fn reader_gates_are_stable_and_known() {
        let old = base();
        let mut new = base();
        new.web_server.port = 8080;
        new.ssh_tunnel_gateway.bind_port = 2222;
        new.observability.otlp_endpoint = "http://127.0.0.1:4317".into();
        let changes = old.restart_only_changes(&new);
        for c in &changes {
            assert!(
                c.reader != ServerReader::Any,
                "{} must not be gated: it has a reader in every build",
                c.name
            );
        }
        let gated: Vec<&str> = changes
            .iter()
            .filter(|c| c.reader == ServerReader::Dashboard)
            .map(|c| c.name)
            .collect();
        assert_eq!(gated, vec!["web_server.port"]);
        assert!(changes
            .iter()
            .any(|c| c.name == "ssh_tunnel_gateway.bind_port" && c.reader == ServerReader::Ssh));
        let otel: Vec<&str> = changes
            .iter()
            .filter(|c| c.reader == ServerReader::Otel)
            .map(|c| c.name)
            .collect();
        assert_eq!(otel, vec!["observability.otlp_endpoint"]);
    }

    /// The three `#[cfg]`-gated listener ports carry the **`frp-server`** gate,
    /// not `Any`: their fields exist whenever `frp-core`'s features are on (which
    /// another crate in the graph can turn on), but nothing reads them unless
    /// `frp-server` compiled the listener — or, for `kcp_bind_port` /
    /// `quic_bind_port`, the dashboard that prints them from the startup
    /// snapshot. `Any` here was a measured false "restart required" in
    /// `cargo test -p frp-server --no-default-features --all-targets`.
    ///
    /// Which variants are asserted depends on this crate's features (they decide
    /// whether the field exists at all); the `frp-server`-side resolution of each
    /// gate is pinned by `gated_listener_ports_follow_their_own_features` in
    /// `frp-server/tests/server_reload_restart_only.rs`, which runs in the
    /// `--no-default-features` lane **and** in the
    /// `--no-default-features --features dashboard` one — the second is where a
    /// `…OrDashboard` disjunction used to report a false "restart required".
    #[test]
    fn gated_listener_ports_carry_a_reader_gate_not_any() {
        /// Move each of the three gated listener ports, where the field exists.
        ///
        /// A helper rather than three inline `#[cfg]` blocks in the test body so
        /// the test's binding is **genuinely mutable in every configuration**:
        /// `&mut cfg` is a mutable borrow even when the body below compiles to
        /// nothing, so `RUSTFLAGS="-D warnings" cargo check -p frp-core
        /// --no-default-features --all-targets`
        /// (`.github/workflows/ci.yml` "Check frp-core tier test targets compile
        /// (isolated, no features)") has no `unused_mut` to report in the micro
        /// tier. That step is exactly where the inline version was caught: the
        /// three assignments are cfg-gated, so with no features on the `let mut`
        /// was unused and `-D warnings` made it an error. No `#[allow]` is
        /// needed, and the feature-gated arms below keep their pins.
        ///
        /// The parameter is `_cfg` because in the no-features configuration the
        /// body is empty; the leading underscore is what keeps *that* from being
        /// an `unused_variables` error, and the cfg'd arms still use it.
        fn set_gated_ports(_cfg: &mut ServerConfig) {
            #[cfg(feature = "kcp")]
            {
                _cfg.kcp_bind_port = 17001;
            }
            #[cfg(feature = "quic")]
            {
                _cfg.quic_bind_port = 17002;
            }
            #[cfg(feature = "websocket")]
            {
                _cfg.websocket_port = 17003;
            }
        }

        let old = base();
        let mut new = base();
        set_gated_ports(&mut new);
        let changes = old.restart_only_changes(&new);
        for c in &changes {
            assert!(
                c.reader != ServerReader::Any,
                "{} must not be `Any`: its reader is frp-server-gated",
                c.name
            );
        }
        #[cfg(feature = "kcp")]
        assert!(changes
            .iter()
            .any(|c| c.name == "kcp_bind_port" && c.reader == ServerReader::Kcp));
        #[cfg(feature = "quic")]
        assert!(changes
            .iter()
            .any(|c| c.name == "quic_bind_port" && c.reader == ServerReader::Quic));
        #[cfg(feature = "websocket")]
        assert!(changes
            .iter()
            .any(|c| c.name == "websocket_port" && c.reader == ServerReader::Websocket));

        // In the micro tier none of the three fields exists, so every arm above
        // is compiled out and the loop is empty. Anchor the test there rather
        // than leaving it a no-op: the premise of this case is that the three
        // ports were changed, and the only checkable consequence in a build where
        // they do not exist is that no *other* field is invented.
        #[cfg(not(any(feature = "kcp", feature = "quic", feature = "websocket")))]
        assert!(
            changes.is_empty(),
            "no gated port exists in this build, so this case must report nothing: {changes:?}"
        );
    }
}
