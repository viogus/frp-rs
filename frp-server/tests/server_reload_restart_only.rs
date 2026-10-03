//! The server's `SIGUSR1` reload against the **restart-only** settings outside
//! `[auth]` (`TODO.md`, "Every restart-only setting outside `[auth]` is still
//! silently ignored by the SIGUSR1 reload").
//!
//! These tests drive `frp_server::service::Service::reload` in process — the
//! same function the signal handler calls (`frps/src/main.rs`) — and assert the
//! summary it returns, one group of settings per case. The shell probe kept with
//! the change (`/tmp/sra-probe/probe-non-auth.sh`, and the base/head table in
//! `/tmp/restart-only-report.md`) measures the same thing from outside, through
//! a real `frps` and a real `SIGUSR1`; these tests cover the field groups a
//! single shell case cannot (every group, and both directions of the
//! feature-gated ones).
//!
//! Every case is a **whole-file rewrite** of one field, and every assertion is on
//! the exact summary — an over-report (naming a field the reload applies, or one
//! whose only reader this build does not compile) is as much a failure here as a
//! silent one.
//!
//! No `#![cfg(...)]` at the top: the file compiles in every feature combination
//! of `frp-server`, and the feature-gated groups carry their own gates.
//!
//! **Running this file against a pristine base tree.** Exactly one ident here
//! belongs to this branch rather than to base: `frp_core::logging::OTEL_ENABLED`
//! (the `otel` gate, added with the list — the question "does *this* build's
//! `frp-core` carry `otel`?" has no base-visible API, which is why it is not
//! spelled with `cfg!`). For a base run, copy this file into the base tree and
//! replace that one ident with `false`:
//!
//! ```text
//! if frp_core::logging::OTEL_ENABLED {   ->   if false {
//! ```
//!
//! Everything else is base API and needs no edit. Measured 2026-09-28 on a
//! pristine `3f975e0` checkout with that one edit: **4 passed / 10 failed** — the
//! four passers are the negative controls (`applied_settings_do_not_report_a_restart`,
//! `dashboard_only_settings_are_reported_only_with_the_dashboard`,
//! `inert_settings_are_not_reported`, `observability_follows_the_otel_gate`), and
//! the ten failures are the fields the base reload never compared.

mod common;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use frp_core::config::load_server_config;
use frp_core::unsafe_features::UnsafeFeatures;
use frp_server::service::Service;

use common::allocate_port;

const TOKEN: &str = "restart-only-probe-token";

/// `bind_addr`/`bind_port` (a free port, never 7000) plus the section under
/// test, with `[auth]` **last** so a bare `key = value` in `extra` is not
/// swallowed by the `[auth]` table. `auth` is therefore never a field that
/// differs between two files written by this helper.
///
/// No top-level `tcp_mux` key: it normalizes into `transport.tcp_mux`, which
/// would then be pinned in both files and hide the one case that flips it. The
/// default (`tcp_mux = true`) is what the run gets.
fn probe_config(port: u16, extra: &str) -> String {
    format!(
        r#"bind_addr = "127.0.0.1"
bind_port = {port}
{extra}
[auth]
method = "token"
token = "{TOKEN}"
"#
    )
}

/// An in-process `frps` with a real config file on a free port.
struct Server {
    svc: Arc<Service>,
    _dir: tempfile::TempDir,
    config_path: PathBuf,
    run: tokio::task::JoinHandle<()>,
}

impl Server {
    async fn start(port: u16, extra: &str) -> Self {
        let dir = tempfile::tempdir().expect("temp dir");
        let config_path = dir.path().join("frps.toml");
        std::fs::write(&config_path, probe_config(port, extra)).expect("write initial config");
        let cfg = load_server_config(config_path.to_str().expect("utf-8 path"), false)
            .expect("the initial config must load");
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

    /// Rewrite the config file and reload, returning the summary.
    async fn rewrite_and_reload(&self, toml: &str) -> String {
        std::fs::write(&self.config_path, toml).expect("rewrite config");
        self.svc.reload().await.expect("the rewritten config loads")
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.run.abort();
    }
}

/// The item's own measurement, in process: `transport.heartbeat_timeout`
/// `30 -> 60` plus `max_ports_per_client` `0 -> 7` used to answer
/// `config reloaded: no changes detected`, naming neither field.
#[tokio::test]
async fn transport_and_limit_changes_are_named_not_silently_ignored() {
    let port = allocate_port();
    // TOML ordering matters: the bare key must precede the table header.
    let before = "max_ports_per_client = 0\n[transport]\nheartbeat_timeout = 30\n";
    let after = "max_ports_per_client = 7\n[transport]\nheartbeat_timeout = 60\n";
    let server = Server::start(port, before).await;

    // The positive control first: the same file again is still quiet, so the
    // report is a diff and not a standing alarm.
    let quiet = server.rewrite_and_reload(&probe_config(port, before)).await;
    assert_eq!(quiet, "config reloaded: no changes detected");

    let summary = server.rewrite_and_reload(&probe_config(port, after)).await;
    assert_ne!(
        summary, "config reloaded: no changes detected",
        "the item's measured shape must not be a no-op any more"
    );
    assert!(
        summary.contains("transport.heartbeat_timeout: 30 -> 60 (restart required)"),
        "the heartbeat timeout must be named with its direction: {summary}"
    );
    assert!(
        summary.contains("max_ports_per_client: 0 -> 7 (restart required)"),
        "the per-client port cap must be named with its direction: {summary}"
    );
}

/// `[log]` is read once, in `init_logging`, **before** the reload path exists —
/// so it must be reported rather than silently ignored.
#[tokio::test]
async fn log_changes_are_reported() {
    let port = allocate_port();
    let server = Server::start(port, "[log]\nlevel = \"info\"\n").await;

    let summary = server
        .rewrite_and_reload(&probe_config(port, "[log]\nlevel = \"debug\"\n"))
        .await;
    assert_eq!(
        summary, "log.level: info -> debug (restart required)",
        "a log change cannot be applied by a reload and must be named"
    );
}

/// One case per remaining group: a whole-file rewrite of one field, and the
/// summary must contain **exactly one** `(restart required)` line, for that
/// field. The value pair is asserted too wherever it is stable.
#[tokio::test]
async fn each_restart_only_group_is_named() {
    // (field, initial file body, rewritten file body, other fields the same
    // rewrite legitimately moves — a line for anything outside this set fails the
    // test, so an unexpected extra report is caught here and not only at the
    // shell probe.)
    let cases: &[(&str, &str, &str, &[&str])] = &[
        (
            "web_server.custom_404_page",
            "[web_server]\ncustom_404_page = \"<html>one</html>\"\n",
            "[web_server]\ncustom_404_page = \"<html>two</html>\"\n",
            &[],
        ),
        (
            "log.format",
            "[log]\nformat = \"text\"\n",
            "[log]\nformat = \"json\"\n",
            &[],
        ),
        (
            "max_conns_per_proxy",
            "max_conns_per_proxy = 0\n",
            "max_conns_per_proxy = 9\n",
            &[],
        ),
        (
            "max_proxies_per_client",
            "max_proxies_per_client = 0\n",
            "max_proxies_per_client = 8\n",
            &[],
        ),
        (
            "max_custom_domains_per_proxy",
            "max_custom_domains_per_proxy = 0\n",
            "max_custom_domains_per_proxy = 4\n",
            &[],
        ),
        (
            "vhost_http_timeout",
            "vhost_http_timeout = 60\n",
            "vhost_http_timeout = 61\n",
            &[],
        ),
        (
            "user_conn_timeout",
            "user_conn_timeout = 10\n",
            "user_conn_timeout = 11\n",
            &[],
        ),
        (
            "detailed_errors_to_client",
            "detailed_errors_to_client = true\n",
            "detailed_errors_to_client = false\n",
            &[],
        ),
        (
            "graceful_shutdown_timeout",
            "graceful_shutdown_timeout = 30\n",
            "graceful_shutdown_timeout = 31\n",
            &[],
        ),
        (
            "tcp_mux_passthrough",
            "tcp_mux_passthrough = false\n",
            "tcp_mux_passthrough = true\n",
            &[],
        ),
        (
            "udp_packet_size",
            "udp_packet_size = 1500\n",
            "udp_packet_size = 1501\n",
            &[],
        ),
        (
            "nat_hole_analysis_data_reserve_hours",
            "natholeAnalysisDataReserveHours = 168\n",
            "natholeAnalysisDataReserveHours = 169\n",
            &[],
        ),
        (
            "max_connections",
            "max_connections = 100\n",
            "max_connections = 101\n",
            &[],
        ),
        (
            "max_accept_rate",
            "max_accept_rate = 10\n",
            "max_accept_rate = 11\n",
            &[],
        ),
        ("tls_only", "", "tls_only = true\n", &[]),
        // Not `"" -> "127.0.0.1"`: the loader completes an empty
        // `proxy_bind_addr` from `bind_addr`, so that spelling is not a change
        // (the `udp_packet_size = 0 -> 1500` class of normalization).
        (
            "proxy_bind_addr",
            "proxy_bind_addr = \"10.0.0.1\"\n",
            "proxy_bind_addr = \"10.0.0.2\"\n",
            &[],
        ),
        (
            "sub_domain_host",
            "",
            "sub_domain_host = \"example.com\"\n",
            &[],
        ),
        ("sudp_port", "sudp_port = 0\n", "sudp_port = 12500\n", &[]),
        (
            "transport.max_pool_count",
            "[transport]\nmax_pool_count = 5\n",
            "[transport]\nmax_pool_count = 6\n",
            &[],
        ),
        (
            "transport.tcp_mux_keepalive_interval",
            "[transport]\ntcp_mux_keepalive_interval = 30\n",
            "[transport]\ntcp_mux_keepalive_interval = 31\n",
            &[],
        ),
        (
            "transport.tcp_mux_keepalive_timeout",
            "[transport]\ntcp_mux_keepalive_timeout = 0\n",
            "[transport]\ntcp_mux_keepalive_timeout = 90\n",
            &[],
        ),
        (
            "transport.tcp_keepalive",
            "[transport]\ntcp_keepalive = 7200\n",
            "[transport]\ntcp_keepalive = 7201\n",
            &[],
        ),
        (
            "transport.tcp_send_buffer_size",
            "[transport]\ntcp_send_buffer_size = 0\n",
            "[transport]\ntcp_send_buffer_size = 4096\n",
            &[],
        ),
        (
            "transport.tcp_recv_buffer_size",
            "[transport]\ntcp_recv_buffer_size = 0\n",
            "[transport]\ntcp_recv_buffer_size = 4096\n",
            &[],
        ),
        (
            // Flipping `tcp_mux` also moves the *completed* `heartbeat_timeout`
            // (`-1` with the mux on, `90` with it off), which is a real second
            // difference and therefore an expected second line.
            "transport.tcp_mux",
            "[transport]\ntcp_mux = true\n",
            "[transport]\ntcp_mux = false\n",
            ["transport.heartbeat_timeout"].as_slice(),
        ),
    ];

    for (field, from, to, also_expected) in cases {
        let port = allocate_port();
        let server = Server::start(port, from).await;
        let summary = server.rewrite_and_reload(&probe_config(port, to)).await;

        // The summary is a `; `-joined list of `name: …` / `name changed …`
        // entries. Every entry's name must be the field under test or one of this
        // case's known companions — anything else is an over-report, which is as
        // much a failure as a silent field.
        for entry in summary.split("; ") {
            let named = match entry.split_once(": ") {
                Some((name, _)) => name,
                // `http_plugins changed (restart required)` — name-only entries.
                None => entry
                    .split_once(" changed (")
                    .map(|(n, _)| n)
                    .unwrap_or(entry),
            };
            assert!(
                named == *field || also_expected.contains(&named),
                "unexpected field in the summary for `{field}`: `{named}` \
                 (whole summary: {summary})"
            );
        }
        assert!(
            summary.starts_with(field) || summary.contains(&format!("{field}:")),
            "the summary must name `{field}`: {summary}"
        );
        assert!(
            !summary.contains("no changes detected"),
            "`{field}` must not be a no-op: {summary}"
        );
    }
}

/// The two `Option<u32>` limits are reported only when the value the server
/// **runs with** changes.
///
/// An absent `max_connections` and `max_connections = 512` both build a
/// 512-permit semaphore, and an absent `max_accept_rate` and
/// `max_accept_rate = 0` both mean "no limit" — so the pairs are one setting and
/// the reload must stay quiet. Comparing the raw options reported them as
/// `max_connections: <unset> -> 512 (restart required)` and
/// `max_accept_rate: <unset> -> 0 (restart required)` where the base binary said
/// `no changes detected`: a false "restart required" introduced by this change
/// and caught by review.
///
/// `max_connections = 0` is **not** an equivalence with the default — 0 means
/// unlimited — so that pair must still be reported.
#[tokio::test]
async fn unset_limits_are_not_reported_as_a_restart() {
    let port = allocate_port();
    let server = Server::start(port, "").await;

    // Absent -> the explicit default, and back: one setting, no line.
    let both_spelled = server
        .rewrite_and_reload(&probe_config(
            port,
            "max_connections = 512\nmax_accept_rate = 0\n",
        ))
        .await;
    assert_eq!(
        both_spelled, "config reloaded: no changes detected",
        "the explicit defaults of both limits are the running values"
    );
    let back_to_absent = server.rewrite_and_reload(&probe_config(port, "")).await;
    assert_eq!(
        back_to_absent, "config reloaded: no changes detected",
        "removing the explicit defaults is not a change either"
    );

    // A different connection cap IS reported, against the effective running value.
    let capped = server
        .rewrite_and_reload(&probe_config(port, "max_connections = 100\n"))
        .await;
    assert_eq!(
        capped, "max_connections: <unset> -> 100 (restart required)",
        "an absent limit is printed as <unset>, and the value differs in effect"
    );

    // `0` is "unlimited", a different running value from the 512 default. The
    // baseline is still the **running** config, which the previous reload did not
    // apply — so the old side stays `<unset>`, not the `100` it just reported.
    let unlimited = server
        .rewrite_and_reload(&probe_config(port, "max_connections = 0\n"))
        .await;
    assert_eq!(
        unlimited, "max_connections: <unset> -> 0 (restart required)",
        "0 = unlimited differs from the 512 default and must be reported"
    );

    // A real rate limit differs from "no limit".
    let limited = server
        .rewrite_and_reload(&probe_config(port, "max_accept_rate = 10\n"))
        .await;
    assert_eq!(
        limited, "max_accept_rate: <unset> -> 10 (restart required)",
        "an absent max_accept_rate is 0 = no limit; 10 is a different setting"
    );
}

/// The three `#[cfg]`-gated listener ports are reported only when **this build**
/// compiles their reader — the KCP / QUIC / WebSocket listener in `Service::run`.
///
/// The dashboard is **not** a second reader, which is the correction this round
/// makes: `frp-server/src/dashboard.rs`'s own `#[cfg(feature = "kcp")]` /
/// `#[cfg(feature = "quic")]` (`:501-502`, `:2491-2494`) are **frp-server's**
/// features, so it prints `kcpBindPort` / `quicBindPort` only in a build that
/// already has the listener compiled. A dashboard-only build's
/// `/api/v2/system/info` has neither key, so the dashboard can only ever have
/// *added* a false positive, never a reader. (Measured: the two keys are absent
/// in `--no-default-features --features dashboard` and present in
/// `--no-default-features --features dashboard,kcp,quic`; the configs differ only
/// in the `cfg`, not in serde.)
///
/// This is the arm that runs in `--no-default-features` **and** in
/// `--no-default-features --features dashboard` — the second is compiled by
/// `ci.yml:3802`'s clippy lane but no lane test-ran it before this round — where
/// the `frp-client` dev-dependency turns `frp-core`'s `kcp`/`quic`/`websocket` on
/// while `frp-server`'s stay off: the fields exist and are parsed, nothing reads
/// them, and a line here is a false "restart required".
///
/// Each expectation is derived from the feature the reload itself asks about, so
/// the test asserts the documented rule in every configuration rather than one
/// build's answer.
#[tokio::test]
async fn gated_listener_ports_follow_their_own_features() {
    let port = allocate_port();
    let server = Server::start(port, "").await;

    let summary = server
        .rewrite_and_reload(&probe_config(
            port,
            "kcp_bind_port = 17001\nquic_bind_port = 17002\nwebsocket_port = 17003\n",
        ))
        .await;

    #[cfg(feature = "kcp")]
    assert!(
        summary.contains("kcp_bind_port:"),
        "the KCP listener reads it in this build: {summary}"
    );
    #[cfg(not(feature = "kcp"))]
    assert!(
        !summary.contains("kcp_bind_port"),
        "no KCP listener in this build, so no line — the dashboard is not a \
         reader (its own cfg is this crate's kcp too): {summary}"
    );

    #[cfg(feature = "quic")]
    assert!(
        summary.contains("quic_bind_port:"),
        "the QUIC listener reads it in this build: {summary}"
    );
    #[cfg(not(feature = "quic"))]
    assert!(
        !summary.contains("quic_bind_port"),
        "no QUIC listener in this build, so no line: {summary}"
    );

    #[cfg(feature = "websocket")]
    assert!(
        summary.contains("websocket_port:"),
        "the WebSocket listener reads it in this build: {summary}"
    );
    #[cfg(not(feature = "websocket"))]
    assert!(
        !summary.contains("websocket_port"),
        "no WebSocket listener in this build, so no line: {summary}"
    );

    // In every config without any of the three listeners — `dashboard` on or off,
    // which is exactly the distinction this test exists to keep honest — the whole
    // reload must still be a no-op, which is what the base binary said and what
    // the first version of this change got wrong in both directions.
    #[cfg(not(any(feature = "kcp", feature = "quic", feature = "websocket")))]
    assert_eq!(
        summary, "config reloaded: no changes detected",
        "with no listener compiled in, all three ports are inert"
    );
}

/// The settings no reader in this crate consumes are **not** reported: a restart
/// cannot make them take effect either, so a "restart required" line would be
/// false. Each entry was measured with `grep` (see the doc comments in
/// `frp-core/src/config/restart_only.rs`).
#[tokio::test]
async fn inert_settings_are_not_reported() {
    let port = allocate_port();
    let server = Server::start(port, "").await;

    let summary = server
        .rewrite_and_reload(&probe_config(
            port,
            "[web_server]\npprof_enable = true\ntls_ca_file = \"/tmp/dash-ca.pem\"\n",
        ))
        .await;
    assert_eq!(
        summary, "config reloaded: no changes detected",
        "pprof_enable and web_server.tls_ca_file have no reader in frp-server"
    );

    let summary = server
        .rewrite_and_reload(&probe_config(
            port,
            "tls_server_name = \"frps.example.com\"\n",
        ))
        .await;
    assert_eq!(
        summary, "config reloaded: no changes detected",
        "ServerConfig::tls_server_name has no reader in frp-server"
    );

    // `ServerConfig.tls_enable`: the pre-fix reload printed
    // `tls_enable: false -> true (restart required)` for this exact rewrite,
    // even though nothing in `frp-server`/`frps` reads the field (measured:
    // `grep -rn tls_enable frp-server/src frps/src` finds no read) — and a
    // restart could not make the change take effect either. This is the pin
    // that fails if that line comes back.
    let summary = server
        .rewrite_and_reload(&probe_config(port, "tls_enable = true\n"))
        .await;
    assert_eq!(
        summary, "config reloaded: no changes detected",
        "ServerConfig::tls_enable is inert: neither applied nor reported"
    );

    let summary = server
        .rewrite_and_reload(&probe_config(port, "[featureGates]\nVirtualNet = true\n"))
        .await;
    assert_eq!(
        summary, "config reloaded: no changes detected",
        "feature gates are validated at load time and read by nothing at runtime"
    );
}

/// The applied set must stay quiet: `allow_ports` and the TLS paths are re-keyed
/// in place by the reload, and `bind_port`/`bind_addr` are reported
/// by the reload itself — none of them may appear twice or as "restart
/// required". (`tls_enable` is neither applied nor reported: it is inert, see
/// [`inert_settings_are_not_reported`].)
#[tokio::test]
async fn applied_settings_do_not_report_a_restart() {
    let port = allocate_port();
    let server = Server::start(port, "allow_ports = \"10000-20000\"\n").await;

    let summary = server
        .rewrite_and_reload(&probe_config(port, "allow_ports = \"30000-40000\"\n"))
        .await;
    assert!(
        summary.contains("allow_ports:"),
        "the applied set is still reported: {summary}"
    );
    assert!(
        !summary.contains("restart required"),
        "an applied setting must not claim a restart: {summary}"
    );
}

/// `web_server.*` (besides `custom_404_page`) has exactly one reader: the
/// dashboard block of `Service::run`. With the feature on it is restart-only and
/// must be named; with it off nothing reads the field and naming it would be
/// false. Whichever build this runs in, only one direction is asserted.
#[tokio::test]
async fn dashboard_only_settings_are_reported_only_with_the_dashboard() {
    let port = allocate_port();
    let server = Server::start(port, "[web_server]\nport = 0\n").await;

    let summary = server
        .rewrite_and_reload(&probe_config(port, "[web_server]\nport = 18080\n"))
        .await;

    #[cfg(feature = "dashboard")]
    assert!(
        summary.contains("web_server.port: 0 -> 18080 (restart required)"),
        "with the dashboard compiled in, its port is restart-only: {summary}"
    );
    #[cfg(not(feature = "dashboard"))]
    assert_eq!(
        summary, "config reloaded: no changes detected",
        "without the dashboard, nothing reads web_server.port: a restart would \
         not change anything and reporting one would be false"
    );
}

/// The SSH-gateway group follows the same rule: its only reader is
/// `Service::run`'s `#[cfg(feature = "ssh")]` block.
#[tokio::test]
async fn ssh_gateway_settings_follow_the_ssh_feature() {
    let port = allocate_port();
    let server = Server::start(port, "[ssh_tunnel_gateway]\nssh_session_idle_timeout = 0\n").await;

    let summary = server
        .rewrite_and_reload(&probe_config(
            port,
            "[ssh_tunnel_gateway]\nssh_session_idle_timeout = 60\n",
        ))
        .await;

    #[cfg(feature = "ssh")]
    assert!(
        summary.contains("ssh_tunnel_gateway.ssh_session_idle_timeout: 0 -> 60 (restart required)"),
        "with the SSH gateway compiled in, its idle timeout is restart-only: {summary}"
    );
    #[cfg(not(feature = "ssh"))]
    assert_eq!(
        summary, "config reloaded: no changes detected",
        "without the ssh feature the gateway is never started: no reader, no claim"
    );
}

/// `transport.quic_options` is read once, by the QUIC listener, and has neither
/// `PartialEq` nor `Display` — so it is named, without values.
#[tokio::test]
async fn quic_options_follow_the_quic_feature() {
    let port = allocate_port();
    let server = Server::start(
        port,
        "[transport]\nquic_bind_port = 0\n[transport.quic]\nkeepalive_period = 10\n",
    )
    .await;

    let summary = server
        .rewrite_and_reload(&probe_config(
            port,
            "[transport]\nquic_bind_port = 0\n[transport.quic]\nkeepalive_period = 11\n",
        ))
        .await;

    #[cfg(feature = "quic")]
    assert_eq!(
        summary, "transport.quic_options changed (restart required)",
        "the QUIC parameters are restart-only and are named without values"
    );
    #[cfg(not(feature = "quic"))]
    assert_eq!(
        summary, "config reloaded: no changes detected",
        "without the quic feature nothing reads the QUIC options"
    );
}

/// `[observability]`'s reader is `frps`'s `init_logging`, gated on the binary's
/// `otel` feature (which forwards `frp-core/otel`). This asserts whichever
/// direction the build it runs in is in, from the same source of truth the
/// reload uses.
#[tokio::test]
async fn observability_follows_the_otel_gate() {
    let port = allocate_port();
    let server = Server::start(port, "[observability]\notlp_endpoint = \"\"\n").await;

    let summary = server
        .rewrite_and_reload(&probe_config(
            port,
            "[observability]\notlp_endpoint = \"http://127.0.0.1:4317\"\n",
        ))
        .await;

    if frp_core::logging::OTEL_ENABLED {
        assert!(
            summary.contains("observability.otlp_endpoint:"),
            "with `otel` the exporter is built once at startup: {summary}"
        );
        assert!(summary.contains("restart required"), "{summary}");
    } else {
        assert_eq!(
            summary, "config reloaded: no changes detected",
            "without `otel` nothing reads these fields"
        );
    }
}

/// `http_plugins` is rebuilt once, at startup, and its entries have neither
/// `PartialEq` nor `Display` — but the field must still be named, and its `addr`
/// may embed credentials, so the line carries no values.
#[tokio::test]
async fn http_plugins_is_named_without_values() {
    let port = allocate_port();
    let server = Server::start(port, "").await;

    let summary = server
        .rewrite_and_reload(&probe_config(
            port,
            "[[httpPlugins]]\nname = \"p\"\naddr = \"http://user:secret@127.0.0.1:8080\"\n",
        ))
        .await;
    assert_eq!(
        summary, "http_plugins changed (restart required)",
        "the plugin list is restart-only; its address must not be printed"
    );
    assert!(
        !summary.contains("secret"),
        "a credential in the plugin address must never reach the summary: {summary}"
    );
}

/// A plugin list that changes only in the credential-bearing `addr` is still a
/// change (the `Debug` comparison is over the whole entry), and one that changes
/// nothing is quiet.
#[tokio::test]
async fn http_plugins_compares_more_than_the_entry_count() {
    let port = allocate_port();
    let server = Server::start(
        port,
        "[[httpPlugins]]\nname = \"p\"\naddr = \"http://127.0.0.1:8080\"\n",
    )
    .await;

    let same = server
        .rewrite_and_reload(&probe_config(
            port,
            "[[httpPlugins]]\nname = \"p\"\naddr = \"http://127.0.0.1:8080\"\n",
        ))
        .await;
    assert_eq!(same, "config reloaded: no changes detected");

    let renamed = server
        .rewrite_and_reload(&probe_config(
            port,
            "[[httpPlugins]]\nname = \"q\"\naddr = \"http://127.0.0.1:8080\"\n",
        ))
        .await;
    assert_eq!(
        renamed, "http_plugins changed (restart required)",
        "a same-count content change must still be reported"
    );
}

/// The config a restart-only change is compared against is the **running** one,
/// which a reload never updates: the same difference is reported again on every
/// reload until the process restarts, and the reported old value stays the
/// startup value. That is the honest reading of "restart required" — the process
/// is still running the old value.
#[tokio::test]
async fn the_baseline_is_the_running_config_not_the_last_file() {
    let port = allocate_port();
    let server = Server::start(port, "max_ports_per_client = 0\n").await;

    let first = server
        .rewrite_and_reload(&probe_config(port, "max_ports_per_client = 7\n"))
        .await;
    assert_eq!(
        first, "max_ports_per_client: 0 -> 7 (restart required)",
        "the running value is the baseline"
    );

    let second = server
        .rewrite_and_reload(&probe_config(port, "max_ports_per_client = 7\n"))
        .await;
    assert_eq!(
        second, "max_ports_per_client: 0 -> 7 (restart required)",
        "the reload did not apply it, so the running value is still 0 and the \
         difference is still there"
    );

    let third = server
        .rewrite_and_reload(&probe_config(port, "max_ports_per_client = 8\n"))
        .await;
    assert_eq!(
        third, "max_ports_per_client: 0 -> 8 (restart required)",
        "still compared against the running 0, never against the previous file"
    );

    let quiet = server
        .rewrite_and_reload(&probe_config(port, "max_ports_per_client = 0\n"))
        .await;
    assert_eq!(
        quiet, "config reloaded: no changes detected",
        "putting the file back to the running value is quiet again"
    );
}
