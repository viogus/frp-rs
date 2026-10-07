use super::normalize::{expand_env_vars, normalize_client_config, normalize_server_config};
use super::strict::{check_strict, levenshtein};
use super::*;
use crate::feature_gate::VIRTUAL_NET;
use std::io::Write;

#[test]
fn test_parse_client_toml() {
    let toml_str = r#"
server_addr = "127.0.0.1"
server_port = 7000
token = "my-token"

[[proxies]]
name = "test-tcp"
type = "tcp"
local_ip = "127.0.0.1"
local_port = 80
remote_port = 7001
"#;
    let cfg: ClientConfig = toml::from_str(toml_str).unwrap();
    assert_eq!(cfg.proxies.len(), 1);
    assert_eq!(cfg.server_addr, "127.0.0.1");
    assert_eq!(cfg.server_port, 7000);
    assert_eq!(cfg.token, "my-token");
    let p = &cfg.proxies[0];
    assert_eq!(p.name, "test-tcp");
    assert_eq!(p.proxy_type, "tcp");
    assert_eq!(p.local_ip, "127.0.0.1");
    assert_eq!(p.local_port, 80);
    assert_eq!(p.remote_port, 7001);
}

#[test]
fn test_parse_client_store_config() {
    let toml_str = r#"
server_addr = "127.0.0.1"
server_port = 7000

[store]
path = "./frpc_store.json"
"#;
    let cfg: ClientConfig = load_client_config_from_str(toml_str).unwrap();
    assert_eq!(
        cfg.store.as_ref().unwrap().path,
        "./frpc_store.json",
        "[store] path should be parsed"
    );
}

#[test]
fn test_parse_client_store_defaults_to_none() {
    let cfg: ClientConfig = load_client_config_from_str("server_addr = '127.0.0.1'").unwrap();
    assert!(
        cfg.store.is_none(),
        "store defaults to None without [store]"
    );
}

#[test]
fn test_xtcp_visitor_defaults_to_quic() {
    let visitor = VisitorConfig::default();
    assert_eq!(
        visitor.protocol, "quic",
        "XTCP visitor must default to quic (Go frp v0.70.1)"
    );
}

#[test]
fn test_xtcp_visitor_empty_protocol_normalizes_to_quic() {
    // Go util.EmptyOr(Protocol, "quic") applied in Complete() BEFORE
    // validation (pkg/config/v1/visitor.go:160 + pkg/config/load.go): an
    // explicitly-empty `protocol = ""` must normalize to "quic" the same
    // way a missing field does, not stay "" (which would then be rejected
    // by the kcp/quic validation as a third, unknown protocol).
    let toml = r#"
[common]
server_addr = "127.0.0.1"
server_port = 7000
token = "t"

[[visitors]]
name = "v"
type = "xtcp"
server_name = "s"
bind_port = 7000
protocol = ""
"#;
    let mut cfg = load_client_config_from_str(toml).expect("config loads");
    let visitor = cfg
        .visitors
        .iter()
        .find(|v| v.name == "v")
        .expect("visitor");
    assert_eq!(
        visitor.protocol, "quic",
        "empty protocol must normalize to quic"
    );
    // And it passes validation (a literal "" would be rejected).
    super::loader::validate_client_config(&mut cfg).expect("empty protocol validates as quic");
}

#[test]
fn test_visitor_config_validation_matches_go() {
    // Round 10 (MEDIUM): Go validation/visitor.go:42-63 — name/serverName
    // required, bindPort==0 rejected (negative = no-bind passes), XTCP
    // protocol restricted to kcp/quic. Mirrored in validate_client_config.
    let mk = |name: &str, server: &str, port: i32, proto: &str| VisitorConfig {
        name: name.into(),
        server_name: server.into(),
        bind_port: port,
        protocol: proto.into(),
        visitor_type: "xtcp".into(),
        ..Default::default()
    };
    let err = |v: VisitorConfig| {
        super::loader::validate_client_config(&mut ClientConfig {
            visitors: vec![v],
            ..Default::default()
        })
        .unwrap_err()
    };
    // Go interpolates the name unquoted (`visitor %s: %v`). The empty-name arm
    // keeps frp-rs's own wording: Go prints `visitor : name is required` there
    // (measured), a disclosed divergence left for the coordinator.
    assert_eq!(
        err(mk("", "s", 7000, "kcp")),
        "visitor config: name is required"
    );
    assert_eq!(
        err(mk("v", "", 7000, "kcp")),
        "visitor v: server name is required"
    );
    assert_eq!(
        err(mk("v", "s", 0, "kcp")),
        "visitor v: bind port is required"
    );
    assert_eq!(
        err(mk("v", "s", 7000, "tcp")),
        "visitor 'v': protocol should be kcp or quic"
    );
    // Negative bind_port is Go's no-bind sentinel — must pass validation.
    let mut ok = mk("v", "s", -1, "quic");
    ok.bind_port = -1;
    assert!(super::loader::validate_client_config(&mut ClientConfig {
        visitors: vec![ok],
        ..Default::default()
    })
    .is_ok());
}

#[test]
fn test_unknown_visitor_type_rejected() {
    // Round-8 blocker (fix 4): Go v0.71.0 dispatches visitors by a type
    // switch over stcp/sudp/xtcp — anything else, including empty, fails
    // ("unknown visitor config type"). A `type = "typo"` visitor used to
    // load silently and never connect.
    let mk = |visitor_type: &str| VisitorConfig {
        name: "v".into(),
        server_name: "s".into(),
        bind_port: 7000,
        visitor_type: visitor_type.into(),
        ..Default::default()
    };
    let err = |v: VisitorConfig| {
        super::loader::validate_client_config(&mut ClientConfig {
            visitors: vec![v],
            ..Default::default()
        })
        .unwrap_err()
    };
    assert_eq!(err(mk("typo")), "visitor 'v': unknown visitor type 'typo'");
    // Empty type is rejected too (serde default "").
    assert_eq!(err(mk("")), "visitor 'v': unknown visitor type ''");
    // All three valid types pass.
    for t in ["stcp", "sudp", "xtcp"] {
        assert!(
            super::loader::validate_client_config(&mut ClientConfig {
                visitors: vec![mk(t)],
                ..Default::default()
            })
            .is_ok(),
            "visitor type {t} must be accepted"
        );
    }
}

#[test]
fn test_merge_store_items_overlays_by_name() {
    let base = ClientConfig {
        server_addr: "127.0.0.1".into(),
        proxies: vec![
            ProxyConfig {
                name: "shared".into(),
                proxy_type: "tcp".into(),
                local_port: 1000,
                ..Default::default()
            },
            ProxyConfig {
                name: "config-only".into(),
                proxy_type: "tcp".into(),
                local_port: 2000,
                ..Default::default()
            },
        ],
        visitors: vec![VisitorConfig {
            name: "shared-visitor".into(),
            visitor_type: "stcp".into(),
            bind_port: 3000,
            ..Default::default()
        }],
        ..Default::default()
    };
    let store_proxies = vec![ProxyConfig {
        name: "shared".into(),
        proxy_type: "tcp".into(),
        local_port: 4000,
        enabled: false,
        ..Default::default()
    }];
    let store_visitors = vec![VisitorConfig {
        name: "store-visitor".into(),
        visitor_type: "xtcp".into(),
        bind_port: 5000,
        ..Default::default()
    }];

    let merged = base.merge_store_items(store_proxies, store_visitors);
    let shared = merged.proxies.iter().find(|p| p.name == "shared").unwrap();
    assert_eq!(shared.local_port, 4000, "store entry overlays config entry");
    assert!(
        merged.proxies.iter().any(|p| p.name == "config-only"),
        "config-only proxy is preserved"
    );
    assert!(
        merged.visitors.iter().any(|v| v.name == "store-visitor"),
        "store visitor is added"
    );
}

#[test]
fn test_go_format_server_toml() {
    let toml_str = r#"
[common]
bind_addr = "0.0.0.0"
bind_port = 7000
auth_method = "token"
token = "my-token"
log_file = "./frps.log"
log_level = "info"
"#;
    let cfg: ServerConfig = load_server_config_from_str(toml_str).unwrap();
    assert_eq!(cfg.bind_port, 7000);
    assert_eq!(cfg.auth.token, "my-token");
    assert_eq!(cfg.auth.method, "token");
}

#[test]
fn test_go_camelcase_server_port_aliases() {
    // Go frp uses camelCase: bindPort, kcpBindPort, vhostHTTPPort, etc.
    // These must map to Rust snake_case fields via serde aliases.
    let toml_str = r#"
bindPort = 7000
kcpBindPort = 7100
vhostHTTPPort = 10080
vhostHTTPSPort = 10443
quicBindPort = 7200
sudpPort = 7300
tcpmuxHTTPConnectPort = 7400
websocketPort = 7500
proxyBindAddr = "10.0.0.1"
auth.method = "token"
auth.token = "test"
"#;
    let cfg: ServerConfig = load_server_config_from_str(toml_str).unwrap();
    assert_eq!(cfg.bind_port, 7000, "bindPort");
    #[cfg(feature = "kcp")]
    assert_eq!(cfg.kcp_bind_port, 7100, "kcpBindPort");
    assert_eq!(cfg.vhost_http_port, 10080, "vhostHTTPPort");
    assert_eq!(cfg.vhost_https_port, 10443, "vhostHTTPSPort");
    #[cfg(feature = "quic")]
    assert_eq!(cfg.quic_bind_port, 7200, "quicBindPort");
    assert_eq!(cfg.sudp_port, 7300, "sudpPort");
    assert_eq!(cfg.tcpmux_httpconnect_port, 7400, "tcpmuxHTTPConnectPort");
    #[cfg(feature = "websocket")]
    assert_eq!(cfg.websocket_port, 7500, "websocketPort");
    assert_eq!(cfg.proxy_bind_addr, "10.0.0.1", "proxyBindAddr");
}

/// The `#[cfg(feature = …)]`-gated `ServerConfig` listener ports, each with the
/// two spellings serde accepts (a bare field and its Go-inspired `alias`) and the
/// feature that compiles the field.
///
/// This is the whole class. `frp-core/src/config/server.rs` is the only server
/// config struct with feature-gated fields, and it holds exactly these three; no
/// client config struct has any (`frp-core/src/config/client.rs` carries no
/// `#[cfg(feature …)]` at all), so `known_client_keys()` has nothing to go stale
/// on. Both facts are pinned by
/// `feature_gated_server_field_set_matches_the_pinned_scope` and the
/// `feature_gated_server_port_*` tests below.
const FEATURE_GATED_SERVER_PORTS: [(&str, &str, &str); 3] = [
    ("kcp_bind_port", "kcpBindPort", "kcp"),
    ("quic_bind_port", "quicBindPort", "quic"),
    ("websocket_port", "websocketPort", "websocket"),
];

/// Write `body` into its own temp dir and load it through the entry point the
/// `frps` startup paths use, with **strict** mode on.
///
/// Strict mode is the interesting arm: it is the default for `frps -c`, and it is
/// where the key is *accepted* in both build shapes (see
/// `feature_gated_server_ports_stay_known_to_strict_mode_in_every_build`), so the
/// load succeeding here is part of the pin rather than an accident of the test.
fn load_server_with_presence(body: &str) -> (ServerConfig, ConfigPresence) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("frps.toml");
    std::fs::write(&path, body).unwrap();
    load_server_config_uncompleted_with_presence(path.to_str().unwrap(), true)
        .unwrap_or_else(|e| panic!("strict mode must load this:\n{e}\nbody:\n{body}"))
}

/// The whole-text pin for one of the six gated-listener diagnostics (three
/// field-less, three field-present-no-reader): the text is the clause array
/// **joined**, so it is defined once and a reworded clause cannot leave a copied
/// literal behind in a test; the array still carries both clauses; and the record
/// names the key it reports.
///
/// The two clause sets are `#[cfg]`-exclusive per port, so every build shape
/// instantiates this helper at least once and it needs no gate of its own.
fn assert_unhonoured_diagnostic(clauses: &[&str], warning: &str, key: &str) {
    assert_eq!(clauses.len(), 2, "{key}: clause count");
    assert!(clauses.iter().all(|c| !c.is_empty()), "{key}: empty clause");
    assert_eq!(
        warning,
        clauses.join(" ").as_str(),
        "{key}: text is the clause join"
    );
    assert!(warning.contains(key), "{key}: the record must name `{key}`");
}

/// The three feature-gated ports, all reported **Absent** — the caller shape
/// `frp-server` built without any of the three listeners reports through
/// `gated_listener_port_readers`.
fn no_gated_listener_readers() -> GatedListenerPortReaders {
    GatedListenerPortReaders::from_features(false, false, false)
}

/// The same three ports, all reported **Present** — the ordinary `frps` default
/// build's answer.
fn all_gated_listener_readers() -> GatedListenerPortReaders {
    GatedListenerPortReaders::from_features(true, true, true)
}

// ─── kcp_bind_port / kcpBindPort (the `kcp` feature) ─────────────────────

/// Enabled direction: the field exists, so strict mode accepting the key is
/// *correct* and the port reaches its reader (`frp-server` creates the KCP
/// listener when the port is `> 0`). "This build warns about it" is now a
/// compilable statement — the field-present diagnostic exists under
/// `#[cfg(feature = "kcp")]` — but it must be **silent** when the caller reports
/// the listener present. The opposite answer (the hand-named inner-feature
/// shape) is pinned by
/// [`feature_gated_server_port_kcp_enabled_without_a_reader_reports_the_port`].
#[cfg(feature = "kcp")]
#[test]
fn feature_gated_server_port_kcp_enabled_honours_the_port() {
    for (key, expected) in [("kcp_bind_port", 7100u16), ("kcpBindPort", 7101)] {
        let (cfg, presence) =
            load_server_with_presence(&format!("bind_port = 7000\n{key} = {expected}\n"));
        assert_eq!(cfg.kcp_bind_port, expected, "`{key}` must reach the field");
        assert!(
            presence
                .unhonoured_server_feature_key_records(all_gated_listener_readers())
                .is_empty(),
            "a build whose caller reports the KCP listener must stay silent; body key `{key}`"
        );
    }
}

/// **The hand-named inner-feature shape.** `frp-core`'s `kcp` feature is on — the
/// field deserializes, strict mode accepts it and `frps --help` advertises
/// `--kcp-bind-port` — while the crate that owns the listener
/// (`frp-server/kcp`) is off, so the caller reports
/// [`ListenerPortReader::Absent`] and the port the file names stays closed.
///
/// This is exactly the feature resolution of
/// `cargo build -p frps --no-default-features --features tiny,frp-core/kcp`
/// (and of `cargo test -p frp-server --no-default-features --all-targets`, whose
/// `frp-client` dev-dependency turns `frp-core/kcp` on while `frp-server/kcp` is
/// off). Before the reader was threaded through, this load was silent in both
/// halves.
#[cfg(feature = "kcp")]
#[test]
fn feature_gated_server_port_kcp_enabled_without_a_reader_reports_the_port() {
    for (key, port) in [("kcp_bind_port", "7100"), ("kcpBindPort", "7101")] {
        for body in [
            format!("bind_port = 7000\n{key} = {port}\n"),
            format!("bind_port = 7000\n[common]\n{key} = {port}\n"),
        ] {
            let (cfg, presence) = load_server_with_presence(&body);
            assert_eq!(
                cfg.kcp_bind_port,
                port.parse::<u16>().unwrap(),
                "body:\n{body}"
            );
            assert!(
                presence.server_kcp_bind_port_unhonoured,
                "`{key}` asks for a listener this build cannot create; body:\n{body}"
            );
            assert_eq!(
                presence.unhonoured_server_feature_key_records(no_gated_listener_readers()),
                vec![SERVER_KCP_BIND_PORT_UNHONOURED_NO_READER_WARNING.clone()],
                "`{key}` must produce exactly the field-present record; body:\n{body}"
            );
        }
    }
    assert_unhonoured_diagnostic(
        &SERVER_KCP_BIND_PORT_UNHONOURED_NO_READER_CLAUSES,
        SERVER_KCP_BIND_PORT_UNHONOURED_NO_READER_WARNING.as_str(),
        "kcp_bind_port",
    );
}

/// Disabled direction: `ServerConfig` has no `kcp_bind_port` field, so serde
/// drops the key and `frp-server` never compiles the listener. Strict mode still
/// **accepts** the key — it is in `known_server_keys()` unconditionally, the
/// deliberate "never a false 400" direction — so before this flag the load was
/// completely silent about a port that will stay closed.
///
/// The reader argument is pinned **both ways** here: the field-less direction
/// must warn even when the caller reports a listener, because no caller can
/// conjure a field this build did not compile (`frp-server/kcp = ["frp-core/kcp"]`
/// makes that combination unreachable in practice; the assertion is what makes
/// "never weaken the field-less half" a compilable statement).
#[cfg(not(feature = "kcp"))]
#[test]
fn feature_gated_server_port_kcp_disabled_reports_the_dropped_port() {
    for (key, port) in [("kcp_bind_port", "7100"), ("kcpBindPort", "7101")] {
        for body in [
            format!("bind_port = 7000\n{key} = {port}\n"),
            format!("bind_port = 7000\n[common]\n{key} = {port}\n"),
        ] {
            let (cfg, presence) = load_server_with_presence(&body);
            assert_eq!(cfg.bind_port, 7000, "body:\n{body}");
            assert!(
                presence.server_kcp_bind_port_unhonoured,
                "`{key}` asks for a listener this build cannot create; body:\n{body}"
            );
            for readers in [no_gated_listener_readers(), all_gated_listener_readers()] {
                assert_eq!(
                    presence.unhonoured_server_feature_key_records(readers),
                    vec![SERVER_KCP_BIND_PORT_UNHONOURED_WARNING.clone()],
                    "a field this build did not compile is unread whatever the caller \
                     reports; body:\n{body}"
                );
            }
        }
    }
    assert_unhonoured_diagnostic(
        &SERVER_KCP_BIND_PORT_UNHONOURED_CLAUSES,
        SERVER_KCP_BIND_PORT_UNHONOURED_WARNING.as_str(),
        "kcp_bind_port",
    );
}

/// `0` is the documented "disabled" value for every one of the three ports, it
/// is what the field's own default is, and a capable build's reader gates on
/// `> 0` — so a written `0` is fully honoured in every shape and must not
/// produce a record. An absent key is not a request either.
///
/// Runs in every build shape now that the presence flag is computed
/// unconditionally: the field-present shape reads the real field, the field-less
/// shape reads the dropped key, and neither is a request.
#[test]
fn feature_gated_server_port_kcp_disabled_is_silent_for_zero_or_absent() {
    for body in [
        "bind_port = 7000\n".to_string(),
        "bind_port = 7000\nkcp_bind_port = 0\n".to_string(),
        "bind_port = 7000\nkcpBindPort = 0\n".to_string(),
        "bind_port = 7000\n[common]\nkcp_bind_port = 0\n".to_string(),
    ] {
        let (_cfg, presence) = load_server_with_presence(&body);
        assert!(!presence.server_kcp_bind_port_unhonoured, "body:\n{body}");
    }
}

// ─── quic_bind_port / quicBindPort (the `quic` feature) ──────────────────

/// The `quic` twin of `feature_gated_server_port_kcp_enabled_honours_the_port`:
/// the field exists and reaches its reader, and the caller's `Present` answer
/// keeps the record silent.
#[cfg(feature = "quic")]
#[test]
fn feature_gated_server_port_quic_enabled_honours_the_port() {
    for (key, expected) in [("quic_bind_port", 7200u16), ("quicBindPort", 7201)] {
        let (cfg, presence) =
            load_server_with_presence(&format!("bind_port = 7000\n{key} = {expected}\n"));
        assert_eq!(cfg.quic_bind_port, expected, "`{key}` must reach the field");
        assert!(
            presence
                .unhonoured_server_feature_key_records(all_gated_listener_readers())
                .is_empty(),
            "a build whose caller reports the QUIC listener must stay silent; body key `{key}`"
        );
    }
}

/// The `quic` twin of
/// `feature_gated_server_port_kcp_enabled_without_a_reader_reports_the_port`:
/// the hand-named `tiny,frp-core/quic` shape.
#[cfg(feature = "quic")]
#[test]
fn feature_gated_server_port_quic_enabled_without_a_reader_reports_the_port() {
    for (key, port) in [("quic_bind_port", "7200"), ("quicBindPort", "7201")] {
        for body in [
            format!("bind_port = 7000\n{key} = {port}\n"),
            format!("bind_port = 7000\n[common]\n{key} = {port}\n"),
        ] {
            let (cfg, presence) = load_server_with_presence(&body);
            assert_eq!(
                cfg.quic_bind_port,
                port.parse::<u16>().unwrap(),
                "body:\n{body}"
            );
            assert!(
                presence.server_quic_bind_port_unhonoured,
                "`{key}` asks for a listener this build cannot create; body:\n{body}"
            );
            assert_eq!(
                presence.unhonoured_server_feature_key_records(no_gated_listener_readers()),
                vec![SERVER_QUIC_BIND_PORT_UNHONOURED_NO_READER_WARNING.clone()],
                "`{key}` must produce exactly the field-present record; body:\n{body}"
            );
        }
    }
    assert_unhonoured_diagnostic(
        &SERVER_QUIC_BIND_PORT_UNHONOURED_NO_READER_CLAUSES,
        SERVER_QUIC_BIND_PORT_UNHONOURED_NO_READER_WARNING.as_str(),
        "quic_bind_port",
    );
}

/// The `quic` twin of
/// `feature_gated_server_port_kcp_disabled_reports_the_dropped_port`, with the
/// same both-ways reader pin.
#[cfg(not(feature = "quic"))]
#[test]
fn feature_gated_server_port_quic_disabled_reports_the_dropped_port() {
    for (key, port) in [("quic_bind_port", "7200"), ("quicBindPort", "7201")] {
        for body in [
            format!("bind_port = 7000\n{key} = {port}\n"),
            format!("bind_port = 7000\n[common]\n{key} = {port}\n"),
        ] {
            let (cfg, presence) = load_server_with_presence(&body);
            assert_eq!(cfg.bind_port, 7000, "body:\n{body}");
            assert!(
                presence.server_quic_bind_port_unhonoured,
                "`{key}` asks for a listener this build cannot create; body:\n{body}"
            );
            for readers in [no_gated_listener_readers(), all_gated_listener_readers()] {
                assert_eq!(
                    presence.unhonoured_server_feature_key_records(readers),
                    vec![SERVER_QUIC_BIND_PORT_UNHONOURED_WARNING.clone()],
                    "a field this build did not compile is unread whatever the caller \
                     reports; body:\n{body}"
                );
            }
        }
    }
    assert_unhonoured_diagnostic(
        &SERVER_QUIC_BIND_PORT_UNHONOURED_CLAUSES,
        SERVER_QUIC_BIND_PORT_UNHONOURED_WARNING.as_str(),
        "quic_bind_port",
    );
}

/// The `quic` twin of
/// `feature_gated_server_port_kcp_disabled_is_silent_for_zero_or_absent`, run in
/// every shape for the same reason.
#[test]
fn feature_gated_server_port_quic_disabled_is_silent_for_zero_or_absent() {
    for body in [
        "bind_port = 7000\n".to_string(),
        "bind_port = 7000\nquic_bind_port = 0\n".to_string(),
        "bind_port = 7000\nquicBindPort = 0\n".to_string(),
        "bind_port = 7000\n[common]\nquic_bind_port = 0\n".to_string(),
    ] {
        let (_cfg, presence) = load_server_with_presence(&body);
        assert!(!presence.server_quic_bind_port_unhonoured, "body:\n{body}");
    }
}

// ─── websocket_port / websocketPort (the `websocket` feature) ────────────

/// The `websocket` twin of
/// `feature_gated_server_port_kcp_enabled_honours_the_port`. This is the key the
/// defect was measured with (`frps-micro verify --strict-config` on a config
/// carrying `websocketPort = 7500` printed `syntax is ok` and bound nothing).
#[cfg(feature = "websocket")]
#[test]
fn feature_gated_server_port_websocket_enabled_honours_the_port() {
    for (key, expected) in [("websocket_port", 7500u16), ("websocketPort", 7501)] {
        let (cfg, presence) =
            load_server_with_presence(&format!("bind_port = 7000\n{key} = {expected}\n"));
        assert_eq!(cfg.websocket_port, expected, "`{key}` must reach the field");
        assert!(
            presence
                .unhonoured_server_feature_key_records(all_gated_listener_readers())
                .is_empty(),
            "a build whose caller reports the WebSocket listener must stay silent; \
             body key `{key}`"
        );
    }
}

/// The `websocket` twin of
/// `feature_gated_server_port_kcp_enabled_without_a_reader_reports_the_port` —
/// the hand-named `tiny,frp-core/websocket` shape. There is no
/// `--websocket-port` flag, so this file key is the only half that exists here.
#[cfg(feature = "websocket")]
#[test]
fn feature_gated_server_port_websocket_enabled_without_a_reader_reports_the_port() {
    for (key, port) in [("websocket_port", "7500"), ("websocketPort", "7501")] {
        for body in [
            format!("bind_port = 7000\n{key} = {port}\n"),
            format!("bind_port = 7000\n[common]\n{key} = {port}\n"),
        ] {
            let (cfg, presence) = load_server_with_presence(&body);
            assert_eq!(
                cfg.websocket_port,
                port.parse::<u16>().unwrap(),
                "body:\n{body}"
            );
            assert!(
                presence.server_websocket_port_unhonoured,
                "`{key}` asks for a listener this build cannot create; body:\n{body}"
            );
            assert_eq!(
                presence.unhonoured_server_feature_key_records(no_gated_listener_readers()),
                vec![SERVER_WEBSOCKET_PORT_UNHONOURED_NO_READER_WARNING.clone()],
                "`{key}` must produce exactly the field-present record; body:\n{body}"
            );
        }
    }
    assert_unhonoured_diagnostic(
        &SERVER_WEBSOCKET_PORT_UNHONOURED_NO_READER_CLAUSES,
        SERVER_WEBSOCKET_PORT_UNHONOURED_NO_READER_WARNING.as_str(),
        "websocket_port",
    );
}

/// The `websocket` twin of
/// `feature_gated_server_port_kcp_disabled_reports_the_dropped_port`, with the
/// same both-ways reader pin.
#[cfg(not(feature = "websocket"))]
#[test]
fn feature_gated_server_port_websocket_disabled_reports_the_dropped_port() {
    for (key, port) in [("websocket_port", "7500"), ("websocketPort", "7501")] {
        for body in [
            format!("bind_port = 7000\n{key} = {port}\n"),
            format!("bind_port = 7000\n[common]\n{key} = {port}\n"),
        ] {
            let (cfg, presence) = load_server_with_presence(&body);
            assert_eq!(cfg.bind_port, 7000, "body:\n{body}");
            assert!(
                presence.server_websocket_port_unhonoured,
                "`{key}` asks for a listener this build cannot create; body:\n{body}"
            );
            for readers in [no_gated_listener_readers(), all_gated_listener_readers()] {
                assert_eq!(
                    presence.unhonoured_server_feature_key_records(readers),
                    vec![SERVER_WEBSOCKET_PORT_UNHONOURED_WARNING.clone()],
                    "a field this build did not compile is unread whatever the caller \
                     reports; body:\n{body}"
                );
            }
        }
    }
    assert_unhonoured_diagnostic(
        &SERVER_WEBSOCKET_PORT_UNHONOURED_CLAUSES,
        SERVER_WEBSOCKET_PORT_UNHONOURED_WARNING.as_str(),
        "websocket_port",
    );
}

/// The `websocket` twin of
/// `feature_gated_server_port_kcp_disabled_is_silent_for_zero_or_absent`, run in
/// every shape for the same reason.
#[test]
fn feature_gated_server_port_websocket_disabled_is_silent_for_zero_or_absent() {
    for body in [
        "bind_port = 7000\n".to_string(),
        "bind_port = 7000\nwebsocket_port = 0\n".to_string(),
        "bind_port = 7000\nwebsocketPort = 0\n".to_string(),
        "bind_port = 7000\n[common]\nwebsocket_port = 0\n".to_string(),
    ] {
        let (_cfg, presence) = load_server_with_presence(&body);
        assert!(!presence.server_websocket_port_unhonoured, "body:\n{body}");
    }
}

// ─── The class pins (every build shape) ─────────────────────────────────

/// Each feature-gated listener port is still declared to strict mode in **both**
/// spellings, and `server.rs` still gates a field on that feature.
///
/// Strict mode accepting the key is deliberate and stays that way: refusing it
/// would be the "false 400" direction that `docs/deployment.md` rules out, and
/// the repo's own `frps.toml` carries `kcp_bind_port = 17000` +
/// `quic_bind_port = 17001` (and `frp-core/src/config/fixtures/frps_legacy_full.ini`
/// `kcp_bind_port = 7000`), so rejection would stop a `micro`/`tiny` build from
/// loading the documented example at all — the invariant
/// `frp-core/src/config/strict.rs` records next to `subdomain_host`. What the
/// fix changed is only that the load is no longer **silent**.
#[test]
fn feature_gated_server_ports_stay_known_to_strict_mode_in_every_build() {
    let known = super::strict::known_server_keys();
    let server_rs = include_str!("server.rs");
    for (snake, camel, feature) in FEATURE_GATED_SERVER_PORTS {
        assert!(
            known.contains(snake),
            "strict mode must keep accepting `{snake}`"
        );
        assert!(
            known.contains(camel),
            "strict mode must keep accepting `{camel}`"
        );
        assert!(
            server_rs.contains(&format!("#[cfg(feature = \"{feature}\")]")),
            "`{snake}` is no longer gated on `{feature}` — FEATURE_GATED_SERVER_PORTS \
             and the loader's detector have to follow"
        );
    }
}

/// The scope pin: `server.rs` gates fields on **exactly** the features this
/// table names, so a fourth feature-gated server field cannot slip past the
/// loader's detector without this test (and the table it guards) going red.
///
/// It catches a new **feature name**. A *second* field reusing one of the three
/// — `ServerConfigSnapshot` already does that for `kcp`/`quic` — is invisible to
/// it, which is why the value-level pins above are per field. Neither
/// `known_server_keys()` nor `known_client_keys()` is covered by the existing
/// `strict_array_element_keys_match_struct_fields` drift guard (that one walks
/// the `pub(super) const … *KNOWN_KEYS` arrays, and these are function-local).
#[test]
fn feature_gated_server_field_set_matches_the_pinned_scope() {
    let mut found: Vec<&str> = include_str!("server.rs")
        .lines()
        .filter_map(|line| {
            line.trim()
                .strip_prefix("#[cfg(feature = \"")?
                .strip_suffix("\")]")
        })
        .collect();
    found.sort_unstable();
    found.dedup();
    let mut pinned: Vec<&str> = FEATURE_GATED_SERVER_PORTS
        .iter()
        .map(|(_, _, feature)| *feature)
        .collect();
    pinned.sort_unstable();
    assert_eq!(
        found, pinned,
        "a feature-gated server field was added or removed: `server.rs` gates \
         fields on {found:?}, the detector's scope table names {pinned:?}"
    );
}

// ─── The reader-gated listener ports (every build shape) ────────────────
//
// `web_server.port` and `ssh_tunnel_gateway.bind_port` are **unconditional**
// `ServerConfig` fields, so serde accepts both keys in every build; the only
// readers live in `frp-server` (its `dashboard` and `ssh` features). A build
// without the reader loads the file and then silently binds nothing, so
// `ConfigPresence` records the fact unconditionally and the **caller's**
// [`ListenerPortReader`] decides whether a record is emitted — that split is
// what keeps the warning off in the shapes that *do* bind the port (see
// `frp-server/src/service.rs`, which owns both answers).

/// The `.ini` twin of [`load_server_with_presence`]: same entry point, but the
/// file is `frps.ini` so the extension selects the INI reader. Strict mode, as
/// above.
fn load_server_ini_with_presence(body: &str) -> (ServerConfig, ConfigPresence) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("frps.ini");
    std::fs::write(&path, body).unwrap();
    load_server_config_uncompleted_with_presence(path.to_str().unwrap(), true)
        .unwrap_or_else(|e| panic!("strict mode must load this:\n{e}\nbody:\n{body}"))
}

/// `web_server.port` presence, in both section spellings, through `[common]`,
/// and via both legacy flat keys — normalize rewrites all of them into
/// `web_server.port` (`legacy_web_server_keys` for `dashboard_port`,
/// `flatten_to_table` for `web_server_port`, `merge_section_into` for
/// `[webServer]`) *before* the presence read, so one check covers every
/// spelling. A check that read the raw table would miss three of these four.
#[test]
fn reader_gated_web_server_port_presence_is_recorded_in_every_build() {
    for body in [
        "bind_port = 7000\n[web_server]\nport = 7500\n".to_string(),
        "bind_port = 7000\n[webServer]\nport = 7501\n".to_string(),
        "bind_port = 7000\n[common]\nweb_server_port = 7502\n".to_string(),
        "bind_port = 7000\ndashboard_port = 7503\n".to_string(),
    ] {
        let (_cfg, presence) = load_server_with_presence(&body);
        assert!(presence.web_server_port_unhonoured, "body:\n{body}");
    }
}

/// `0` and an absent key are the documented "disabled" value in every build
/// shape — a capable reader gates on `> 0` too — so a written zero asks for no
/// listener and must not be recorded. (The legacy-`.ini` zero *spellings* are
/// covered separately below.)
#[test]
fn reader_gated_web_server_port_zero_or_absent_is_silent_in_every_build() {
    for body in [
        "bind_port = 7000\n",
        "bind_port = 7000\n[web_server]\nport = 0\n",
        "bind_port = 7000\n[webServer]\nport = 0\n",
        "bind_port = 7000\n[common]\nweb_server_port = 0\n",
        "bind_port = 7000\ndashboard_port = 0\n",
    ] {
        let (_cfg, presence) = load_server_with_presence(body);
        assert!(!presence.web_server_port_unhonoured, "body:\n{body}");
    }
}

/// The `ssh_tunnel_gateway.bind_port` twin: the snake section and the
/// `sshTunnelGateway`/`bindPort` Go spellings both reach the one normalized
/// table (`server.rs` aliases and `normalize_server_config` rename it).
#[test]
fn reader_gated_ssh_tunnel_gateway_bind_port_presence_is_recorded_in_every_build() {
    for body in [
        "bind_port = 7000\n[ssh_tunnel_gateway]\nbind_port = 7600\n",
        "bind_port = 7000\n[sshTunnelGateway]\nbindPort = 7601\n",
    ] {
        let (_cfg, presence) = load_server_with_presence(body);
        assert!(
            presence.ssh_tunnel_gateway_bind_port_unhonoured,
            "body:\n{body}"
        );
    }
}

/// The `ssh_tunnel_gateway.bind_port` twin of
/// [`reader_gated_web_server_port_zero_or_absent_is_silent_in_every_build`].
#[test]
fn reader_gated_ssh_tunnel_gateway_bind_port_zero_or_absent_is_silent_in_every_build() {
    for body in [
        "bind_port = 7000\n",
        "bind_port = 7000\n[ssh_tunnel_gateway]\nbind_port = 0\n",
        "bind_port = 7000\n[sshTunnelGateway]\nbindPort = 0\n",
    ] {
        let (_cfg, presence) = load_server_with_presence(body);
        assert!(
            !presence.ssh_tunnel_gateway_bind_port_unhonoured,
            "body:\n{body}"
        );
    }
}

/// The record list is empty for a reader the build **has**, and names only the
/// keys it cannot honour otherwise.
///
/// This is the frp-core half of the "warning must not fire where the feature is
/// on" pin: `unhonoured_reader_gated_port_records(Present, Present)` is `[]`, so
/// a list that ignored the reader (the always-warn mutation) reds the first
/// assertion. The frp-server half is
/// `web_server_port_reader_answers_from_this_build`.
#[test]
fn reader_gated_port_records_follow_the_readers_the_caller_reports() {
    use super::ListenerPortReader::{Absent, Present};

    let body = "bind_port = 7000\n[web_server]\nport = 7500\n\
                [ssh_tunnel_gateway]\nbind_port = 7600\n";
    let (_cfg, presence) = load_server_with_presence(body);

    assert!(
        presence
            .unhonoured_reader_gated_port_records(Present, Present)
            .is_empty(),
        "a build that honours both ports must emit no record: {:?}",
        presence.unhonoured_reader_gated_port_records(Present, Present)
    );
    assert_eq!(
        presence.unhonoured_reader_gated_port_records(Absent, Absent),
        vec![
            WEB_SERVER_PORT_UNHONOURED_WARNING,
            SSH_TUNNEL_GATEWAY_BIND_PORT_UNHONOURED_WARNING,
        ]
    );
    assert_eq!(
        presence.unhonoured_reader_gated_port_records(Absent, Present),
        vec![WEB_SERVER_PORT_UNHONOURED_WARNING]
    );
    assert_eq!(
        presence.unhonoured_reader_gated_port_records(Present, Absent),
        vec![SSH_TUNNEL_GATEWAY_BIND_PORT_UNHONOURED_WARNING]
    );
}

/// The legacy-`.ini` zero spellings, as a **request** question only (this is the
/// reader-gated pair, which compiles in every shape — the three `frp-core`-gated
/// ports are covered by the `#[cfg]` test below).
///
/// The `.ini` reader keeps a numeric literal that does not round-trip through
/// both renderers as a string (`frp-core/src/config/format.rs`,
/// `infer_ini_value_depth`), and `ini_lenient` reads a numeric target back as
/// base-10 (`frp-core/src/config/ini_lenient.rs`). So `+0`, `00` and `"0"` mean
/// the **same** "disabled" as a bare `0`: every build honours them identically,
/// and warning about one would be a false record — the defect the widened
/// `port_value_requests_a_listener` closes.
#[test]
fn ini_zero_spellings_are_not_requests_for_the_reader_gated_ports() {
    for value in ["0", "+0", "00", "\"0\""] {
        let web = format!("bind_port = 7000\n[web_server]\nport = {value}\n");
        let (_cfg, presence) = load_server_ini_with_presence(&web);
        assert!(
            !presence.web_server_port_unhonoured,
            "`{value}` is a zero/disabled spelling; body:\n{web}"
        );

        let ssh = format!("bind_port = 7000\n[ssh_tunnel_gateway]\nbind_port = {value}\n");
        let (_cfg, presence) = load_server_ini_with_presence(&ssh);
        assert!(
            !presence.ssh_tunnel_gateway_bind_port_unhonoured,
            "`{value}` is a zero/disabled spelling; body:\n{ssh}"
        );
    }
}

/// The positive control for the rule above: a value that **does** ask for a
/// listener must still be recorded. `007` and `+5` are strings to the `.ini`
/// reader and parse to a non-zero integer, so a rule that treated every
/// non-integer as "not a request" would drop them and red here.
#[test]
fn ini_nonzero_listener_port_spellings_still_request_a_listener() {
    for value in ["007", "+5", "7500"] {
        let web = format!("bind_port = 7000\n[web_server]\nport = {value}\n");
        let (_cfg, presence) = load_server_ini_with_presence(&web);
        assert!(
            presence.web_server_port_unhonoured,
            "`{value}` asks for a listener; body:\n{web}"
        );

        let ssh = format!("bind_port = 7000\n[ssh_tunnel_gateway]\nbind_port = {value}\n");
        let (_cfg, presence) = load_server_ini_with_presence(&ssh);
        assert!(
            presence.ssh_tunnel_gateway_bind_port_unhonoured,
            "`{value}` asks for a listener; body:\n{ssh}"
        );
    }
}

/// The per-spelling pin for the three `frp-core`-gated ports themselves.
///
/// Runs in **every** build shape, because the presence flags are now computed in
/// every shape (the field-less direction no longer compiles the flag away) — the
/// `.github/workflows/ci.yml` `cargo test -p frp-core --no-default-features
/// --all-targets` lane used to be the only one that reached this. The assertion
/// goes through [`ConfigPresence::unhonoured_server_feature_key_records`] with
/// all three readers **Absent**, the answer that turns every field-present
/// request into a record; a zero spelling must still produce none.
#[test]
fn ini_zero_spellings_do_not_warn_for_the_gated_listener_ports() {
    for value in ["0", "+0", "00", "\"0\""] {
        for key in ["kcp_bind_port", "quic_bind_port", "websocket_port"] {
            let body = format!("[common]\nbind_port = 7000\n{key} = {value}\n");
            let (_cfg, presence) = load_server_ini_with_presence(&body);
            assert!(
                presence
                    .unhonoured_server_feature_key_records(no_gated_listener_readers())
                    .is_empty(),
                "`{key} = {value}` is a zero/disabled spelling; body:\n{body}"
            );
        }
    }
}

#[test]
fn test_go_format_client_with_plugin_toml() {
    let toml_str = r#"
serverAddr = "140.245.66.216"
serverPort = 7000
auth.method = "token"
auth.token = "my-secret-token"

[[proxies]]
name = "home-arm-qb-proxy"
type = "tcp"
remotePort = 10081
[proxies.plugin]
type = "http_proxy"
httpUser = "cdf"
"#;
    let cfg: ClientConfig = load_client_config_from_str(toml_str).unwrap();
    assert_eq!(cfg.server_addr, "140.245.66.216");
    assert_eq!(cfg.server_port, 7000);
    assert_eq!(cfg.token, "my-secret-token");
    assert_eq!(cfg.proxies.len(), 1);
    assert_eq!(cfg.proxies[0].name, "home-arm-qb-proxy");
    assert_eq!(cfg.proxies[0].proxy_type, "tcp");
    assert_eq!(cfg.proxies[0].remote_port, 10081);
    let plugin = cfg.proxies[0].plugin.as_ref().unwrap();
    assert_eq!(plugin.plugin_type, "http_proxy");
    assert_eq!(plugin.http_user, "cdf");
}

#[test]
fn test_go_flat_plugin_unix_domain_socket_toml() {
    let toml_str = r#"
serverAddr = "127.0.0.1"
serverPort = 7000

[[proxies]]
name = "docker_api"
type = "tcp"
remotePort = 9000
plugin = "unix_domain_socket"
plugin_local_addr = "/var/run/docker.sock"
"#;
    let cfg: ClientConfig = load_client_config_from_str(toml_str).unwrap();
    let plugin = cfg.proxies[0]
        .plugin
        .as_ref()
        .expect("Go-style flat plugin must be parsed");
    assert_eq!(plugin.plugin_type, "unix_domain_socket");
    assert_eq!(plugin.local_addr, "/var/run/docker.sock");
}

#[test]
fn test_go_flat_plugin_http_proxy_fields_toml() {
    let toml_str = r#"
serverAddr = "127.0.0.1"
serverPort = 7000

[[proxies]]
name = "web_proxy"
type = "tcp"
remotePort = 9001
plugin = "http_proxy"
plugin_http_user = "alice"
plugin_http_password = "secret"
"#;
    let cfg: ClientConfig = load_client_config_from_str(toml_str).unwrap();
    let plugin = cfg.proxies[0]
        .plugin
        .as_ref()
        .expect("Go-style flat http_proxy plugin must be parsed");
    assert_eq!(plugin.plugin_type, "http_proxy");
    assert_eq!(plugin.http_user, "alice");
    assert_eq!(plugin.http_password, "secret");
}

#[test]
fn test_go_proxy_camelcase_local_fields_toml() {
    let toml_str = r#"
serverAddr = "127.0.0.1"
serverPort = 7000

[[proxies]]
name = "docker"
type = "tcp"
localIP = "127.0.0.1"
localPort = 2375
remotePort = 6001
"#;
    let cfg: ClientConfig = load_client_config_from_str(toml_str).unwrap();
    assert_eq!(cfg.proxies[0].local_ip, "127.0.0.1");
    assert_eq!(cfg.proxies[0].local_port, 2375);
    assert_eq!(cfg.proxies[0].remote_port, 6001);
}

#[test]
fn test_go_camelcase_server_fields_and_allow_ports() {
    let toml_str = r#"
bindAddr = "0.0.0.0"
bindPort = 7000
subDomainHost = "example.com"
vhostHTTPTimeout = 30
detailedErrorsToClient = false
tcpmuxPassthrough = true
enablePrometheus = true
allowPorts = [{ start = 2000, end = 3000 }, { start = 4000, end = 5000 }]

[webServer]
addr = "127.0.0.1"
port = 7500
user = "admin"
password = "secret"

[auth.oidc]
skipExpiryCheck = true
skipIssuerCheck = true
skipAudience = true
additionalAudience = ["api-prod", "api-staging"]
trustedCaFile = "/etc/ssl/custom-ca.pem"

[[httpPlugins]]
name = "hook"
addr = "http://127.0.0.1:4000"
path = "/handler"
ops = ["login"]

[featureGates]
VirtualNet = true
"#;
    let cfg: ServerConfig = load_server_config_from_str(toml_str).unwrap();
    assert_eq!(cfg.bind_addr, "0.0.0.0");
    assert_eq!(cfg.sub_domain_host, "example.com");
    assert_eq!(cfg.vhost_http_timeout, 30);
    assert!(!cfg.detailed_errors_to_client);
    assert!(cfg.tcp_mux_passthrough);
    assert_eq!(cfg.web_server.port, 7500);
    assert!(cfg.web_server.enable_prometheus);
    assert_eq!(cfg.allow_ports, "2000-3000,4000-5000");
    assert_eq!(cfg.http_plugins.len(), 1);
    assert!(cfg.auth.oidc_skip_expiry);
    assert!(cfg.auth.oidc_skip_issuer);
    assert!(cfg.auth.oidc_skip_audience);
    assert_eq!(
        cfg.auth.oidc_additional_audience,
        vec!["api-prod", "api-staging"]
    );
    assert_eq!(cfg.auth.oidc_tls_trusted_ca_file, "/etc/ssl/custom-ca.pem");
    assert_eq!(cfg.feature.gates.get("VirtualNet"), Some(&true));
}

#[test]
fn test_vhost_http_timeout_is_go_signed_int64() {
    // `TODO.md:9834`. Go's `VhostHTTPTimeout` field is `int64`
    // (`pkg/config/v1/server.go`) and the flag is `Int64VarP`
    // (`pkg/config/flags.go:237`), so the file lane accepts a negative value and
    // refuses only what does not fit an `int64`. Measured on Go v0.71.0
    // (`frps verify -c <file>`): `vhostHTTPTimeout = -1` rc 0,
    // `-9223372036854775808` rc 0, `9999999999999999999` rc 1
    // (`strconv.ParseInt: … value out of range`).
    let negative: ServerConfig =
        load_server_config_from_str("bindPort = 7000\nvhostHTTPTimeout = -1\n").unwrap();
    assert_eq!(negative.vhost_http_timeout, -1);

    let floor: ServerConfig = load_server_config_from_str(&format!(
        "bindPort = 7000\nvhostHTTPTimeout = {}\n",
        i64::MIN
    ))
    .unwrap();
    assert_eq!(floor.vhost_http_timeout, i64::MIN);

    let ceiling: ServerConfig = load_server_config_from_str(&format!(
        "bindPort = 7000\nvhostHTTPTimeout = {}\n",
        i64::MAX
    ))
    .unwrap();
    assert_eq!(ceiling.vhost_http_timeout, i64::MAX);

    assert!(
        load_server_config_from_str("bindPort = 7000\nvhostHTTPTimeout = 9223372036854775808\n")
            .is_err(),
        "one past Go's int64 must be refused by the same boundary"
    );
}

#[test]
fn test_go_camelcase_client_sections_oidc_visitor_and_plugins() {
    let toml_str = r#"
serverAddr = "127.0.0.1"
serverPort = 7000

[transport]
poolCount = 5

[webServer]
port = 7500

[auth.oidc]
clientID = "client-1"
clientSecret = "secret"
tokenEndpointURL = "https://issuer.example.com/token"
scope = "openid"

[featureGates]
VirtualNet = true

[[proxies]]
name = "web"
type = "http"
remotePort = 80
customDomains = ["example.com"]
metadatas = { env = "prod" }
useEncryption = true
useCompression = true
plugin = "unix_domain_socket"
plugin_unix_path = "/var/run/docker.sock"

[[visitors]]
name = "vis"
type = "stcp"
serverName = "s"
bindAddr = "0.0.0.0"
bindPort = 1234
fallbackTimeoutMs = 500

[visitors.transport]
useEncryption = true
useCompression = true

[visitors.natTraversal]
disableAssistedAddrs = true
"#;
    let cfg: ClientConfig = load_client_config_from_str(toml_str).unwrap();
    assert_eq!(cfg.pool_count, 5);
    assert_eq!(cfg.web_server.port, 7500);
    let auth = cfg.auth.as_ref().expect("auth");
    assert_eq!(auth.oidc_client_id, "client-1");
    assert_eq!(auth.oidc_client_secret, "secret");
    assert_eq!(auth.oidc_token_endpoint, "https://issuer.example.com/token");
    assert_eq!(auth.oidc_scope, "openid");
    assert_eq!(cfg.feature.gates.get("VirtualNet"), Some(&true));

    let proxy = &cfg.proxies[0];
    assert_eq!(proxy.custom_domains, vec!["example.com".to_string()]);
    assert_eq!(proxy.metas.get("env").map(String::as_str), Some("prod"));
    assert!(proxy.use_encryption);
    assert!(proxy.use_compression);
    let plugin = proxy.plugin.as_ref().expect("plugin");
    assert_eq!(plugin.plugin_type, "unix_domain_socket");
    assert_eq!(plugin.local_addr, "/var/run/docker.sock");

    let visitor = &cfg.visitors[0];
    assert_eq!(visitor.bind_addr, "0.0.0.0");
    assert_eq!(visitor.bind_port, 1234);
    assert_eq!(visitor.fallback_timeout_ms, 500);
    assert!(visitor.use_encryption);
    assert!(visitor.use_compression);
    assert!(visitor.disable_assisted_addrs);
}

#[test]
fn test_go_virtual_net_client_config() {
    let toml_str = r#"
serverAddr = "127.0.0.1"
serverPort = 7000

[featureGates]
VirtualNet = true

[virtualNet]
address = "10.0.0.1"

[[visitors]]
name = "vnet-visitor"
type = "stcp"
serverName = "vnet-server"
secretKey = "secret"
bindPort = -1

[visitors.plugin]
type = "virtual_net"
destinationIP = "100.86.0.1"
"#;
    let cfg: ClientConfig = load_client_config_from_str(toml_str).unwrap();
    assert_eq!(cfg.virtual_net.address, "10.0.0.1");
    assert_eq!(cfg.feature.gates.get(VIRTUAL_NET), Some(&true));

    let visitor = &cfg.visitors[0];
    assert_eq!(visitor.bind_port, -1);
    let plugin = visitor.plugin.as_ref().expect("visitor plugin");
    assert_eq!(plugin.plugin_type, "virtual_net");
    assert_eq!(plugin.destination_ip, "100.86.0.1");
}

#[test]
fn test_virtual_net_feature_gate_required() {
    // [virtualNet] without the gate enabled is rejected.
    let err = load_client_config_from_str(
        r#"
serverAddr = "127.0.0.1"

[virtualNet]
address = "10.0.0.1"
"#,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("VirtualNet feature is not enabled"), "{err}");

    // virtual_net visitor plugin without the gate enabled is rejected.
    let err = load_client_config_from_str(
        r#"
serverAddr = "127.0.0.1"

[[visitors]]
name = "vnet-visitor"
type = "stcp"
serverName = "vnet-server"
bindPort = -1

[visitors.plugin]
type = "virtual_net"
destinationIP = "100.86.0.1"
"#,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("VirtualNet feature is not enabled"), "{err}");
}

#[test]
fn test_virtual_net_visitor_destination_ip_validation() {
    // Missing destinationIP is rejected.
    let err = load_client_config_from_str(
        r#"
serverAddr = "127.0.0.1"

[featureGates]
VirtualNet = true

[[visitors]]
name = "vnet-visitor"
type = "stcp"
serverName = "vnet-server"
bindPort = -1

[visitors.plugin]
type = "virtual_net"
"#,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("requires destinationIP"), "{err}");

    // Invalid IP is rejected.
    let err = load_client_config_from_str(
        r#"
serverAddr = "127.0.0.1"

[featureGates]
VirtualNet = true

[[visitors]]
name = "vnet-visitor"
type = "stcp"
serverName = "vnet-server"
bindPort = -1

[visitors.plugin]
type = "virtual_net"
destinationIP = "not-an-ip"
"#,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("invalid destination IP address"), "{err}");
}

#[test]
fn test_virtual_net_proxy_plugin_nested_and_flat_config() {
    let nested = r#"
serverAddr = "127.0.0.1"
serverPort = 7000

[featureGates]
VirtualNet = true

[virtualNet]
address = "10.0.0.2"

[[proxies]]
name = "vnet-provider"
type = "tcp"
remotePort = 0

[proxies.plugin]
type = "virtual_net"
"#;
    let cfg: ClientConfig = load_client_config_from_str(nested).unwrap();
    let plugin = cfg.proxies[0]
        .plugin
        .as_ref()
        .expect("nested virtual_net plugin");
    assert_eq!(plugin.plugin_type, "virtual_net");

    let flat = r#"
serverAddr = "127.0.0.1"
serverPort = 7000

[featureGates]
VirtualNet = true

[virtualNet]
address = "10.0.0.2"

[[proxies]]
name = "vnet-provider"
type = "tcp"
remotePort = 0
plugin = "virtual_net"
"#;
    let cfg: ClientConfig = load_client_config_from_str(flat).unwrap();
    let plugin = cfg.proxies[0]
        .plugin
        .as_ref()
        .expect("flat virtual_net plugin");
    assert_eq!(plugin.plugin_type, "virtual_net");
}

#[test]
fn test_virtual_net_proxy_plugin_validation() {
    // Feature gate required.
    let err = load_client_config_from_str(
        r#"
serverAddr = "127.0.0.1"

[virtualNet]
address = "10.0.0.2"

[[proxies]]
name = "vnet-provider"
type = "tcp"
plugin = "virtual_net"
"#,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("VirtualNet feature is not enabled"), "{err}");

    // [virtualNet] address is required.
    let err = load_client_config_from_str(
        r#"
serverAddr = "127.0.0.1"

[featureGates]
VirtualNet = true

[[proxies]]
name = "vnet-provider"
type = "tcp"
plugin = "virtual_net"
"#,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("requires [virtualNet] address"), "{err}");

    // The plugin is only valid on tcp proxies.
    let err = load_client_config_from_str(
        r#"
serverAddr = "127.0.0.1"

[featureGates]
VirtualNet = true

[virtualNet]
address = "10.0.0.2"

[[proxies]]
name = "vnet-provider"
type = "stcp"
plugin = "virtual_net"
"#,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("requires proxy type tcp"), "{err}");
}

#[test]
fn test_go_extended_server_config_fields() {
    let toml_str = r#"
bindAddr = "127.0.0.1"
bindPort = 7000

[log]
disablePrintColor = true

[webServer]
assetsDir = "/srv/assets"
pprofEnable = true

[webServer.tls]
certFile = "/etc/frps/dash.crt"
keyFile = "/etc/frps/dash.key"

[[httpPlugins]]
name = "hook"
addr = "http://127.0.0.1:4000"
path = "/handler"
ops = ["login"]
tlsVerify = true
"#;
    let cfg: ServerConfig = load_server_config_from_str(toml_str).unwrap();
    assert!(cfg.log.disable_print_color);
    assert_eq!(cfg.web_server.assets_dir, "/srv/assets");
    assert!(cfg.web_server.pprof_enable);
    assert_eq!(cfg.web_server.tls_cert_file, "/etc/frps/dash.crt");
    assert_eq!(cfg.web_server.tls_key_file, "/etc/frps/dash.key");
    assert!(cfg.http_plugins[0].tls_verify);
}

#[test]
fn test_go_client_web_server_tls_flatten() {
    let toml_str = r#"
serverAddr = "127.0.0.1"
serverPort = 7000

[webServer]
addr = "127.0.0.1"
port = 7400

[webServer.tls]
certFile = "/etc/frpc/admin.crt"
keyFile = "/etc/frpc/admin.key"
trustedCaFile = "/etc/frpc/ca.crt"
serverName = "admin.example.com"
"#;
    let cfg: ClientConfig = load_client_config_from_str(toml_str).unwrap();
    assert_eq!(cfg.web_server.tls_cert_file, "/etc/frpc/admin.crt");
    assert_eq!(cfg.web_server.tls_key_file, "/etc/frpc/admin.key");
    assert_eq!(cfg.web_server.tls_ca_file, "/etc/frpc/ca.crt");
    assert_eq!(cfg.web_server.tls_server_name, "admin.example.com");

    // The client's admin `[webServer.tls]` goes through the same
    // `normalize_web_server_section` (`normalize_client_config` calls it), so
    // the canonical snake_case spellings land on the same flat fields — the
    // client half of
    // `nested_web_server_tls_spellings_reach_the_accessor_in_both_modes`. This
    // is the string-based loader (no strict check), so it pins the mapping, not
    // the strict-mode error path.
    let cfg: ClientConfig = load_client_config_from_str(
        r#"
serverAddr = "127.0.0.1"
serverPort = 7000

[webServer]
addr = "127.0.0.1"
port = 7400

[webServer.tls]
cert_file = "/etc/frpc/admin.crt"
key_file = "/etc/frpc/admin.key"
trusted_ca_file = "/etc/frpc/ca.crt"
server_name = "admin.example.com"
enable = true
"#,
    )
    .unwrap();
    assert_eq!(cfg.web_server.tls_cert(), "/etc/frpc/admin.crt");
    assert_eq!(cfg.web_server.tls_key(), "/etc/frpc/admin.key");
    assert_eq!(cfg.web_server.tls_ca_file, "/etc/frpc/ca.crt");
    assert_eq!(cfg.web_server.tls_server_name, "admin.example.com");
    assert!(
        !cfg.web_server.tls.enable,
        "`enable` is inert on the client too"
    );
}

#[test]
fn test_go_extended_proxy_visitor_config_fields() {
    let toml_str = r#"
serverAddr = "127.0.0.1"
serverPort = 7000

[[proxies]]
name = "web"
type = "http"
remotePort = 80
customDomains = ["web.example.com"]

[proxies.natTraversal]
disableAssistedAddrs = true

[proxies.healthCheck]
type = "http"
url = "http://localhost/health"
httpHeaders = [{ name = "X-Token", value = "abc" }]

[proxies.plugin]
type = "https2http"
crtPath = "/crt"
keyPath = "/key"
enableHTTP2 = true

[proxies.plugin.requestHeaders.set]
X-Custom = "v"

[[visitors]]
name = "vis"
type = "stcp"
serverName = "s"
bindPort = 1234
enabled = false
"#;
    let cfg: ClientConfig = load_client_config_from_str(toml_str).unwrap();
    let proxy = &cfg.proxies[0];
    assert!(proxy.disable_assisted_addrs);
    assert_eq!(
        proxy
            .health_check_http_headers
            .iter()
            .find(|h| h.name == "X-Token")
            .map(|h| h.value.as_str()),
        Some("abc")
    );
    let plugin = proxy.plugin.as_ref().expect("plugin");
    assert_eq!(plugin.crt_file, "/crt");
    assert_eq!(plugin.key_file, "/key");
    assert_eq!(plugin.enable_http2, Some(true));
    assert_eq!(
        plugin.request_headers.get("X-Custom").map(String::as_str),
        Some("v")
    );
    assert!(!cfg.visitors[0].enabled);
}

#[test]
fn test_parse_allow_ports() {
    // Empty → empty
    assert!(parse_allow_ports("").unwrap().is_empty());
    // Single range
    assert_eq!(
        parse_allow_ports("10000-20000").unwrap(),
        vec![PortsRange {
            start: 10000,
            end: 20000,
            single: 0
        }]
    );
    // Multiple ranges
    assert_eq!(
        parse_allow_ports("10000-20000,30000-40000").unwrap(),
        vec![
            PortsRange {
                start: 10000,
                end: 20000,
                single: 0
            },
            PortsRange {
                start: 30000,
                end: 40000,
                single: 0
            },
        ]
    );
    // With spaces
    assert_eq!(
        parse_allow_ports("10000-20000, 30000-40000").unwrap(),
        vec![
            PortsRange {
                start: 10000,
                end: 20000,
                single: 0
            },
            PortsRange {
                start: 30000,
                end: 40000,
                single: 0
            },
        ]
    );
    // Reversed range is an error, matching Go's ParseRangeNumbers
    // ("range number is invalid") — audit task 9 finding 7.
    let err = parse_allow_ports("20000-10000").unwrap_err();
    assert!(err.contains("range number is invalid"), "got: {err}");
    // Single port
    assert_eq!(
        parse_allow_ports("8080").unwrap(),
        vec![PortsRange {
            start: 8080,
            end: 8080,
            single: 0
        }]
    );
    // Go `{single=N}` form
    assert_eq!(
        parse_allow_ports("{single=40000}").unwrap(),
        vec![PortsRange {
            start: 40000,
            end: 40000,
            single: 40000
        }]
    );
    assert!(parse_allow_ports("1000-2000,{single=8080}").unwrap()[1].contains(8080));
    assert!(!parse_allow_ports("1000-2000,{single=8080}").unwrap()[1].contains(8081));
    // Mixed
    assert_eq!(
        parse_allow_ports("1000-2000,8080,30000-40000").unwrap(),
        vec![
            PortsRange {
                start: 1000,
                end: 2000,
                single: 0
            },
            PortsRange {
                start: 8080,
                end: 8080,
                single: 0
            },
            PortsRange {
                start: 30000,
                end: 40000,
                single: 0
            },
        ]
    );
    // Invalid entries are config errors (Go validation behavior).
    assert!(parse_allow_ports("not-a-port").is_err());
    assert!(parse_allow_ports("99999").is_err()); // > u16::MAX
    assert!(parse_allow_ports("{single=oops}").is_err());
}

#[test]
fn test_count_ports() {
    assert_eq!(
        count_ports(&[PortsRange {
            start: 10000,
            end: 10009,
            single: 0
        }]),
        10
    );
    assert_eq!(
        count_ports(&[
            PortsRange {
                start: 10000,
                end: 10009,
                single: 0
            },
            PortsRange {
                start: 20000,
                end: 20004,
                single: 0
            },
        ]),
        15
    );
    assert_eq!(
        count_ports(&[PortsRange {
            start: 1,
            end: 1,
            single: 8080
        }]),
        1
    );
    assert_eq!(count_ports(&[]), 0);
}

#[test]
fn test_go_format_client_toml() {
    let toml_str = r#"
[common]
server_addr = "127.0.0.1"
server_port = 7000
token = "my-token"
protocol = "tcp"
pool_count = 1

[[proxies]]
name = "test-tcp"
type = "tcp"
local_ip = "127.0.0.1"
local_port = 80
remote_port = 7001
"#;
    let cfg: ClientConfig = load_client_config_from_str(toml_str).unwrap();
    assert_eq!(cfg.server_addr, "127.0.0.1");
    assert_eq!(cfg.server_port, 7000);
    assert_eq!(cfg.token, "my-token");
    assert_eq!(cfg.transport_protocol, "tcp");
    assert_eq!(cfg.pool_count, 1);
    assert_eq!(cfg.proxies.len(), 1);
    let p = &cfg.proxies[0];
    assert_eq!(p.name, "test-tcp");
    assert_eq!(p.proxy_type, "tcp");
    assert_eq!(p.local_ip, "127.0.0.1");
    assert_eq!(p.local_port, 80);
    assert_eq!(p.remote_port, 7001);
}

#[test]
fn test_parse_allow_ports_edge_cases() {
    // Empty string
    assert!(parse_allow_ports("").unwrap().is_empty());

    // Single port
    let r = parse_allow_ports("8080").unwrap();
    assert_eq!(
        r,
        vec![PortsRange {
            start: 8080,
            end: 8080,
            single: 0
        }]
    );

    // Two single ports
    let r = parse_allow_ports("9000,8000").unwrap();
    assert_eq!(
        r,
        vec![
            PortsRange {
                start: 9000,
                end: 9000,
                single: 0
            },
            PortsRange {
                start: 8000,
                end: 8000,
                single: 0
            },
        ]
    );

    // Mixed ranges and single ports
    let r = parse_allow_ports("1000-2000,3000,5000-6000").unwrap();
    assert_eq!(
        r,
        vec![
            PortsRange {
                start: 1000,
                end: 2000,
                single: 0
            },
            PortsRange {
                start: 3000,
                end: 3000,
                single: 0
            },
            PortsRange {
                start: 5000,
                end: 6000,
                single: 0
            },
        ]
    );

    // Whitespace handling
    let r = parse_allow_ports(" 1000 , 2000-3000 ").unwrap();
    assert_eq!(
        r,
        vec![
            PortsRange {
                start: 1000,
                end: 1000,
                single: 0
            },
            PortsRange {
                start: 2000,
                end: 3000,
                single: 0
            },
        ]
    );

    // Garbage and out-of-range entries are errors (Go validation).
    assert!(parse_allow_ports("not-a-port").is_err());
    assert!(parse_allow_ports("99999").is_err()); // > u16::MAX
    assert!(parse_allow_ports("0").is_err());
}

#[test]
fn test_parse_bandwidth_limit_edge_cases() {
    // Empty → Some(0) (no limit, Go compat)
    assert_eq!(parse_bandwidth_limit(""), Some(0));
    // Bare number without suffix → None (Go requires "KB"/"MB")
    assert_eq!(parse_bandwidth_limit("0"), None);

    // KB variant (binary: 1KB = 1024)
    assert_eq!(parse_bandwidth_limit("1KB"), Some(1024));

    // Single-letter suffix "K" → None (Go requires "KB")
    assert_eq!(parse_bandwidth_limit("1K"), None);

    // MB variant
    assert_eq!(parse_bandwidth_limit("1MB"), Some(1_048_576));

    // Single-letter suffix "M" → None (Go requires "MB")
    assert_eq!(parse_bandwidth_limit("1M"), None);

    // GB variant — Go frp rejects "GB"; must use "MB" or "KB"
    assert_eq!(parse_bandwidth_limit("1GB"), None);

    // Bare number → None (Go requires a suffix)
    assert_eq!(parse_bandwidth_limit("500"), None);

    // Case-SENSITIVE suffix (Go strings.CutSuffix): "mb"/"kb" are rejected.
    assert_eq!(parse_bandwidth_limit("1mb"), None);
    assert_eq!(parse_bandwidth_limit("1kb"), None);
    // 0 / negative number with a valid suffix → Some(0) (no limit, Go
    // NewBandwidthLimiter returns nil for bytes <= 0).
    assert_eq!(parse_bandwidth_limit("0KB"), Some(0));
    assert_eq!(parse_bandwidth_limit("-1MB"), Some(0));

    // Garbage → None
    assert_eq!(parse_bandwidth_limit("not-a-number"), None);
    assert_eq!(parse_bandwidth_limit("abc"), None);

    // Large value doesn't overflow
    assert!(parse_bandwidth_limit("999MB").is_some());
}

#[test]
fn test_auth_client_config_default() {
    let cfg = AuthClientConfig::default();
    assert_eq!(cfg.method, "token");
    assert!(cfg.token.is_empty());
    assert!(cfg.oidc_client_id.is_empty());
    assert!(cfg.oidc_client_secret.is_empty());
    assert!(cfg.oidc_audience.is_empty());
    assert!(cfg.oidc_token_endpoint.is_empty());
    assert!(cfg.oidc_scope.is_empty());
    assert!(cfg.oidc_issuer.is_empty());
    assert!(cfg.additional_endpoint_params.is_empty());
}

#[test]
fn test_parse_server_token_source_file() {
    let toml_str = r#"
bind_port = 7000

[auth.tokenSource]
type = "file"
file.path = "/tmp/frp-token"
"#;
    let cfg: ServerConfig = load_server_config_from_str(toml_str).unwrap();
    let source = cfg.auth.token_source.expect("tokenSource should parse");
    assert_eq!(source.source_type, "file");
    assert_eq!(source.file.unwrap().path, "/tmp/frp-token");
    assert!(source.exec.is_none());
}

#[test]
fn test_parse_client_token_source_exec() {
    let toml_str = r#"
server_addr = "127.0.0.1"
server_port = 7000

[auth.tokenSource]
type = "exec"
exec.command = "/bin/sh"
exec.args = ["-c", "printf '%s' \"$TOKEN\""]
exec.env = [{ name = "TOKEN", value = "secret" }]
"#;
    let cfg: ClientConfig = load_client_config_from_str(toml_str).unwrap();
    let source = cfg
        .auth
        .unwrap()
        .token_source
        .expect("tokenSource should parse");
    assert_eq!(source.source_type, "exec");
    let exec = source.exec.expect("exec source should parse");
    assert_eq!(exec.command, "/bin/sh");
    assert_eq!(exec.args, vec!["-c", "printf '%s' \"$TOKEN\""]);
    assert_eq!(exec.env.len(), 1);
    assert_eq!(exec.env[0].name, "TOKEN");
    assert_eq!(exec.env[0].value, "secret");
}

#[test]
fn test_reject_token_and_token_source_server() {
    let toml_str = r#"
bind_port = 7000

[auth]
token = "static-token"

[auth.tokenSource]
type = "file"
file.path = "/tmp/frp-token"
"#;
    let err = load_server_config_from_str(toml_str)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("cannot specify both auth.token and auth.tokenSource"),
        "{err}"
    );
}

#[test]
fn test_reject_token_and_token_source_client() {
    let toml_str = r#"
server_addr = "127.0.0.1"
server_port = 7000
token = "static-token"

[auth.tokenSource]
type = "file"
file.path = "/tmp/frp-token"
"#;
    let err = load_client_config_from_str(toml_str)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("cannot specify both auth.token and auth.tokenSource"),
        "{err}"
    );
}

#[test]
fn test_reject_unsupported_token_source_type() {
    let toml_str = r#"
bind_port = 7000

[auth.tokenSource]
type = "env"
file.path = "/tmp/frp-token"
"#;
    let err = load_server_config_from_str(toml_str)
        .unwrap_err()
        .to_string();
    assert!(err.contains("unsupported value source type"), "{err}");
}

#[test]
fn test_reject_token_source_missing_file_path() {
    let toml_str = r#"
bind_port = 7000

[auth.tokenSource]
type = "file"
file = {}
"#;
    let err = load_server_config_from_str(toml_str)
        .unwrap_err()
        .to_string();
    assert!(err.contains("file path cannot be empty"), "{err}");
}

#[test]
fn test_client_transport_flatten() {
    // Go frp client config uses [transport] section.
    // normalize_client_config should flatten it to top-level.
    let toml_str = r#"
server_addr = "127.0.0.1"
server_port = 7000
token = "test-token"

[transport]
tcp_mux = false
"#;
    let cfg: ClientConfig = load_client_config_from_str(toml_str).unwrap();
    // tcp_mux=false from [transport] should override default (true)
    assert!(!cfg.tcp_mux);
}

#[test]
fn test_client_transport_flatten_default() {
    // Without [transport] section, tcp_mux defaults to true
    let toml_str = r#"
server_addr = "127.0.0.1"
server_port = 7000
token = "test-token"
"#;
    let cfg: ClientConfig = load_client_config_from_str(toml_str).unwrap();
    assert!(cfg.tcp_mux);
    // dial_server_keepalive defaults to 7200 (Go frp default) via the serde
    // default fn — a plain `#[serde(default)]` would yield 0 (disabled),
    // silently diverging from the documented default.
    assert_eq!(cfg.dial_server_keepalive, 7200);
    // An explicit 0 is the Go zero value (util.EmptyOr) → the default 7200.
    let cfg0: ClientConfig = load_client_config_from_str(
        "server_addr = '127.0.0.1'\n[transport]\ndial_server_keepalive = 0",
    )
    .unwrap();
    assert_eq!(cfg0.dial_server_keepalive, 7200);
}

#[test]
fn test_tcp_mux_defaults_application_heartbeats_disabled_go_compat() {
    let cfg = load_client_config_from_str("server_addr = '127.0.0.1'").unwrap();

    assert!(cfg.tcp_mux);
    assert_eq!(cfg.heartbeat_interval, -1);
    assert_eq!(cfg.heartbeat_timeout, -1);
}

#[test]
fn test_tcp_mux_preserves_explicit_application_heartbeats() {
    let cfg = load_client_config_from_str(
        r#"
serverAddr = "127.0.0.1"
[transport]
heartbeatInterval = 15
heartbeatTimeout = 45
"#,
    )
    .unwrap();

    assert!(cfg.tcp_mux);
    assert_eq!(cfg.heartbeat_interval, 15);
    assert_eq!(cfg.heartbeat_timeout, 45);
}

#[test]
fn test_tcp_mux_disabled_keeps_application_heartbeat_defaults() {
    let cfg = load_client_config_from_str(
        r#"
serverAddr = "127.0.0.1"
[transport]
tcpMux = false
"#,
    )
    .unwrap();

    assert!(!cfg.tcp_mux);
    assert_eq!(cfg.heartbeat_interval, default_heartbeat_interval());
    assert_eq!(cfg.heartbeat_timeout, default_heartbeat_timeout());
}

#[test]
fn test_dial_server_timeout_zero_means_default() {
    let cfg = load_client_config_from_str(
        r#"
serverAddr = "127.0.0.1"
[transport]
dialServerTimeout = 0
"#,
    )
    .unwrap();

    assert_eq!(cfg.dial_server_timeout, default_dial_server_timeout());
}

#[test]
fn test_explicit_zero_client_heartbeats_use_go_defaults_when_tcp_mux_off() {
    // Go v0.71.0 ClientTransportConfig.Complete(): with tcpMux off,
    // HeartbeatInterval/HeartbeatTimeout = util.EmptyOr(0, 30/90) — an
    // explicit 0 means "use the default", NOT "disabled".
    let cfg = load_client_config_from_str(
        r#"
serverAddr = "127.0.0.1"
[transport]
tcpMux = false
heartbeatInterval = 0
heartbeatTimeout = 0
"#,
    )
    .unwrap();

    assert!(!cfg.tcp_mux);
    assert_eq!(cfg.heartbeat_interval, default_heartbeat_interval());
    assert_eq!(cfg.heartbeat_timeout, default_heartbeat_timeout());
}

#[test]
fn test_explicit_zero_client_pool_count_and_keepalive_use_go_defaults() {
    // Go v0.71.0 ClientTransportConfig.Complete(): PoolCount =
    // util.EmptyOr(0, 1) and DialServerKeepAlive = util.EmptyOr(0, 7200) —
    // an explicit 0 means "use the default", NOT "disabled".
    let cfg = load_client_config_from_str(
        r#"
serverAddr = "127.0.0.1"
[transport]
poolCount = 0
dialServerKeepalive = 0
"#,
    )
    .unwrap();

    assert_eq!(cfg.pool_count, 1);
    assert_eq!(cfg.dial_server_keepalive, default_dial_server_keepalive());
}

#[test]
fn test_explicit_zero_client_heartbeats_map_to_minus_one_with_tcp_mux() {
    // Go v0.71.0 util.EmptyOr(v, -1) is value-level, not presence-level:
    // with tcpMux on, an explicit 0 — like an absent heartbeat — means
    // "use the default" = -1 (disabled, yamux keepalive covers liveness).
    // The old code preserved an explicit 0 (round-8 fix 5: runtime-
    // equivalent, but Go frpc shows -1, e.g. in status output).
    let cfg = load_client_config_from_str(
        r#"
serverAddr = "127.0.0.1"
[transport]
heartbeatInterval = 0
heartbeatTimeout = 0
"#,
    )
    .unwrap();

    assert!(cfg.tcp_mux);
    assert_eq!(cfg.heartbeat_interval, -1);
    assert_eq!(cfg.heartbeat_timeout, -1);
}

#[test]
fn test_explicit_zero_server_heartbeat_timeout_uses_go_default_when_tcp_mux_off() {
    // Go v0.71.0 ServerTransportConfig.Complete(): with tcpMux off,
    // HeartbeatTimeout = util.EmptyOr(0, 90) — an explicit 0 means
    // "use the default", NOT "disabled".
    let cfg = load_server_config_from_str(
        r#"
bindPort = 7000
[transport]
tcpMux = false
heartbeatTimeout = 0
"#,
    )
    .unwrap();

    assert_eq!(cfg.transport.tcp_mux, Some(false));
    assert_eq!(cfg.transport.heartbeat_timeout, default_heartbeat_timeout());
}

#[test]
fn test_server_tcp_mux_default_forces_heartbeat_timeout_disabled() {
    // Go v0.71.0: with tcpMux on (default) and no explicit heartbeat
    // timeout, the application-layer heartbeat is forced to -1 (yamux
    // keepalive covers liveness).
    let cfg = load_server_config_from_str("bindPort = 7000").unwrap();
    assert_eq!(cfg.transport.heartbeat_timeout, -1);
}

#[test]
fn test_go_v0701_server_transport_mux_toml() {
    let cfg = load_server_config_from_str(
        r#"
bindPort = 7000
[transport]
tcpMux = false
tcpMuxKeepaliveInterval = 15
"#,
    )
    .unwrap();

    assert_eq!(cfg.transport.tcp_mux, Some(false));
    assert_eq!(cfg.transport.tcp_mux_keepalive_interval, 15);
}

#[test]
fn test_server_tcp_mux_keepalive_omitted_defaults_to_30() {
    // Go v0.71.0: TcpMuxKeepaliveInterval = EmptyOr(0, 30) — omitted OR
    // explicit 0 resolves to 30, NOT the runtime `.max(1)` (1s scan).
    let cfg = load_server_config_from_str(
        r#"
bindPort = 7000
"#,
    )
    .unwrap();
    assert_eq!(cfg.transport.tcp_mux_keepalive_interval, 30);
}

#[test]
fn test_server_tcp_mux_keepalive_explicit_zero_defaults_to_30() {
    let cfg = load_server_config_from_str(
        r#"
bindPort = 7000
[transport]
tcpMuxKeepaliveInterval = 0
"#,
    )
    .unwrap();
    assert_eq!(cfg.transport.tcp_mux_keepalive_interval, 30);
}

#[test]
fn test_client_tcp_mux_keepalive_omitted_defaults_to_30() {
    let cfg = load_client_config_from_str(
        r#"
serverAddr = "127.0.0.1"
"#,
    )
    .unwrap();
    assert_eq!(cfg.tcp_mux_keepalive_interval, 30);
}

#[test]
fn test_client_tcp_mux_keepalive_explicit_zero_defaults_to_30() {
    let cfg = load_client_config_from_str(
        r#"
serverAddr = "127.0.0.1"
[transport]
tcpMuxKeepaliveInterval = 0
"#,
    )
    .unwrap();
    assert_eq!(cfg.tcp_mux_keepalive_interval, 30);
}

#[test]
fn test_client_tcp_mux_keepalive_explicit_value_preserved() {
    let cfg = load_client_config_from_str(
        r#"
serverAddr = "127.0.0.1"
[transport]
tcpMuxKeepaliveInterval = 45
"#,
    )
    .unwrap();
    assert_eq!(cfg.tcp_mux_keepalive_interval, 45);
}

#[test]
fn test_tcp_mux_keepalive_timeout_defaults_to_zero() {
    // 0 = auto (default): omitted on both sides resolves to 0, and 0 must
    // NOT be normalized away to 30 like the keepalive interval is.
    let server = load_server_config_from_str("bindPort = 7000").unwrap();
    assert_eq!(server.transport.tcp_mux_keepalive_timeout, 0);
    let client = load_client_config_from_str("serverAddr = '127.0.0.1'").unwrap();
    assert_eq!(client.tcp_mux_keepalive_timeout, 0);
}

#[test]
fn test_tcp_mux_keepalive_timeout_positive_negative_zero_parse() {
    // Positive: explicit bound, preserved as-is (no floor here — the floor
    // is applied at the mux layer via idle_dead_bound).
    let positive = load_server_config_from_str(
        r#"
bindPort = 7000
[transport]
tcpMuxKeepaliveTimeout = 3600
"#,
    )
    .unwrap();
    assert_eq!(positive.transport.tcp_mux_keepalive_timeout, 3600);

    // Negative: disable the reaper.
    let negative = load_server_config_from_str(
        r#"
bindPort = 7000
[transport]
tcpMuxKeepaliveTimeout = -1
"#,
    )
    .unwrap();
    assert_eq!(negative.transport.tcp_mux_keepalive_timeout, -1);

    // Zero: auto (explicit 0 stays 0 — no EmptyOr normalization).
    let zero = load_server_config_from_str(
        r#"
bindPort = 7000
[transport]
tcpMuxKeepaliveTimeout = 0
"#,
    )
    .unwrap();
    assert_eq!(zero.transport.tcp_mux_keepalive_timeout, 0);
}

#[test]
fn test_tcp_mux_keepalive_timeout_camel_case_alias_maps() {
    // camelCase `tcpMuxKeepaliveTimeout` must map to the snake_case field
    // on both server and client.
    let server = load_server_config_from_str(
        r#"
bindPort = 7000
[transport]
tcpMuxKeepaliveTimeout = 120
"#,
    )
    .unwrap();
    assert_eq!(server.transport.tcp_mux_keepalive_timeout, 120);

    let client = load_client_config_from_str(
        r#"
serverAddr = "127.0.0.1"
[transport]
tcpMuxKeepaliveTimeout = 120
"#,
    )
    .unwrap();
    assert_eq!(client.tcp_mux_keepalive_timeout, 120);
}

#[test]
fn test_explicit_server_heartbeat_timeout_90_is_preserved_with_tcp_mux() {
    let cfg = load_server_config_from_str(
        r#"
bindPort = 7000
[transport]
heartbeatTimeout = 90
"#,
    )
    .unwrap();

    assert_eq!(cfg.transport.heartbeat_timeout, 90);
}

#[test]
fn test_explicit_client_heartbeat_timeout_90_is_preserved_with_tcp_mux() {
    // Round-8 fix 7a: pins the presence mechanism — an explicit
    // heartbeatTimeout = 90 with tcpMux on (default) must survive
    // complete() as 90, not be zeroed or mapped to -1 (only 0 and the
    // absent default map to -1; fix 5).
    let cfg = load_client_config_from_str(
        r#"
serverAddr = "127.0.0.1"
[transport]
heartbeatTimeout = 90
"#,
    )
    .unwrap();

    assert!(cfg.tcp_mux);
    assert_eq!(cfg.heartbeat_timeout, 90);
}

#[test]
fn test_explicit_server_heartbeat_timeout_7200_is_preserved() {
    // Round-8 fix 7d: no clamp — a Go-frpc-scale value (7200) must pass
    // through the server loader untouched (Go frp has no clamp).
    let cfg = load_server_config_from_str(
        r#"
bindPort = 7000
[transport]
heartbeatTimeout = 7200
"#,
    )
    .unwrap();

    assert_eq!(cfg.transport.heartbeat_timeout, 7200);
}

#[test]
fn test_client_server_addr_defaults_to_go_zero_value() {
    // Round-8 fix 7b: Go client.go:86 ClientCommonConfig.Complete() —
    // ServerAddr = util.EmptyOr(ServerAddr, "0.0.0.0"). A config without
    // serverAddr must normalize to "0.0.0.0", not error or empty-string.
    let cfg = load_client_config_from_str("serverPort = 7000").unwrap();
    assert_eq!(cfg.server_addr, "0.0.0.0");
}

#[test]
fn test_explicit_disabled_client_heartbeat_is_preserved() {
    let cfg = load_client_config_from_str(
        r#"
serverAddr = "127.0.0.1"
[transport]
heartbeatInterval = -1
heartbeatTimeout = -1
"#,
    )
    .unwrap();

    assert!(cfg.tcp_mux);
    assert_eq!(cfg.heartbeat_interval, -1);
    assert_eq!(cfg.heartbeat_timeout, -1);
}

#[test]
fn test_go_v0701_client_transport_toml() {
    let toml_str = r#"
serverAddr = "127.0.0.1"
serverPort = 7000

[transport]
protocol = "quic"
tcpMux = false

[transport.tls]
enable = false
serverName = "frps.example.com"
disableCustomTLSFirstByte = false
"#;
    let cfg = load_client_config_from_str(toml_str).unwrap();

    assert_eq!(cfg.transport_protocol, "quic");
    assert!(!cfg.tcp_mux);
    assert!(!cfg.tls_enable);
    assert_eq!(cfg.tls_server_name, "frps.example.com");
    assert!(!cfg.disable_custom_tls_first_byte);
}

#[test]
fn test_go_v0701_server_transport_tls_toml() {
    let toml_str = r#"
bindPort = 7000

[transport.tls]
force = true
certFile = "/etc/frp/server.crt"
keyFile = "/etc/frp/server.key"
trustedCaFile = "/etc/frp/clients-ca.crt"
serverName = "frps.example.com"
"#;
    let cfg = load_server_config_from_str(toml_str).unwrap();

    assert!(cfg.tls_only);
    assert!(cfg.tls_enable);
    assert_eq!(cfg.tls_cert_file, "/etc/frp/server.crt");
    assert_eq!(cfg.tls_key_file, "/etc/frp/server.key");
    assert_eq!(cfg.tls_ca_file, "/etc/frp/clients-ca.crt");
    assert_eq!(cfg.tls_server_name, "frps.example.com");
}

#[test]
fn test_server_legacy_tls_fields_override_canonical_transport_tls() {
    let toml_str = r#"
tls_enable = false
tls_cert_file = "/legacy/server.crt"
tls_key_file = "/legacy/server.key"
tls_ca_file = "/legacy/clients-ca.crt"

[transport.tls]
force = true
certFile = "/canonical/server.crt"
keyFile = "/canonical/server.key"
trustedCaFile = "/canonical/clients-ca.crt"
serverName = "frps.example.com"
"#;
    let cfg = load_server_config_from_str(toml_str).unwrap();

    assert!(!cfg.tls_enable);
    assert_eq!(cfg.tls_cert_file, "/legacy/server.crt");
    assert_eq!(cfg.tls_key_file, "/legacy/server.key");
    assert_eq!(cfg.tls_ca_file, "/legacy/clients-ca.crt");
    assert!(cfg.tls_only);
    assert_eq!(cfg.tls_server_name, "frps.example.com");
}

#[test]
fn test_server_legacy_tls_only_overrides_canonical_force() {
    let cfg = load_server_config_from_str(
        r#"
tls_only = false

[transport.tls]
force = true
"#,
    )
    .unwrap();

    assert!(!cfg.tls_only);
}

#[test]
fn test_server_canonical_trusted_ca_alone_forces_tls_only_on_complete() {
    let cfg = load_server_config_from_str(
        r#"
[transport.tls]
trustedCaFile = "/etc/frp/clients-ca.crt"
"#,
    )
    .unwrap();

    assert_eq!(cfg.tls_ca_file, "/etc/frp/clients-ca.crt");
    assert!(cfg.tls_only);
}

#[test]
fn test_client_legacy_transport_tls_fields_override_canonical_nested_fields() {
    let cfg = load_client_config_from_str(
        r#"
serverAddr = "127.0.0.1"
transport_protocol = "tcp"
tcp_mux = true
tls_enable = false
tls_cert_file = "/legacy/client.crt"
tls_key_file = "/legacy/client.key"
tls_ca_file = "/legacy/server-ca.crt"
tls_server_name = "legacy.example.com"
disable_custom_tls_first_byte = true

[transport]
protocol = "quic"
tcpMux = false

[transport.tls]
enable = true
certFile = "/canonical/client.crt"
keyFile = "/canonical/client.key"
trustedCaFile = "/canonical/server-ca.crt"
serverName = "canonical.example.com"
disableCustomTLSFirstByte = false
"#,
    )
    .unwrap();

    assert_eq!(cfg.transport_protocol, "tcp");
    assert!(cfg.tcp_mux);
    assert!(!cfg.tls_enable);
    assert_eq!(cfg.tls_cert_file, "/legacy/client.crt");
    assert_eq!(cfg.tls_key_file, "/legacy/client.key");
    assert_eq!(cfg.tls_ca_file, "/legacy/server-ca.crt");
    assert_eq!(cfg.tls_server_name, "legacy.example.com");
    assert!(cfg.disable_custom_tls_first_byte);
}

#[test]
fn test_strict_mode_accepts_go_v0701_transport_keys() {
    let mut client_file = tempfile::NamedTempFile::new().unwrap();
    client_file
        .write_all(
            br#"serverAddr = "127.0.0.1"
[transport]
protocol = "quic"
tcpMux = false
[transport.tls]
enable = true
serverName = "frps.example.com"
disableCustomTLSFirstByte = false
"#,
        )
        .unwrap();
    load_client_config(client_file.path().to_str().unwrap(), true).unwrap();

    let mut server_file = tempfile::NamedTempFile::new().unwrap();
    server_file
        .write_all(
            br#"bindPort = 7000
[transport]
tcpMux = false
tcpMuxKeepaliveInterval = 30
[transport.tls]
force = true
certFile = "/etc/frp/server.crt"
keyFile = "/etc/frp/server.key"
trustedCaFile = "/etc/frp/clients-ca.crt"
serverName = "frps.example.com"
"#,
        )
        .unwrap();
    load_server_config(server_file.path().to_str().unwrap(), true).unwrap();
}

#[test]
fn test_strict_mode_rejects_transport_and_tls_typos() {
    let mut client_file = tempfile::NamedTempFile::new().unwrap();
    client_file
        .write_all(
            br#"serverAddr = "127.0.0.1"
[transport]
protcol = "quic"
[transport.tls]
enabel = true
"#,
        )
        .unwrap();

    let error = load_client_config(client_file.path().to_str().unwrap(), true)
        .unwrap_err()
        .to_string();
    assert!(error.contains("protcol"));
    assert!(error.contains("enabel"));
}

#[test]
fn test_oidc_additional_endpoint_params_map() {
    // Go frp v0.70.1: AuthOIDCClientConfig.AdditionalEndpointParams is a
    // map[string]string — TOML table must parse into a HashMap, not a
    // "k=v&k=v" string.
    let toml = r#"
            server_addr = "127.0.0.1"
            server_port = 7000
            auth_method = "oidc"
            [auth]
            method = "oidc"
            [auth.oidc]
            clientID = "client-1"
            tokenEndpointURL = "https://idp.example.com/token"
            additionalEndpointParams = { tenant = "acme", region = "eu" }
        "#;
    let cfg: super::ClientConfig = super::load_client_config_from_str(toml).unwrap();
    let auth = cfg.auth.expect("auth section");
    assert_eq!(
        auth.additional_endpoint_params
            .get("tenant")
            .map(String::as_str),
        Some("acme")
    );
    assert_eq!(
        auth.additional_endpoint_params
            .get("region")
            .map(String::as_str),
        Some("eu")
    );
}

#[test]
fn test_oidc_token_source_parsed_from_subtable() {
    let toml = r#"
            server_addr = "127.0.0.1"
            server_port = 7000
            auth_method = "oidc"
            [auth]
            method = "oidc"
            [auth.oidc]
            tokenSource = { type = "file", file = { path = "/tmp/oidc-token" } }
        "#;
    let cfg: super::ClientConfig = super::load_client_config_from_str(toml).unwrap();
    let auth = cfg.auth.expect("auth section");
    let source = auth
        .oidc_token_source
        .expect("oidc.tokenSource should parse");
    assert_eq!(source.source_type, "file");
    assert_eq!(
        source.file.as_ref().map(|f| f.path.as_str()),
        Some("/tmp/oidc-token")
    );
}

#[test]
fn test_oidc_token_source_mutually_exclusive_with_other_fields() {
    let toml = r#"
            server_addr = "127.0.0.1"
            server_port = 7000
            auth_method = "oidc"
            [auth]
            method = "oidc"
            [auth.oidc]
            clientID = "client-1"
            tokenSource = { type = "file", file = { path = "/tmp/tok" } }
        "#;
    let err = super::load_client_config_from_str(toml)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("cannot specify both auth.oidc.tokenSource"),
        "expected mutual-exclusivity error, got: {err}"
    );
}

#[test]
fn test_oidc_requires_client_id_and_token_endpoint() {
    // Missing clientID
    let toml = r#"
            server_addr = "127.0.0.1"
            server_port = 7000
            auth_method = "oidc"
            [auth]
            method = "oidc"
            [auth.oidc]
            tokenEndpointURL = "https://idp.example.com/token"
        "#;
    let err = super::load_client_config_from_str(toml)
        .unwrap_err()
        .to_string();
    assert!(err.contains("clientID is required"), "got: {err}");

    // Missing token endpoint (and no issuer for discovery)
    let toml2 = r#"
            server_addr = "127.0.0.1"
            server_port = 7000
            auth_method = "oidc"
            [auth]
            method = "oidc"
            [auth.oidc]
            clientID = "client-1"
        "#;
    let err2 = super::load_client_config_from_str(toml2)
        .unwrap_err()
        .to_string();
    assert!(err2.contains("tokenEndpointURL is required"), "got: {err2}");
}

#[test]
fn test_oidc_additional_endpoint_params_scope_rejected() {
    let toml = r#"
            server_addr = "127.0.0.1"
            server_port = 7000
            auth_method = "oidc"
            [auth]
            method = "oidc"
            [auth.oidc]
            clientID = "client-1"
            tokenEndpointURL = "https://idp.example.com/token"
            additionalEndpointParams = { scope = "openid" }
        "#;
    let err = super::load_client_config_from_str(toml)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("additionalEndpointParams.scope is not allowed"),
        "got: {err}"
    );
}

#[test]
fn test_strict_mode_accepts_server_tls_server_name_alias() {
    let mut server_file = tempfile::NamedTempFile::new().unwrap();
    server_file
        .write_all(
            br#"bindPort = 7000
tlsServerName = "frps.example.com"
"#,
        )
        .unwrap();

    let cfg = load_server_config(server_file.path().to_str().unwrap(), true).unwrap();
    assert_eq!(cfg.tls_server_name, "frps.example.com");
}

/// Regression pin for `docs/config.md`: the four flat server TLS rows used to
/// advertise `tlsOnly` / `tlsCertFile` / `tlsKeyFile` / `tlsCaFile` as their
/// "Go frp Equivalent". No loader accepts them — `frp-core/src/config/server.rs:42-56`
/// declares those fields with `#[serde(default)]` and no alias, and Go
/// v0.71.0 carries them under the nested `[transport.tls]` section, which
/// `frp-core/src/config/normalize.rs:908-935` maps onto the flat fields.
/// This pins both directions (the four stay rejected, the two real aliases
/// stay accepted) so the table cannot drift back.
#[test]
fn test_flat_camelcase_tls_spellings_are_not_loader_spellings() {
    let rejected = [
        ("tlsOnly", "true"),
        ("tlsCertFile", "\"/cc.crt\""),
        ("tlsKeyFile", "\"/cc.key\""),
        ("tlsCaFile", "\"/cc-ca.crt\""),
    ];

    // 1. Non-strict (the SIGUSR1 reload mode): ignored, every field stays at
    //    its default. In particular `tlsCaFile` must not trigger the
    //    ca-implies-only fill at `frp-core/src/config/server.rs:539-540`.
    for &(key, value) in rejected.iter() {
        let cfg = load_server_config_from_str(&format!("bind_port = 7000\n{key} = {value}\n"))
            .unwrap_or_else(|e| panic!("{key} must not fail the non-strict load: {e}"));
        assert!(!cfg.tls_only, "{key} unexpectedly set tls_only");
        assert_eq!(
            cfg.tls_cert_file, "",
            "{key} unexpectedly set tls_cert_file"
        );
        assert_eq!(cfg.tls_key_file, "", "{key} unexpectedly set tls_key_file");
        assert_eq!(cfg.tls_ca_file, "", "{key} unexpectedly set tls_ca_file");
    }

    // 2. Strict (frps's default): each is refused, and the message names the
    //    offending key.
    for &(key, value) in rejected.iter() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        write!(file, "bind_port = 7000\n{key} = {value}\n").unwrap();
        let err = load_server_config_uncompleted(file.path().to_str().unwrap(), true)
            .expect_err("camelCase flat spelling must be refused in strict mode")
            .to_string();
        assert!(
            err.contains(key),
            "{key} refused, but the message does not name it: {err}"
        );
    }

    // 3. The two flat aliases that DO work load in both modes.
    let aliases = "tlsServerName = \"frps.example.com\"\ntls_trusted_ca_file = \"/cc-ca.crt\"\n";
    let cfg = load_server_config_from_str(&format!("bind_port = 7000\n{aliases}")).unwrap();
    assert_eq!(cfg.tls_server_name, "frps.example.com");
    assert_eq!(cfg.tls_ca_file, "/cc-ca.crt");
    assert!(cfg.tls_only, "tls_ca_file should complete tls_only to true");

    let mut file = tempfile::NamedTempFile::new().unwrap();
    write!(file, "bind_port = 7000\n{aliases}").unwrap();
    let cfg = load_server_config_uncompleted(file.path().to_str().unwrap(), true).unwrap();
    assert_eq!(cfg.tls_server_name, "frps.example.com");
    assert_eq!(cfg.tls_ca_file, "/cc-ca.crt");

    // 4. The strict-mode allow-list agrees: the two aliases are in it and the
    //    four camelCase spellings are not. `known_server_keys` is `pub(super)`
    //    and this module is a child of `config`, so it is reachable without
    //    widening its visibility.
    let known = super::strict::known_server_keys();
    assert!(known.contains("tlsServerName"));
    assert!(known.contains("tls_trusted_ca_file"));
    for &(key, _) in rejected.iter() {
        assert!(
            !known.contains(key),
            "{key} must not be in known_server_keys()"
        );
    }
}

/// Regression pin for `docs/config.md`: the four flat client TLS rows used to
/// advertise `tlsEnable` / `tlsCertFile` / `tlsKeyFile` / `tlsCaFile` (and the
/// second `tlsTrustedCaFile` spelling of the `tls_ca_file` row) as their
/// "Go frp Equivalent". No loader accepts them —
/// `frp-core/src/config/client.rs:264-270` declares those fields with
/// `#[serde(default)]` and no alias, and Go v0.71.0 carries them under the
/// nested `[transport.tls]` section, which
/// `frp-core/src/config/normalize.rs:1443-1454` maps onto the flat fields.
/// This pins both directions (the five spellings stay rejected, the two real
/// aliases stay accepted) so the table cannot drift back.
#[test]
fn test_flat_camelcase_client_tls_spellings_are_not_loader_spellings() {
    let rejected = [
        ("tlsEnable", "false"),
        ("tlsCertFile", "\"/cc.crt\""),
        ("tlsKeyFile", "\"/cc.key\""),
        ("tlsCaFile", "\"/cc-ca.crt\""),
        ("tlsTrustedCaFile", "\"/cc-ca.crt\""),
    ];

    // 1. Non-strict (the SIGUSR1 reload mode): ignored, every field stays at
    //    its default — `tls_enable` keeps the client's `true` default, so a
    //    flat `tlsEnable = false` must not clear it.
    for &(key, value) in rejected.iter() {
        let cfg =
            load_client_config_from_str(&format!("server_addr = '127.0.0.1'\n{key} = {value}\n"))
                .unwrap_or_else(|e| panic!("{key} must not fail the non-strict load: {e}"));
        assert!(cfg.tls_enable, "{key} unexpectedly cleared tls_enable");
        assert_eq!(
            cfg.tls_cert_file, "",
            "{key} unexpectedly set tls_cert_file"
        );
        assert_eq!(cfg.tls_key_file, "", "{key} unexpectedly set tls_key_file");
        assert_eq!(cfg.tls_ca_file, "", "{key} unexpectedly set tls_ca_file");
    }

    // 2. Strict (frpc's default): each is refused, and the message names the
    //    offending key.
    for &(key, value) in rejected.iter() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        write!(file, "server_addr = '127.0.0.1'\n{key} = {value}\n").unwrap();
        let err = super::file::load_client_config(file.path().to_str().unwrap(), true)
            .expect_err("camelCase flat spelling must be refused in strict mode")
            .to_string();
        assert!(
            err.contains(key),
            "{key} refused, but the message does not name it: {err}"
        );
    }

    // 3. The nested `[transport.tls]` spellings DO load, in both modes, and
    //    land on the same flat fields.
    let nested = "[transport.tls]\nenable = false\ncertFile = \"/n.crt\"\nkeyFile = \"/n.key\"\ntrustedCaFile = \"/n-ca.crt\"\n";
    let cfg = load_client_config_from_str(&format!("server_addr = '127.0.0.1'\n{nested}")).unwrap();
    assert!(!cfg.tls_enable);
    assert_eq!(cfg.tls_cert_file, "/n.crt");
    assert_eq!(cfg.tls_key_file, "/n.key");
    assert_eq!(cfg.tls_ca_file, "/n-ca.crt");

    let mut file = tempfile::NamedTempFile::new().unwrap();
    write!(file, "server_addr = '127.0.0.1'\n{nested}").unwrap();
    let cfg = super::file::load_client_config(file.path().to_str().unwrap(), true).unwrap();
    assert!(!cfg.tls_enable);
    assert_eq!(cfg.tls_cert_file, "/n.crt");
    assert_eq!(cfg.tls_key_file, "/n.key");
    assert_eq!(cfg.tls_ca_file, "/n-ca.crt");

    // 4. The two flat aliases that DO work load in both modes, and the
    //    strict-mode allow-list agrees: they are in it and the five camelCase
    //    spellings are not. `known_client_keys` is `pub(super)` and this module
    //    is a child of `config`, so it is reachable without widening its
    //    visibility.
    let aliases = "tlsServerName = \"frpc.example.com\"\ndisableCustomTLSFirstByte = false\n";
    let cfg =
        load_client_config_from_str(&format!("server_addr = '127.0.0.1'\n{aliases}")).unwrap();
    assert_eq!(cfg.tls_server_name, "frpc.example.com");
    assert!(!cfg.disable_custom_tls_first_byte);

    let mut file = tempfile::NamedTempFile::new().unwrap();
    write!(file, "server_addr = '127.0.0.1'\n{aliases}").unwrap();
    let cfg = super::file::load_client_config(file.path().to_str().unwrap(), true).unwrap();
    assert_eq!(cfg.tls_server_name, "frpc.example.com");
    assert!(!cfg.disable_custom_tls_first_byte);

    let known = super::strict::known_client_keys();
    assert!(known.contains("tlsServerName"));
    assert!(known.contains("disableCustomTLSFirstByte"));
    for &(key, _) in rejected.iter() {
        assert!(
            !known.contains(key),
            "{key} must not be in known_client_keys()"
        );
    }
}

#[test]
fn test_client_disable_custom_tls_first_byte_defaults_match_go() {
    assert!(ClientConfig::default().disable_custom_tls_first_byte);

    let cfg: ClientConfig = toml::from_str("server_addr = '127.0.0.1'").unwrap();
    assert!(cfg.disable_custom_tls_first_byte);
}

#[test]
fn test_levenshtein() {
    assert_eq!(levenshtein("server_addr", "serverAddr"), 2); // delete '_' + case change
    assert_eq!(levenshtein("bind_port", "bindPort"), 2); // delete '_' + case change
    assert_eq!(levenshtein("token", "tokens"), 1);
    assert_eq!(levenshtein("abc", "xyz"), 3);
    assert_eq!(levenshtein("", ""), 0);
    assert_eq!(levenshtein("a", ""), 1);
}

#[test]
fn test_unknown_field_suggestion() {
    // Build a simple toml table with an unknown key (flat, no sections)
    let toml_str = "token = \"test\"\nserverAddr = \"1.2.3.4\"\n";
    let value: toml::Value = toml::from_str(toml_str).unwrap();
    let known: std::collections::HashSet<&str> = ["token", "server_addr"].iter().copied().collect();
    let errors = check_strict(value.as_table().unwrap(), &known, "", "test.toml");
    assert_eq!(errors.len(), 1);
    assert!(errors[0].contains("did you mean 'server_addr'"));
}

/// `run_strict_check` reports **every** unknown key, joined with `\n`
/// (`errors.join("\n")` in `frp-core/src/config/strict.rs`), not just the first.
///
/// That is what makes a CLI config-load failure **N lines for N rejected keys**,
/// where Go's decoder sets `DisallowUnknownFields` on one `decoder.Decode(out)`
/// call (`pkg/util/jsonx/json_v1.go:43-44`, reached from
/// `pkg/config/v1/decode.go:29-33`) and returns at the **first** unknown field,
/// so Go prints one line whatever N is. The divergence is recorded as deliberate
/// in `docs/developing.md` § CLI exit codes → *Output stream and shape on a
/// config-load failure*, and it is pinned **here** because every CLI fixture in
/// `frpc/tests/cli_exit_codes.rs` and `frps/tests/cli_exit_codes.rs` carries
/// exactly one unknown key — none of them can see this count move.
///
/// The order is pinned too, and it is why the two binaries name the same key
/// first: `toml::Table` iterates in **key-name** order, so `zzz_bad, mmm_bad,
/// aaa_bad` in the document comes out as `aaa_bad, mmm_bad, zzz_bad` here, and
/// the key Go names first is that same alphabetically-first one — measured on
/// both binaries with the document order permuted (with `zzz…, another…,
/// third…`, Go names `another…` and frp-rs names `another…` first).
#[test]
fn strict_check_reports_every_unknown_key_not_just_the_first() {
    let toml_str = "server_addr = \"127.0.0.1\"\nserver_port = 7000\n\
                    zzz_bad = 1\nmmm_bad = 2\naaa_bad = 3\n";
    let value: toml::Value = toml::from_str(toml_str).unwrap();
    let known: std::collections::HashSet<&str> =
        ["server_addr", "server_port"].iter().copied().collect();

    let err = super::strict::run_strict_check(&value, &known, "t.toml")
        .expect_err("three unknown keys must be refused")
        .to_string();

    let lines: Vec<&str> = err.lines().collect();
    assert_eq!(
        lines.len(),
        3,
        "one line per rejected key (Go prints one line for all three); got {err:?}"
    );
    for (line, key) in lines.iter().zip(["aaa_bad", "mmm_bad", "zzz_bad"]) {
        assert_eq!(
            *line,
            format!("unknown field \"{key}\" in config file t.toml"),
            "each line names its own key, in key-name order, with no suggestion \
             for these keys; got {err:?}"
        );
    }
}

#[test]
fn test_auth_client_config_oidc_method() {
    // When method is "oidc", oidc_* fields should be usable
    let cfg = AuthClientConfig {
        method: "oidc".into(),
        oidc_client_id: "client-123".into(),
        oidc_client_secret: "secret-456".into(),
        oidc_audience: "https://api.example.com".into(),
        oidc_issuer: "https://auth.example.com".into(),
        oidc_scope: "openid profile".into(),
        oidc_token_endpoint: "https://auth.example.com/token".into(),
        ..Default::default()
    };
    assert_eq!(cfg.method, "oidc");
    assert_eq!(cfg.oidc_client_id, "client-123");
    assert_eq!(cfg.oidc_audience, "https://api.example.com");
}

/// The load-path half of the one `auth.method` policy
/// (`frp_core::auth::parse_auth_method`): both config entry points complete an
/// empty method to `token` (Go's `AuthServerConfig.Complete`,
/// `pkg/config/v1/server.go:136-139`) and reject anything that is not exactly
/// `token`/`oidc` with Go's text (`validation/server.go:31`,
/// `validation/client.go:101`). Before this, `"OIDC"` loaded on the client and
/// skipped its OIDC client-credentials check, while the server lowercased the
/// same spelling into OIDC.
///
/// Measured against Go v0.71.0 (`frps -c <method = "OIDC">`): rc 1, 54 B
/// stdout, 0 B stderr, stdout exactly
/// `invalid auth method, optional values are [token oidc]\n`. This test pins
/// the *text* returned by the loaders; the rc and the stream belong to the CLI
/// probes in `frps/tests/cli_exit_codes.rs` and `frpc/tests/cli_exit_codes.rs`.
#[test]
fn auth_method_is_completed_then_validated_exactly() {
    const GO_TEXT: &str = "invalid auth method, optional values are [token oidc]";

    // 1. Client, `[auth]` present with the method absent or explicitly empty →
    //    completed to `token` and loads. This is Go's `util.EmptyOr`; it must
    //    keep working.
    for empty in [
        "[auth]\ntoken = \"t\"\n",
        "[auth]\ntoken = \"t\"\nmethod = \"\"\n",
    ] {
        let toml = format!("serverAddr = \"127.0.0.1\"\n{empty}");
        let cfg = load_client_config_from_str(&toml)
            .unwrap_or_else(|e| panic!("{empty:?} must load (empty → token): {e}"));
        assert_eq!(
            cfg.auth.as_ref().map(|a| a.method.as_str()),
            Some("token"),
            "the loader must hand on the completed value"
        );
    }

    // 2. Server, same shape.
    let cfg = load_server_config_from_str("bindPort = 7100\n\n[auth]\ntoken = \"t\"\n")
        .expect("a server config with no method must load (empty → token)");
    assert_eq!(cfg.auth.method, "token");

    // 3. Client, every spelling Go rejects. The `oidc` fields are deliberately
    //    EMPTY: with the old `auth.method != "oidc"` early return the
    //    client-credentials check was skipped for all of these, so this also
    //    asserts the method error *wins* over the missing-`clientID` error and
    //    carries Go's text rather than "auth.oidc.clientID is required".
    for bad in ["OIDC", "Oidc", " oidc", "oidc ", "tokenn", "\u{043e}idc"] {
        let toml = format!("serverAddr = \"127.0.0.1\"\n\n[auth]\nmethod = \"{bad}\"\n");
        let err = load_client_config_from_str(&toml)
            .expect_err(&format!("client method {bad:?} must be a load error"))
            .to_string();
        assert!(
            err.ends_with(GO_TEXT),
            "client method {bad:?}: expected Go's text, got {err:?}"
        );
        assert!(
            !err.contains("clientID"),
            "client method {bad:?}: the method check must precede the OIDC \
             credentials check; got {err:?}"
        );
    }

    // 4. Server, same spellings.
    for bad in ["OIDC", " oidc", "tokenn"] {
        let toml = format!("bindPort = 7100\n\n[auth]\nmethod = \"{bad}\"\n");
        let err = load_server_config_from_str(&toml)
            .expect_err(&format!("server method {bad:?} must be a load error"))
            .to_string();
        assert!(
            err.ends_with(GO_TEXT),
            "server method {bad:?}: expected Go's text, got {err:?}"
        );
    }
}

#[test]
fn test_ssh_tunnel_gateway_config_snake_case() {
    let toml = r#"
bind_port = 7000

[ssh_tunnel_gateway]
bind_port = 2200
bind_addr = "0.0.0.0"
private_key_file = "/etc/frp/ssh_host_key"
auto_gen_private_key_path = "/var/lib/frp/ssh_key"
authorized_keys_file = "/etc/frp/authorized_keys"
"#;
    let cfg: ServerConfig = toml::from_str(toml).unwrap();
    assert_eq!(cfg.ssh_tunnel_gateway.bind_port, 2200);
    assert_eq!(cfg.ssh_tunnel_gateway.bind_addr, "0.0.0.0");
    assert_eq!(
        cfg.ssh_tunnel_gateway.private_key_file,
        "/etc/frp/ssh_host_key"
    );
    assert_eq!(
        cfg.ssh_tunnel_gateway.auto_gen_private_key_path,
        "/var/lib/frp/ssh_key"
    );
    assert_eq!(
        cfg.ssh_tunnel_gateway.authorized_keys_file,
        "/etc/frp/authorized_keys"
    );
}

#[test]
fn test_ssh_tunnel_gateway_config_camel_case() {
    let toml = r#"
bindPort = 7000

[sshTunnelGateway]
bindPort = 2200
"#;
    let cfg: ServerConfig = load_server_config_from_str(toml).unwrap();
    assert_eq!(cfg.ssh_tunnel_gateway.bind_port, 2200);
}

#[test]
fn test_ssh_tunnel_gateway_default_disabled() {
    let toml = r#"bind_port = 7000"#;
    let cfg: ServerConfig = toml::from_str(toml).unwrap();
    assert_eq!(cfg.ssh_tunnel_gateway.bind_port, 0);
}

// ─── Property-based tests (proptest) ───────────────────────────────

/// Helper: normalize a TOML string through the full server config pipeline
/// and return the re-serialized TOML (post-normalization).
fn normalize_server_toml(toml_str: &str) -> String {
    let mut val: toml::Value = toml::from_str(toml_str).unwrap();
    normalize_server_config(&mut val, super::format::ConfigFormat::Toml).unwrap();
    toml::to_string(&val).unwrap()
}

/// Helper: normalize a TOML string through the full client config pipeline.
fn normalize_client_toml(toml_str: &str) -> String {
    let mut val: toml::Value = toml::from_str(toml_str).unwrap();
    normalize_client_config(&mut val, super::format::ConfigFormat::Toml).unwrap();
    toml::to_string(&val).unwrap()
}

mod proptest_tests {
    use proptest::prelude::*;

    // ── Strategies ────────────────────────────────────────────────

    /// Generate a valid server TOML config with [common] section.
    fn arb_server_common_config() -> impl Strategy<Value = String> {
        (any::<u16>(), any::<u16>(), any::<u16>(), any::<u16>()).prop_map(
            |(bind_port, vhost_http, vhost_https, dash_port)| {
                format!(
                    "[common]\n\
                         bind_port = {bind_port}\n\
                         vhost_http_port = {vhost_http}\n\
                         vhost_https_port = {vhost_https}\n\
                         web_server_port = {dash_port}\n"
                )
            },
        )
    }

    /// Generate a valid client TOML config with [common] section.
    fn arb_client_common_config() -> impl Strategy<Value = String> {
        (any::<u16>(), "[a-zA-Z0-9._-]{1,16}").prop_map(|(port, addr)| {
            format!(
                "[common]\n\
                     server_addr = \"{addr}\"\n\
                     server_port = {port}\n\
                     token = \"test-token\"\n"
            )
        })
    }

    // ── Server config properties ──────────────────────────────────

    proptest! {
        /// Server config normalization is idempotent: applying it twice
        /// produces the same result as applying it once.
        #[test]
        fn server_normalization_idempotent(toml_str in arb_server_common_config()) {
            let first = super::normalize_server_toml(&toml_str);
            let second = super::normalize_server_toml(&first);
            prop_assert_eq!(first, second,
                "normalize(normalize(x)) != normalize(x)");
        }
    }

    proptest! {
        /// Server config: flat auth fields produce same result as nested [auth].
        #[test]
        fn server_auth_flat_vs_nested_equivalent(
            bind_port in any::<u16>(),
            token in "[a-zA-Z0-9]{4,32}",
        ) {
            let flat = format!(
                "bind_port = {bind_port}\n\
                 auth_method = \"token\"\n\
                 auth_token = \"{token}\"\n"
            );
            let nested = format!(
                "bind_port = {bind_port}\n\
                 [auth]\n\
                 method = \"token\"\n\
                 token = \"{token}\"\n"
            );
            let flat_norm = super::normalize_server_toml(&flat);
            let nested_norm = super::normalize_server_toml(&nested);
            prop_assert_eq!(flat_norm, nested_norm,
                "flat auth fields did not normalize to same result as nested [auth]");
        }
    }

    proptest! {
        /// Server config: flat log fields produce same result as nested [log].
        #[test]
        fn server_log_flat_vs_nested_equivalent(
            bind_port in any::<u16>(),
            level in "trace|debug|info|warn|error",
            file in "[a-z/.]{0,32}",
        ) {
            let flat = format!(
                "bind_port = {bind_port}\n\
                 log_level = \"{level}\"\n\
                 log_file = \"{file}\"\n"
            );
            let nested = format!(
                "bind_port = {bind_port}\n\
                 [log]\n\
                 level = \"{level}\"\n\
                 file = \"{file}\"\n"
            );
            let flat_norm = super::normalize_server_toml(&flat);
            let nested_norm = super::normalize_server_toml(&nested);
            prop_assert_eq!(flat_norm, nested_norm,
                "flat log fields did not normalize to same result as nested [log]");
        }
    }

    proptest! {
        /// Server config: flat web_server fields produce same result as nested [web_server].
        #[test]
        fn server_web_server_flat_vs_nested_equivalent(
            bind_port in any::<u16>(),
            ws_port in any::<u16>(),
            ws_user in "[a-zA-Z0-9]{2,16}",
            ws_pwd in "[a-zA-Z0-9]{2,16}",
        ) {
            let flat = format!(
                "bind_port = {bind_port}\n\
                 web_server_port = {ws_port}\n\
                 web_server_user = \"{ws_user}\"\n\
                 web_server_password = \"{ws_pwd}\"\n"
            );
            let nested = format!(
                "bind_port = {bind_port}\n\
                 [web_server]\n\
                 port = {ws_port}\n\
                 user = \"{ws_user}\"\n\
                 password = \"{ws_pwd}\"\n"
            );
            let flat_norm = super::normalize_server_toml(&flat);
            let nested_norm = super::normalize_server_toml(&nested);
            prop_assert_eq!(flat_norm, nested_norm,
                "flat web_server fields did not normalize to same as nested [web_server]");
        }
    }

    // ── Client config properties ─────────────────────────────────

    proptest! {
        /// Client config normalization is idempotent.
        #[test]
        fn client_normalization_idempotent(toml_str in arb_client_common_config()) {
            let first = super::normalize_client_toml(&toml_str);
            let second = super::normalize_client_toml(&first);
            prop_assert_eq!(first, second,
                "normalize(normalize(x)) != normalize(x)");
        }
    }

    proptest! {
        /// Client config: protocol field maps to transport_protocol.
        #[test]
        fn client_protocol_to_transport_protocol(
            port in any::<u16>(),
            proto in "tcp|kcp|quic|websocket",
            token in "[a-zA-Z0-9]{4,16}",
        ) {
            let input = format!(
                "[common]\n\
                 server_addr = \"127.0.0.1\"\n\
                 server_port = {port}\n\
                 token = \"{token}\"\n\
                 protocol = \"{proto}\"\n"
            );
            let norm = super::normalize_client_toml(&input);
            // After normalization, "protocol" should become "transport_protocol"
            prop_assert!(norm.contains("transport_protocol"),
                "protocol was not normalized to transport_protocol: {norm}");
            prop_assert!(!norm.contains("\nprotocol ="),
                "old protocol key still present after normalization: {norm}");
        }
    }

    proptest! {
        /// Client config: Go camelCase fields normalized to snake_case.
        #[test]
        fn client_camelcase_to_snakecase(
            port in any::<u16>(),
            addr in "[a-z.]{4,16}",
            token in "[a-zA-Z0-9]{4,16}",
        ) {
            let input = format!(
                "[common]\n\
                 serverAddr = \"{addr}\"\n\
                 serverPort = {port}\n\
                 token = \"{token}\"\n"
            );
            let norm = super::normalize_client_toml(&input);
            prop_assert!(norm.contains("server_addr"),
                "serverAddr not normalized to server_addr: {norm}");
            prop_assert!(norm.contains("server_port"),
                "serverPort not normalized to server_port: {norm}");
        }
    }

    proptest! {
        /// Client config: [transport] section flattened to top-level keys.
        #[test]
        fn client_transport_flatten(
            port in any::<u16>(),
            token in "[a-zA-Z0-9]{4,16}",
        ) {
            let input = format!(
                "server_addr = \"127.0.0.1\"\n\
                 server_port = {port}\n\
                 token = \"{token}\"\n\
                 [transport]\n\
                 tcp_mux = false\n"
            );
            let norm = super::normalize_client_toml(&input);
            // After normalization, [transport] should be gone and tcp_mux at top level
            prop_assert!(norm.contains("tcp_mux"),
                "transport.tcp_mux not flattened to top-level: {norm}");
            // The [transport] section itself should be gone
            prop_assert!(!norm.contains("[transport]"),
                "[transport] section still present after flatten: {norm}");
        }
    }

    proptest! {
        /// Server config: [common] section flattened to root, then normalization
        /// is idempotent.
        #[test]
        fn server_common_flatten_idempotent(
            bind_port in any::<u16>(),
            token in "[a-zA-Z0-9]{4,16}",
        ) {
            let input = format!(
                "[common]\n\
                 bind_port = {bind_port}\n\
                 auth_method = \"token\"\n\
                 auth_token = \"{token}\"\n\
                 log_level = \"info\"\n"
            );
            let first = super::normalize_server_toml(&input);
            let second = super::normalize_server_toml(&first);
            prop_assert_eq!(first.clone(), second,
                "[common] flatten + normalize not idempotent");
            // [common] should be gone
            prop_assert!(!first.contains("[common]"),
                "[common] section still present after normalization: {first}");
        }
    }

    // ── Non-proptest edge case tests ─────────────────────────────

    #[test]
    fn server_token_promoted_to_auth() {
        let input = "bind_port = 7000\ntoken = \"my-secret\"\n";
        let norm = super::normalize_server_toml(input);
        assert!(
            norm.contains("[auth]"),
            "token should be promoted into [auth]: {norm}"
        );
        assert!(
            norm.contains("token = \"my-secret\""),
            "token value missing: {norm}"
        );
    }

    #[test]
    fn server_ssh_tunnel_gateway_rename() {
        let input = "bind_port = 7000\n[sshTunnelGateway]\nbindPort = 2200\n";
        let norm = super::normalize_server_toml(input);
        assert!(
            norm.contains("ssh_tunnel_gateway"),
            "sshTunnelGateway not renamed: {norm}"
        );
        assert!(
            !norm.contains("sshTunnelGateway"),
            "old sshTunnelGateway key still present: {norm}"
        );
    }

    #[test]
    fn client_tls_trusted_ca_rename() {
        let input =
            "server_addr = \"x\"\nserver_port = 7000\ntls_trusted_ca_file = \"/certs/ca.pem\"\n";
        let norm = super::normalize_client_toml(input);
        assert!(
            norm.contains("tls_ca_file"),
            "tls_trusted_ca_file not renamed to tls_ca_file: {norm}"
        );
        assert!(
            !norm.contains("tls_trusted_ca_file"),
            "old tls_trusted_ca_file key still present: {norm}"
        );
    }

    #[test]
    fn server_enable_prometheus_to_web_server() {
        let input = "bind_port = 7000\nenable_prometheus = true\n";
        let norm = super::normalize_server_toml(input);
        assert!(
            norm.contains("[web_server]"),
            "enable_prometheus should create [web_server]: {norm}"
        );
        assert!(
            norm.contains("enable_prometheus"),
            "enable_prometheus value missing: {norm}"
        );
    }

    #[test]
    fn client_transport_wire_protocol_v2() {
        let input = "server_addr = \"x\"\nserver_port = 7000\n[transport]\nwireProtocol = \"v2\"\n";
        let norm = super::normalize_client_toml(input);
        assert!(
            norm.contains("v2 = true"),
            "wireProtocol=v2 not converted to v2=true: {norm}"
        );
    }

    // ── Proxy/visitor sub-table normalization (flat vs nested) ─────────

    proptest! {
        /// A proxy expressed with Go-format sub-tables
        /// ([proxies.transport] / [proxies.healthCheck] /
        /// [proxies.loadBalancer]) normalizes to the same TOML as the
        /// equivalent flat fields. normalize_proxies (normalize.rs:2547)
        /// flattens the sub-tables in the order transport → healthCheck →
        /// loadBalancer; the flat form below lists the fields in exactly
        /// that order so the serialized outputs match.
        #[test]
        fn proxy_subtables_flat_vs_nested_equivalent(
            use_enc in any::<bool>(),
            bw in "1MB|2MB|1KB",
            interval in 1u64..3600,
            group in "[a-z]{1,8}",
        ) {
            let nested = format!(
                "server_addr = \"127.0.0.1\"\n\
                 server_port = 7000\n\
                 [[proxies]]\n\
                 name = \"p\"\n\
                 type = \"tcp\"\n\
                 local_ip = \"127.0.0.1\"\n\
                 local_port = 80\n\
                 remote_port = 7001\n\
                 [proxies.transport]\n\
                 useEncryption = {use_enc}\n\
                 bandwidthLimit = \"{bw}\"\n\
                 [proxies.healthCheck]\n\
                 type = \"tcp\"\n\
                 intervalSeconds = {interval}\n\
                 [proxies.loadBalancer]\n\
                 group = \"{group}\"\n\
                 groupKey = \"k\"\n"
            );
            let flat = format!(
                "server_addr = \"127.0.0.1\"\n\
                 server_port = 7000\n\
                 [[proxies]]\n\
                 name = \"p\"\n\
                 type = \"tcp\"\n\
                 local_ip = \"127.0.0.1\"\n\
                 local_port = 80\n\
                 remote_port = 7001\n\
                 use_encryption = {use_enc}\n\
                 bandwidth_limit = \"{bw}\"\n\
                 health_check_type = \"tcp\"\n\
                 health_check_interval_seconds = {interval}\n\
                 group = \"{group}\"\n\
                 group_key = \"k\"\n"
            );
            let nested_norm = super::normalize_client_toml(&nested);
            let flat_norm = super::normalize_client_toml(&flat);
            prop_assert_eq!(nested_norm, flat_norm);
        }
    }

    proptest! {
        /// Same equivalence for visitor sub-tables
        /// ([visitors.transport] / [visitors.natTraversal],
        /// normalize_visitors at normalize.rs:2799).
        #[test]
        fn visitor_subtables_flat_vs_nested_equivalent(
            use_enc in any::<bool>(),
            use_comp in any::<bool>(),
            bind_port in 1000i32..60000,
        ) {
            let nested = format!(
                "server_addr = \"127.0.0.1\"\n\
                 server_port = 7000\n\
                 [[visitors]]\n\
                 name = \"v\"\n\
                 type = \"stcp\"\n\
                 server_name = \"s\"\n\
                 secret_key = \"sk\"\n\
                 bind_port = {bind_port}\n\
                 [visitors.transport]\n\
                 useEncryption = {use_enc}\n\
                 useCompression = {use_comp}\n\
                 [visitors.natTraversal]\n\
                 disableAssistedAddrs = true\n"
            );
            let flat = format!(
                "server_addr = \"127.0.0.1\"\n\
                 server_port = 7000\n\
                 [[visitors]]\n\
                 name = \"v\"\n\
                 type = \"stcp\"\n\
                 server_name = \"s\"\n\
                 secret_key = \"sk\"\n\
                 bind_port = {bind_port}\n\
                 use_encryption = {use_enc}\n\
                 use_compression = {use_comp}\n\
                 disable_assisted_addrs = true\n"
            );
            let nested_norm = super::normalize_client_toml(&nested);
            let flat_norm = super::normalize_client_toml(&flat);
            prop_assert_eq!(nested_norm, flat_norm);
        }
    }
}

// --- validate_no_duplicate_names tests (Go frp v0.70.0 compat) ---

#[test]
fn duplicate_proxy_names_rejected() {
    let toml = r#"
            server_addr = "127.0.0.1"
            server_port = 7000

            [[proxies]]
            name = "dup"
            type = "tcp"
            local_ip = "127.0.0.1"
            local_port = 22
            remote_port = 6000

            [[proxies]]
            name = "dup"
            type = "tcp"
            local_ip = "127.0.0.1"
            local_port = 3306
            remote_port = 6001
        "#;
    let err = super::load_client_config_from_str(toml).unwrap_err();
    assert!(
        err.to_string().contains("proxy name [dup] is duplicated"),
        "expected duplicate proxy error, got: {err}"
    );
}

#[test]
fn duplicate_visitor_names_rejected() {
    let toml = r#"
            server_addr = "127.0.0.1"
            server_port = 7000

            [[visitors]]
            name = "dup"
            type = "stcp"
            server_name = "a"
            secret_key = "secret"
            bind_port = 9001

            [[visitors]]
            name = "dup"
            type = "stcp"
            server_name = "b"
            secret_key = "secret"
            bind_port = 9002
        "#;
    let err = super::load_client_config_from_str(toml).unwrap_err();
    assert!(
        err.to_string().contains("visitor name [dup] is duplicated"),
        "expected duplicate visitor error, got: {err}"
    );
}

#[test]
fn unique_proxy_names_accepted() {
    let toml = r#"
            server_addr = "127.0.0.1"
            server_port = 7000

            [[proxies]]
            name = "p1"
            type = "tcp"
            local_ip = "127.0.0.1"
            local_port = 22
            remote_port = 6000

            [[proxies]]
            name = "p2"
            type = "tcp"
            local_ip = "127.0.0.1"
            local_port = 3306
            remote_port = 6001
        "#;
    super::load_client_config_from_str(toml).unwrap();
}

#[test]
fn same_name_across_proxy_and_visitor_allowed() {
    // Go frp v0.70.0: proxies and visitors are separate namespaces.
    let toml = r#"
            server_addr = "127.0.0.1"
            server_port = 7000

            [[proxies]]
            name = "same"
            type = "tcp"
            local_ip = "127.0.0.1"
            local_port = 22
            remote_port = 6000

            [[visitors]]
            name = "same"
            type = "stcp"
            server_name = "a"
            secret_key = "secret"
            bind_port = 9001
        "#;
    super::load_client_config_from_str(toml).unwrap();
}

// ── HIGH-1 / HIGH-2: Proxy sub-table normalization ────────────────

#[test]
fn proxy_transport_subtable_normalized() {
    let toml = r#"
            server_addr = "127.0.0.1"
            server_port = 7000
            [[proxies]]
            name = "test"
            type = "tcp"
            local_ip = "127.0.0.1"
            local_port = 80
            remote_port = 7001
            [proxies.transport]
            useEncryption = true
            bandwidthLimit = "1MB"
            proxyProtocolVersion = "v2"
        "#;
    let cfg: super::ClientConfig = super::load_client_config_from_str(toml).unwrap();
    let p = &cfg.proxies[0];
    assert!(p.use_encryption, "useEncryption should be true");
    assert_eq!(p.bandwidth_limit, "1MB");
    assert_eq!(p.proxy_protocol_version, "v2");
}

#[test]
fn proxy_healthcheck_subtable_normalized() {
    let toml = r#"
            server_addr = "127.0.0.1"
            server_port = 7000
            [[proxies]]
            name = "test"
            type = "tcp"
            local_ip = "127.0.0.1"
            local_port = 80
            remote_port = 7001
            [proxies.healthCheck]
            type = "tcp"
            intervalSeconds = 5
            timeoutSeconds = 2
            maxFailed = 3
        "#;
    let cfg: super::ClientConfig = super::load_client_config_from_str(toml).unwrap();
    let p = &cfg.proxies[0];
    assert_eq!(p.health_check_type, "tcp");
    assert_eq!(p.health_check_interval_seconds, 5);
    assert_eq!(p.health_check_timeout_seconds, 2);
    assert_eq!(p.health_check_max_failed, 3);
}

#[test]
fn proxy_healthcheck_negative_values_default_go_parity() {
    // Go frp accepts negative health check ints and falls back to the
    // defaults (client/health/health.go:57-64). The u64/u32 ProxyConfig
    // fields would fail serde on -1 and kill the whole config load; the
    // normalize step clamps <= 0 to the Go defaults pre-deserialization.
    let toml = r#"
            server_addr = "127.0.0.1"
            server_port = 7000
            [[proxies]]
            name = "test"
            type = "tcp"
            local_ip = "127.0.0.1"
            local_port = 80
            remote_port = 7001
            health_check_type = "tcp"
            health_check_interval_seconds = -1
            health_check_timeout_seconds = -5
            health_check_max_failed = -2
        "#;
    let cfg: super::ClientConfig = super::load_client_config_from_str(toml).unwrap();
    let p = &cfg.proxies[0];
    assert_eq!(p.health_check_interval_seconds, 10);
    assert_eq!(p.health_check_timeout_seconds, 3);
    assert_eq!(p.health_check_max_failed, 1);
}

#[test]
fn proxy_healthcheck_nested_negative_and_zero_default() {
    // Same clamp through the Go-style [proxies.healthCheck] sub-table
    // flattening (negative and explicit-zero both land on the Go default,
    // matching Go's `<= 0` rule), while positive explicit values are
    // preserved.
    let toml = r#"
            server_addr = "127.0.0.1"
            server_port = 7000
            [[proxies]]
            name = "test"
            type = "tcp"
            local_ip = "127.0.0.1"
            local_port = 80
            remote_port = 7001
            [proxies.healthCheck]
            type = "tcp"
            intervalSeconds = -1
            timeoutSeconds = 0
            maxFailed = 3
        "#;
    let cfg: super::ClientConfig = super::load_client_config_from_str(toml).unwrap();
    let p = &cfg.proxies[0];
    assert_eq!(p.health_check_interval_seconds, 10);
    assert_eq!(p.health_check_timeout_seconds, 3);
    assert_eq!(p.health_check_max_failed, 3);
}

#[test]
fn proxy_loadbalancer_subtable_normalized() {
    let toml = r#"
            server_addr = "127.0.0.1"
            server_port = 7000
            [[proxies]]
            name = "test"
            type = "tcp"
            local_ip = "127.0.0.1"
            local_port = 80
            remote_port = 7001
            [proxies.loadBalancer]
            group = "web"
            groupKey = "secret"
        "#;
    let cfg: super::ClientConfig = super::load_client_config_from_str(toml).unwrap();
    let p = &cfg.proxies[0];
    assert_eq!(p.group, "web");
    assert_eq!(p.group_key, "secret");
}

#[test]
fn proxy_request_headers_set_normalized() {
    let toml = r#"
            server_addr = "127.0.0.1"
            server_port = 7000
            [[proxies]]
            name = "test"
            type = "http"
            local_ip = "127.0.0.1"
            local_port = 80
            custom_domains = ["example.com"]
            [proxies.requestHeaders.set]
            "x-from-where" = "value"
        "#;
    let cfg: super::ClientConfig = super::load_client_config_from_str(toml).unwrap();
    let p = &cfg.proxies[0];
    assert_eq!(
        p.headers.get("x-from-where").map(|s| s.as_str()),
        Some("value")
    );
}

#[test]
fn proxy_response_headers_set_normalized() {
    let toml = r#"
            server_addr = "127.0.0.1"
            server_port = 7000
            [[proxies]]
            name = "test"
            type = "http"
            local_ip = "127.0.0.1"
            local_port = 80
            custom_domains = ["example.com"]
            [proxies.responseHeaders.set]
            "X-Frame-Options" = "DENY"
        "#;
    let cfg: super::ClientConfig = super::load_client_config_from_str(toml).unwrap();
    let p = &cfg.proxies[0];
    assert_eq!(
        p.response_headers
            .get("X-Frame-Options")
            .map(|s| s.as_str()),
        Some("DENY")
    );
}

// ── MEDIUM-3: LogConfig `to` alias ─────────────────────────────────

#[test]
fn log_to_alias_works() {
    let toml = "level = \"debug\"\nto = \"/var/log/frps.log\"\nmax_days = 7\n";
    let cfg: super::LogConfig = toml::from_str(toml).unwrap();
    assert_eq!(cfg.file, "/var/log/frps.log");
}

// ── MEDIUM-3b: LogConfig `format` field ────────────────────────────

#[test]
fn log_format_defaults_to_text() {
    let cfg = super::LogConfig::default();
    assert_eq!(cfg.format, "text");
}

#[test]
fn log_format_parses_json() {
    let toml = "level = \"info\"\nformat = \"json\"\nmax_days = 0\n";
    let cfg: super::LogConfig = toml::from_str(toml).unwrap();
    assert_eq!(cfg.format, "json");
}

#[test]
fn log_format_preserved_when_absent() {
    // A config without `format` must still deserialize (serde default).
    let toml = "level = \"debug\"\n";
    let cfg: super::LogConfig = toml::from_str(toml).unwrap();
    assert_eq!(cfg.format, "text");
}

// ── LogConfig completion (Go `LogConfig.Complete()`) ───────────────
//
// Go's `ServerConfig.Complete()` calls `c.Log.Complete()`
// (`pkg/config/v1/server.go:105`) and the client's calls the same thing at
// `pkg/config/v1/client.go:94`. The body is three `util.EmptyOr` fills
// (`pkg/config/v1/common.go:119-123`), and `util.EmptyOr`
// (`pkg/util/util/types.go:17-23`) fills the type's ZERO value — so an explicit
// `""`/`0` is filled, not only an absent key. That zero-value semantics is the
// whole point: the serde defaults on `LogConfig` fire only when the key is
// absent, so before this the explicit-empty shapes reached `init_logging` and
// silenced the logger. Measured on the pre-fix binary (own free port, flags-only
// lane, stdout and stderr counted separately BEFORE any signal):
// `frps --log-level ""` → 0 B stdout / 0 B stderr, listener up;
// `frps --log-file ""` → 0 B / 0 B **and** a `frps.log.<date>` created in the
// CWD; `frps --log-max-days 0` → logs normally but with retention disabled.
// Go v0.71.0 with the same flags logs its startup lines on stdout and binds.

/// The absent-vs-empty split, for all three Go fields, on the type itself.
#[test]
fn log_config_absent_keys_keep_serde_defaults_and_empty_ones_are_filled() {
    // ABSENT: the serde default must already be in place, and `complete()` must
    // be a no-op on it.
    let mut absent: super::LogConfig = toml::from_str("").unwrap();
    assert_eq!(absent.level, "info", "serde default for an ABSENT level");
    assert_eq!(
        absent.file, "console",
        "serde default for an ABSENT to/file"
    );
    assert_eq!(absent.max_days, 3, "serde default for an ABSENT maxDays");
    let before = absent.clone();
    absent.complete();
    assert_eq!(absent.level, before.level);
    assert_eq!(absent.file, before.file);
    assert_eq!(absent.max_days, before.max_days);

    // PRESENT-BUT-EMPTY/ZERO: deserialization alone must NOT default these —
    // that is the defect — and `complete()` is what fills them.
    let mut present: super::LogConfig =
        toml::from_str("level = \"\"\nto = \"\"\nmax_days = 0\n").unwrap();
    assert_eq!(present.level, "", "deserialization alone must not default");
    assert_eq!(present.file, "", "deserialization alone must not default");
    assert_eq!(
        present.max_days, 0,
        "deserialization alone must not default"
    );
    present.complete();
    assert_eq!(present.level, "info");
    assert_eq!(present.file, "console");
    assert_eq!(present.max_days, 3);

    // The `maxDays` camelCase alias and the frp-rs `file` spelling reach the
    // same field as `to`, and are completed identically.
    for toml in ["maxDays = 0\n", "file = \"\"\n", "to = \"\"\n"] {
        let mut cfg: super::LogConfig = toml::from_str(toml).unwrap();
        cfg.complete();
        assert_eq!(cfg.max_days, 3, "maxDays under {toml:?}");
        assert_eq!(cfg.file, "console", "file/to under {toml:?}");
    }

    // Every explicit NON-empty/non-zero value passes through verbatim — the
    // fill is an `EmptyOr`, not a re-default of the field.
    let mut kept: super::LogConfig =
        toml::from_str("level = \"trace\"\nto = \"/var/log/frps.log\"\nmax_days = 0\n").unwrap();
    kept.complete();
    assert_eq!(kept.level, "trace");
    assert_eq!(kept.file, "/var/log/frps.log");
    assert_eq!(kept.max_days, 3, "0 is the zero value -> filled");

    let mut negative: super::LogConfig =
        toml::from_str("level = \"warn\"\nto = \"console\"\nmax_days = -1\n").unwrap();
    negative.complete();
    assert_eq!(
        negative.max_days, -1,
        "only the zero value is filled; a negative maxDays is explicit"
    );
}

/// The frp-rs-only `format` field must NOT be completed, because Go has nothing
/// to complete it with: Go v0.71.0's `LogConfig`
/// (`pkg/config/v1/common.go:103-117`) has no `Format` field, and `--log-format`
/// is `unknown flag` on the real binary (measured: `frps --log-format ""` →
/// `Error: unknown flag: --log-format` + usage on **stderr**, 2368 B, rc 1,
/// nothing listening). `resolve_log_format` already maps `""` to `"text"`, so
/// adding a fill here would be a second, differently-placed mapping for a field
/// Go does not have.
#[test]
fn log_config_completion_leaves_format_alone() {
    let mut cfg: super::LogConfig = toml::from_str("format = \"\"\n").unwrap();
    assert_eq!(
        cfg.format, "",
        "the frp-rs extension is not serde-defaulted"
    );
    cfg.complete();
    assert_eq!(
        cfg.format, "",
        "format has no Go completion to mirror; resolve_log_format handles it"
    );
    assert_eq!(
        crate::logging::resolve_log_format(None, &cfg.format),
        "text"
    );
}

/// The completion must be reachable through the **server** and **client**
/// config-level entry points, not just on `LogConfig` — this is the
/// "precedent applied to one slot and not its sibling" pin. Go calls
/// `c.Log.Complete()` from both `ServerConfig.Complete()`
/// (`pkg/config/v1/server.go:105`) and `ClientCommonConfig.Complete()`
/// (`pkg/config/v1/client.go:94`).
#[test]
fn server_and_client_config_completion_both_fill_the_log_section() {
    // Server: the CLI-override lane writes these values before `complete()`.
    let mut server: ServerConfig =
        serde_json::from_value(serde_json::json!({ "bindPort": 19841 })).unwrap();
    server.log.file = String::new();
    server.log.level = String::new();
    server.log.max_days = 0;
    server.complete();
    assert_eq!(server.log.file, "console");
    assert_eq!(server.log.level, "info");
    assert_eq!(server.log.max_days, 3);

    // Client: `log.file = "" / level = "" / max_days = 0` in the file (frpc does
    // not overlay its CLI flags onto the loaded config).
    let mut client: ClientConfig = serde_json::from_value(serde_json::json!({
        "serverAddr": "127.0.0.1",
        "serverPort": 19842,
        "log": { "to": "", "level": "", "maxDays": 0 }
    }))
    .unwrap();
    assert_eq!(client.log.file, "");
    client.complete_with_heartbeat_set(false, false);
    assert_eq!(client.log.file, "console");
    assert_eq!(client.log.level, "info");
    assert_eq!(client.log.max_days, 3);

    // And the resolved logging inputs the binaries actually pass to
    // `init_tracing` come out of the completed config rather than the raw one:
    // an empty file no longer resolves to a *path*, and an empty level no longer
    // resolves to the empty string.
    assert_eq!(
        crate::logging::resolve_log_file(None, &server.log.file),
        None,
        "console means stdout"
    );
    assert_eq!(
        crate::logging::resolve_log_level(None, Some(&server.log.level), "debug"),
        "info"
    );
}

// ── MEDIUM-4: WebServer addr default ────────────────────────────────

#[test]
fn web_server_addr_defaults_to_localhost() {
    let cfg: super::WebServerConfig = Default::default();
    assert_eq!(cfg.addr, "127.0.0.1");
}

/// Go frp v0.71.0 `ClientCommonConfig.Complete()` calls
/// `c.WebServer.Complete()` (`pkg/config/v1/client.go:96`), and the client has
/// no later step that re-defaults the address (the server's
/// `pkg/config/v1/server.go:116-117` re-defaults a *set port* to `0.0.0.0`, but
/// that branch is dead for the same reason and is a different surface — see
/// `server_web_server_addr_empty_is_completed_to_localhost`). So on frpc an
/// explicit `addr = ""` becomes
/// `127.0.0.1`. Measured on the Go v0.71.0 binary: with `[webServer] addr = ""`
/// and `port = 7499`, `frpc status -c <cfg>` dials `127.0.0.1:7499`. Before this
/// completion, frp-rs dialled `:7499` and failed with
/// `failed to lookup address information`.
#[test]
fn client_web_server_addr_empty_is_completed_to_localhost() {
    let toml =
        "serverAddr = \"127.0.0.1\"\nserverPort = 7500\n[webServer]\naddr = \"\"\nport = 7499\n";
    let cfg: super::ClientConfig = super::load_client_config_from_str(toml).unwrap();
    assert_eq!(cfg.web_server.addr, "127.0.0.1");
    assert_eq!(cfg.web_server.port, 7499);
}

/// The completion fills only an *empty* address: an explicit bind address
/// survives, and the absent-key case still goes through the serde default
/// (also `127.0.0.1`).
#[test]
fn client_web_server_addr_explicit_and_absent_are_unchanged() {
    let toml = "serverAddr = \"127.0.0.1\"\nserverPort = 7500\n[webServer]\naddr = \"10.1.2.3\"\nport = 7499\n";
    let cfg: super::ClientConfig = super::load_client_config_from_str(toml).unwrap();
    assert_eq!(cfg.web_server.addr, "10.1.2.3");

    let toml = "serverAddr = \"127.0.0.1\"\nserverPort = 7500\n[webServer]\nport = 7499\n";
    let cfg: super::ClientConfig = super::load_client_config_from_str(toml).unwrap();
    assert_eq!(cfg.web_server.addr, "127.0.0.1");

    // No `[webServer]` at all: the port stays 0, so the admin commands still
    // refuse with Go's sentence instead of dialing the completed address (the
    // `AdminResolveError::NoPort` path).
    let toml = "serverAddr = \"127.0.0.1\"\nserverPort = 7500\n";
    let cfg: super::ClientConfig = super::load_client_config_from_str(toml).unwrap();
    assert_eq!(cfg.web_server.port, 0);
    assert_eq!(cfg.web_server.addr, "127.0.0.1");
}

// ── MEDIUM-5: OIDC nesting normalization ───────────────────────────

#[test]
fn auth_oidc_subtable_normalized() {
    let toml = r#"
bind_port = 7000
[auth.oidc]
issuer = "https://auth.example.com"
audience = "https://api.example.com"
tokenEndpointURL = "https://auth.example.com/token"
"#;
    let cfg: super::ServerConfig = super::load_server_config_from_str(toml).unwrap();
    assert_eq!(cfg.auth.oidc_issuer, "https://auth.example.com");
    assert_eq!(cfg.auth.oidc_audience, "https://api.example.com");
    assert_eq!(
        cfg.auth.oidc_token_endpoint,
        "https://auth.example.com/token"
    );
}

// ── MEDIUM-6: HTTP plugins addr+path normalization ─────────────────

#[test]
fn http_plugin_addr_path_to_url() {
    let toml = r#"
bind_port = 7000
[[http_plugins]]
name = "test"
addr = "http://127.0.0.1:4000"
path = "/handler"
"#;
    let cfg: super::ServerConfig = super::load_server_config_from_str(toml).unwrap();
    assert_eq!(cfg.http_plugins[0].addr, "http://127.0.0.1:4000");
    assert_eq!(cfg.http_plugins[0].path, "/handler");
}

// ── MEDIUM-8: custom_404_page normalization ────────────────────────

#[test]
fn custom_404_page_top_level_normalized() {
    let toml = r#"
bind_port = 7000
custom404Page = "<html>Not Found</html>"
"#;
    let cfg: super::ServerConfig = super::load_server_config_from_str(toml).unwrap();
    assert_eq!(cfg.web_server.custom_404_page, "<html>Not Found</html>");
}

// ── MEDIUM-9: transport legacy fields normalization ─────────────────

#[test]
fn transport_legacy_fields_normalized() {
    let toml = r#"
bind_port = 7000
heartbeat_timeout = 120
max_pool_count = 10
"#;
    let cfg: super::ServerConfig = super::load_server_config_from_str(toml).unwrap();
    assert_eq!(cfg.transport.heartbeat_timeout, 120);
    assert_eq!(cfg.transport.max_pool_count, 10);
}

// ─── YAML config support (Go frp v0.70.1 Viper parity) ──────────────

/// Parse a YAML server config through the full pipeline (YAML → toml::Value
/// → normalize → deserialize), mirroring `load_server_config_from_str` for
/// TOML.
fn load_server_config_from_yaml(yaml: &str) -> Result<ServerConfig, Box<dyn std::error::Error>> {
    let mut value = super::format::parse_to_toml_value(yaml, super::format::ConfigFormat::Yaml)?;
    expand_env_vars(&mut value);
    normalize_server_config(&mut value, super::format::ConfigFormat::Yaml)?;
    let presence = super::loader::ConfigPresence::from_normalized_value(&value);
    let json_value = super::normalize::toml_to_json(value);
    let mut cfg: ServerConfig =
        serde_json::from_value(json_value).map_err(|e| format!("config validation error: {e}"))?;
    super::loader::validate_server_config(&mut cfg)?;
    cfg.transport
        .complete_with_heartbeat_timeout_set(presence.server_heartbeat_timeout_set);
    cfg.complete();
    Ok(cfg)
}

/// Parse a YAML client config through the full pipeline, mirroring
/// `load_client_config_from_str` for TOML.
fn load_client_config_from_yaml(yaml: &str) -> Result<ClientConfig, Box<dyn std::error::Error>> {
    let mut value = super::format::parse_to_toml_value(yaml, super::format::ConfigFormat::Yaml)?;
    expand_env_vars(&mut value);
    normalize_client_config(&mut value, super::format::ConfigFormat::Yaml)?;
    let presence = super::loader::ConfigPresence::from_normalized_value(&value);
    let mut cfg: ClientConfig = serde_json::from_value(super::normalize::toml_to_json(value))
        .map_err(|e| format!("config validation error: {e}"))?;
    super::loader::validate_client_config(&mut cfg)?;
    cfg.complete_with_heartbeat_set(
        presence.client_heartbeat_interval_set,
        presence.client_heartbeat_timeout_set,
    );
    Ok(cfg)
}

#[test]
fn test_detect_format_yaml_extensions() {
    use super::format::{detect_format, ConfigFormat};
    assert_eq!(detect_format("frps.yaml"), ConfigFormat::Yaml);
    assert_eq!(detect_format("frpc.yml"), ConfigFormat::Yaml);
    assert_eq!(
        detect_format("frps.YAML"),
        ConfigFormat::Yaml,
        "case-insensitive"
    );
    assert_eq!(detect_format("frps.toml"), ConfigFormat::Toml);
}

#[test]
fn test_server_yaml_equivalent_to_toml() {
    let toml = r#"
bind_addr = "0.0.0.0"
bind_port = 7000

[auth]
method = "token"
token = "my-token"

[log]
level = "info"
"#;
    let yaml = r#"
bind_addr: "0.0.0.0"
bind_port: 7000
auth:
  method: token
  token: my-token
log:
  level: info
"#;
    let toml_cfg = super::load_server_config_from_str(toml).unwrap();
    let yaml_cfg = load_server_config_from_yaml(yaml).unwrap();
    assert_eq!(toml_cfg.bind_addr, yaml_cfg.bind_addr);
    assert_eq!(toml_cfg.bind_port, yaml_cfg.bind_port);
    assert_eq!(toml_cfg.auth.method, yaml_cfg.auth.method);
    assert_eq!(toml_cfg.auth.token, yaml_cfg.auth.token);
    assert_eq!(toml_cfg.log.level, yaml_cfg.log.level);
}

#[test]
fn test_client_yaml_equivalent_to_toml() {
    let toml = r#"
server_addr = "127.0.0.1"
server_port = 7000
token = "client-token"

[[proxies]]
name = "web"
type = "tcp"
local_ip = "127.0.0.1"
local_port = 8080
remote_port = 7001
"#;
    let yaml = r#"
server_addr: "127.0.0.1"
server_port: 7000
token: client-token
proxies:
  - name: web
    type: tcp
    local_ip: "127.0.0.1"
    local_port: 8080
    remote_port: 7001
"#;
    let toml_cfg = super::load_client_config_from_str(toml).unwrap();
    let yaml_cfg = load_client_config_from_yaml(yaml).unwrap();
    assert_eq!(toml_cfg.server_addr, yaml_cfg.server_addr);
    assert_eq!(toml_cfg.server_port, yaml_cfg.server_port);
    assert_eq!(toml_cfg.token, yaml_cfg.token);
    assert_eq!(toml_cfg.proxies.len(), yaml_cfg.proxies.len());
    let (tp, yp) = (&toml_cfg.proxies[0], &yaml_cfg.proxies[0]);
    assert_eq!(tp.name, yp.name);
    assert_eq!(tp.proxy_type, yp.proxy_type);
    assert_eq!(tp.local_ip, yp.local_ip);
    assert_eq!(tp.local_port, yp.local_port);
    assert_eq!(tp.remote_port, yp.remote_port);
}

#[test]
fn test_yaml_merge_key_applied_at_parse_time() {
    let yaml = r#"
defaults: &defaults
  a: 1
  b: 2
merged:
  <<: *defaults
  b: 3
"#;
    let value =
        super::format::parse_to_toml_value(yaml, super::format::ConfigFormat::Yaml).unwrap();
    let merged = value.get("merged").expect("merged table");
    assert_eq!(
        merged.get("a").and_then(toml::Value::as_integer),
        Some(1),
        "inherited key from <<"
    );
    assert_eq!(
        merged.get("b").and_then(toml::Value::as_integer),
        Some(3),
        "explicit key wins over merge"
    );
    assert!(merged.get("<<").is_none(), "merge key must be consumed");
}

#[test]
fn test_yaml_merge_key_merges_anchor_fields() {
    let yaml = r#"
server_addr: "127.0.0.1"
server_port: 7000
proxies:
  - &base
    name: base
    type: tcp
    local_ip: "127.0.0.1"
    use_encryption: true
  - <<: *base
    name: merged
    local_port: 8080
    remote_port: 7001
"#;
    let cfg = load_client_config_from_yaml(yaml).unwrap();
    assert_eq!(cfg.proxies.len(), 2);
    let merged = cfg.proxies.iter().find(|p| p.name == "merged").unwrap();
    assert_eq!(merged.local_ip, "127.0.0.1", "<< merged local_ip");
    assert!(merged.use_encryption, "<< merged use_encryption");
    assert_eq!(merged.local_port, 8080, "explicit field wins over merge");
    assert_eq!(merged.remote_port, 7001);
}

#[test]
fn test_yaml_include_file_merged() {
    let dir = tempfile::tempdir().unwrap();
    let main_path = dir.path().join("frps.toml");
    std::fs::write(
        &main_path,
        r#"
bind_addr = "0.0.0.0"
bind_port = 7000
includes = ["extra.yaml"]
"#,
    )
    .unwrap();
    std::fs::write(
        dir.path().join("extra.yaml"),
        r#"
auth:
  method: token
  token: "yaml-token"
"#,
    )
    .unwrap();
    let cfg = super::load_server_config(main_path.to_str().unwrap(), false).unwrap();
    assert_eq!(cfg.bind_addr, "0.0.0.0");
    assert_eq!(cfg.bind_port, 7000);
    assert_eq!(cfg.auth.method, "token");
    assert_eq!(
        cfg.auth.token, "yaml-token",
        "include .yaml should merge auth.token"
    );
}

#[test]
fn test_collect_config_files_includes_yaml_and_yml() {
    let dir = tempfile::tempdir().unwrap();
    for name in [
        "a.toml",
        "b.yaml",
        "c.yml",
        "d.json",
        "notes.txt",
        "CONFIG.YAML",
    ] {
        std::fs::write(dir.path().join(name), "").unwrap();
    }
    std::fs::create_dir(dir.path().join("sub")).unwrap();
    std::fs::write(dir.path().join("sub").join("e.yaml"), "").unwrap();
    std::fs::write(dir.path().join("sub").join("f.ini"), "").unwrap();
    let files = super::collect_config_files(dir.path()).unwrap();
    let names: Vec<String> = files
        .iter()
        .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
        .collect();
    for expected in [
        "a.toml",
        "b.yaml",
        "c.yml",
        "d.json",
        "e.yaml",
        "f.ini",
        "CONFIG.YAML",
    ] {
        assert!(
            names.contains(&expected.to_string()),
            "missing {expected}: {names:?}"
        );
    }
    assert!(
        !names.iter().any(|n| n == "notes.txt"),
        "non-config file collected: {names:?}"
    );
}

#[cfg(unix)]
#[test]
fn test_collect_config_files_symlink_cycle_terminates() {
    // M13 regression: a symlink cycle inside a `--config-dir` tree (dir →
    // ancestor → dir) used to recurse forever, blowing the stack (SIGSEGV
    // under panic=abort — uncatchable). The walk must terminate, still
    // collecting the real config files.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("root.toml"), "").unwrap();
    std::fs::create_dir(dir.path().join("sub")).unwrap();
    std::fs::write(dir.path().join("sub").join("nested.yaml"), "").unwrap();
    // sub/up → .. (a direct cycle back to the root dir).
    std::os::unix::fs::symlink("..", dir.path().join("sub").join("up")).unwrap();
    // root/self → . (self-referential cycle).
    std::os::unix::fs::symlink(".", dir.path().join("self")).unwrap();
    // root/loop → sub (a deeper cycle through the same subtree).
    std::os::unix::fs::symlink("sub", dir.path().join("loop")).unwrap();

    let files = super::collect_config_files(dir.path()).unwrap();
    let names: Vec<String> = files
        .iter()
        .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
        .collect();
    for expected in ["root.toml", "nested.yaml"] {
        assert!(
            names.contains(&expected.to_string()),
            "missing {expected}: {names:?}"
        );
    }
}

#[cfg(unix)]
#[test]
fn test_collect_config_files_admits_a_non_regular_entry_by_extension() {
    // This pins **admission**, and the fact that it is extension-only: the
    // collector has no regular-file check, so a FIFO (or any other
    // non-regular entry) whose name ends in a config extension is collected
    // like a file. The tree's only non-regular filter is on the `[include]`
    // `glob_in_dir` path, and it skips *directories* by the directory entry's
    // own type — `if entry.file_type()?.is_dir()`
    // (`frp-core/src/config/file.rs:893`) — never by `is_file()`, so it admits
    // a FIFO just as this collector does. `collect_config_files_inner` has no
    // filter at all.
    //
    // That is deliberately Go-parity, not an oversight: Go frp v0.71.0's
    // `--config-dir` walk filters directory entries by extension
    // (`cmd/frpc/sub/root.go`) and then reads each match, so a FIFO named
    // `b.toml` is admitted by both implementations and the shared loader's
    // first `std::fs::read_to_string` (`frp-core/src/config/normalize.rs:628`)
    // then blocks with no writer. Measured against the real Go binaries
    // (v0.71.0, darwin/arm64, `/private/tmp/frp_0.71.0_darwin_arm64/frpc`):
    //   * `frpc --config-dir <fifo-only>` still running after 15 s, 0 log bytes;
    //   * `frpc --config-dir <a.toml + FIFO>` still running after 4 s, after
    //     already logging the valid file's `connect to server error`.
    //
    // Consequence for anyone tempted to "fix" this here: adding
    // `if !path.is_file() { continue; }` at the push site is an intentional
    // divergence from Go (it turns the FIFO-only directory into the existing
    // empty-directory rc 2 path, and the mixed directory into a
    // serve-the-valid-file path), so it must red **this** test and be argued
    // against a fresh Go probe rather than land silently. A bounded read in
    // the loader is the other option the residue names; this test only pins
    // collection, where no read happens.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.toml"), "").unwrap();
    let fifo = dir.path().join("b.toml");
    let status = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .expect("mkfifo must be runnable to build this fixture");
    assert!(status.success(), "mkfifo {fifo:?} failed: {status:?}");

    // `collect_config_files` must *return* here: it only stats entries, so a
    // non-regular entry can never block collection itself.
    let files = super::collect_config_files(dir.path()).unwrap();
    let names: Vec<String> = files
        .iter()
        .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
        .collect();
    assert!(
        names.contains(&"a.toml".to_string()),
        "regular config file missing from collection: {names:?}"
    );
    assert!(
        names.contains(&"b.toml".to_string()),
        "a non-regular entry with a config extension must be admitted \
         (extension-only admission, Go parity); got {names:?}"
    );
}

// ─── JSON config support (Go frp Viper parity) ───────────────────────

/// Parse a JSON client config through the full pipeline (JSON → toml::Value
/// → normalize → deserialize), mirroring `load_client_config_from_yaml` for
/// YAML.
fn load_client_config_from_json(json: &str) -> Result<ClientConfig, Box<dyn std::error::Error>> {
    let mut value = super::format::parse_to_toml_value(json, super::format::ConfigFormat::Json)?;
    expand_env_vars(&mut value);
    normalize_client_config(&mut value, super::format::ConfigFormat::Json)?;
    let presence = super::loader::ConfigPresence::from_normalized_value(&value);
    let mut cfg: ClientConfig = serde_json::from_value(super::normalize::toml_to_json(value))
        .map_err(|e| format!("config validation error: {e}"))?;
    super::loader::validate_client_config(&mut cfg)?;
    cfg.complete_with_heartbeat_set(
        presence.client_heartbeat_interval_set,
        presence.client_heartbeat_timeout_set,
    );
    Ok(cfg)
}

#[test]
fn test_detect_format_json_and_ini_extensions() {
    use super::format::{detect_format, ConfigFormat};
    assert_eq!(detect_format("frps.json"), ConfigFormat::Json);
    assert_eq!(
        detect_format("frpc.JSON"),
        ConfigFormat::Json,
        "case-insensitive"
    );
    assert_eq!(detect_format("frpc.ini"), ConfigFormat::Ini);
    assert_eq!(
        detect_format("frps.INI"),
        ConfigFormat::Ini,
        "case-insensitive"
    );
    assert_eq!(
        detect_format("frps.cfg"),
        ConfigFormat::Toml,
        "unknown extension falls back to TOML (Go Viper default)"
    );
}

#[test]
fn test_client_json_equivalent_to_toml() {
    let toml = r#"
server_addr = "127.0.0.1"
server_port = 7000
token = "client-token"

[[proxies]]
name = "web"
type = "tcp"
local_ip = "127.0.0.1"
local_port = 8080
remote_port = 7001
"#;
    let json = r#"{
  "server_addr": "127.0.0.1",
  "server_port": 7000,
  "token": "client-token",
  "proxies": [
    {
      "name": "web",
      "type": "tcp",
      "local_ip": "127.0.0.1",
      "local_port": 8080,
      "remote_port": 7001
    }
  ]
}"#;
    let toml_cfg = super::load_client_config_from_str(toml).unwrap();
    let json_cfg = load_client_config_from_json(json).unwrap();
    assert_eq!(toml_cfg.server_addr, json_cfg.server_addr);
    assert_eq!(toml_cfg.server_port, json_cfg.server_port);
    assert_eq!(toml_cfg.token, json_cfg.token);
    assert_eq!(toml_cfg.proxies.len(), json_cfg.proxies.len());
    let (tp, jp) = (&toml_cfg.proxies[0], &json_cfg.proxies[0]);
    assert_eq!(tp.name, jp.name);
    assert_eq!(tp.proxy_type, jp.proxy_type);
    assert_eq!(tp.local_ip, jp.local_ip);
    assert_eq!(tp.local_port, jp.local_port);
    assert_eq!(tp.remote_port, jp.remote_port);
}

#[test]
fn test_json_malformed_returns_err() {
    // Malformed JSON surfaces as an Err from the parse entrypoint (and the
    // full pipeline), never a panic.
    assert!(
        super::format::parse_to_toml_value("{ not json", super::format::ConfigFormat::Json)
            .is_err()
    );
    let err = load_client_config_from_json(r#"{ "server_addr": }"#);
    assert!(err.is_err(), "malformed JSON must not panic: {err:?}");
}

// ─── Env var expansion (Go frp Viper `${ENV_VAR}` parity) ───────────
//
// All variable names use the unique `FRP_RS_TEST_ENV_` prefix. Tests run in
// parallel in one process, so each test touches only its own variable name.

#[test]
fn test_env_var_expansion_basic() {
    std::env::set_var("FRP_RS_TEST_ENV_SERVER", "10.0.0.1");
    let cfg: ClientConfig = load_client_config_from_str(
        r#"
server_addr = "${FRP_RS_TEST_ENV_SERVER}"
server_port = 7000
token = "pre-${FRP_RS_TEST_ENV_SERVER}-post"
"#,
    )
    .unwrap();
    std::env::remove_var("FRP_RS_TEST_ENV_SERVER");
    assert_eq!(cfg.server_addr, "10.0.0.1", "basic ${{VAR}} expansion");
    assert_eq!(
        cfg.token, "pre-10.0.0.1-post",
        "multiple/embedded ${{VAR}} expansion in one string"
    );
}

#[test]
fn test_env_var_expansion_undefined_becomes_empty() {
    // Guarantee the variable is unset in this process.
    std::env::remove_var("FRP_RS_TEST_ENV_UNSET");
    let cfg: ClientConfig = load_client_config_from_str(
        r#"
server_addr = "127.0.0.1"
token = "x${FRP_RS_TEST_ENV_UNSET}y"
"#,
    )
    .unwrap();
    assert_eq!(
        cfg.token, "xy",
        "undefined ${{VAR}} expands to the empty string (Go Viper parity)"
    );
}

#[test]
fn test_env_var_expansion_nested_positions() {
    std::env::set_var("FRP_RS_TEST_ENV_NESTED_IP", "192.168.1.5");
    std::env::set_var("FRP_RS_TEST_ENV_NESTED_NAME", "env-proxy");
    std::env::set_var("FRP_RS_TEST_ENV_NESTED_TOKEN", "secret-token");
    let cfg: ClientConfig = load_client_config_from_str(
        r#"
server_addr = "127.0.0.1"
server_port = 7000
token = "${FRP_RS_TEST_ENV_NESTED_TOKEN}"

[[proxies]]
name = "${FRP_RS_TEST_ENV_NESTED_NAME}"
type = "tcp"
local_ip = "${FRP_RS_TEST_ENV_NESTED_IP}"
local_port = 8080
remote_port = 7001

[store]
path = "/tmp/${FRP_RS_TEST_ENV_NESTED_NAME}.json"
"#,
    )
    .unwrap();
    std::env::remove_var("FRP_RS_TEST_ENV_NESTED_IP");
    std::env::remove_var("FRP_RS_TEST_ENV_NESTED_NAME");
    std::env::remove_var("FRP_RS_TEST_ENV_NESTED_TOKEN");
    assert_eq!(cfg.token, "secret-token");
    assert_eq!(cfg.proxies.len(), 1);
    assert_eq!(cfg.proxies[0].name, "env-proxy");
    assert_eq!(cfg.proxies[0].local_ip, "192.168.1.5");
    assert_eq!(
        cfg.store.as_ref().unwrap().path,
        "/tmp/env-proxy.json",
        "nested [store] table value expanded"
    );
}

#[test]
fn test_env_var_expansion_double_dollar_to_literal() {
    let cfg: ClientConfig = load_client_config_from_str(
        r#"
server_addr = "127.0.0.1"
token = "a$$b"
"#,
    )
    .unwrap();
    assert_eq!(cfg.token, "a$b", "$$ collapses to a literal $");
}

#[test]
fn test_env_var_expansion_escaped_brace_is_literal() {
    std::env::set_var("FRP_RS_TEST_ENV_ESCAPED", "SHOULD_NOT_APPEAR");
    let cfg: ClientConfig = load_client_config_from_str(
        r#"
server_addr = "127.0.0.1"
token = "$${FRP_RS_TEST_ENV_ESCAPED}"
"#,
    )
    .unwrap();
    std::env::remove_var("FRP_RS_TEST_ENV_ESCAPED");
    assert_eq!(
        cfg.token, "${FRP_RS_TEST_ENV_ESCAPED}",
        "$${{VAR}} stays a literal ${{VAR}} (escape hatch)"
    );
}

#[test]
fn test_env_var_expansion_ignores_bare_dollar() {
    std::env::set_var("FRP_RS_TEST_ENV_NOBRACE", "nope");
    let cfg: ClientConfig = load_client_config_from_str(
        r#"
server_addr = "127.0.0.1"
token = "$FRP_RS_TEST_ENV_NOBRACE"
"#,
    )
    .unwrap();
    std::env::remove_var("FRP_RS_TEST_ENV_NOBRACE");
    assert_eq!(
        cfg.token, "$FRP_RS_TEST_ENV_NOBRACE",
        "bare $VAR (no braces) is not expanded"
    );
}

#[test]
fn test_env_var_expansion_yaml_format() {
    std::env::set_var("FRP_RS_TEST_ENV_YAML_SERVER", "yaml-host");
    let cfg = load_client_config_from_yaml(
        r#"
server_addr: ${FRP_RS_TEST_ENV_YAML_SERVER}
server_port: 7000
"#,
    )
    .unwrap();
    std::env::remove_var("FRP_RS_TEST_ENV_YAML_SERVER");
    assert_eq!(
        cfg.server_addr, "yaml-host",
        "env expansion applies to all formats' toml::Value output"
    );
}

#[test]
fn test_env_var_expansion_in_include_file() {
    std::env::set_var("FRP_RS_TEST_ENV_INCLUDE_TOKEN", "inc-token");
    let dir = tempfile::tempdir().unwrap();
    let main_path = dir.path().join("frps.toml");
    std::fs::write(
        &main_path,
        r#"
bind_addr = "0.0.0.0"
bind_port = 7000
includes = ["extra.toml"]
"#,
    )
    .unwrap();
    std::fs::write(
        dir.path().join("extra.toml"),
        r#"
token = "${FRP_RS_TEST_ENV_INCLUDE_TOKEN}"
"#,
    )
    .unwrap();
    let cfg = super::load_server_config(main_path.to_str().unwrap(), false).unwrap();
    std::env::remove_var("FRP_RS_TEST_ENV_INCLUDE_TOKEN");
    assert_eq!(
        cfg.auth.token, "inc-token",
        "include file values are env-expanded (expansion runs after includes merge)"
    );
}

#[test]
fn test_env_var_expansion_unclosed_brace_kept_verbatim() {
    // `${` with no closing `}` stays literal (no panic, no expansion).
    let cfg: ClientConfig = load_client_config_from_str(
        r#"
server_addr = "127.0.0.1"
server_port = 7000
token = "abc-${UNCLOSED"
"#,
    )
    .unwrap();
    assert_eq!(
        cfg.auth.as_ref().unwrap().token,
        "abc-${UNCLOSED",
        "unclosed dollar-brace kept verbatim"
    );
}

#[test]
fn test_env_var_expansion_empty_name() {
    // `${}` (empty name) expands to the empty string.
    let cfg: ClientConfig = load_client_config_from_str(
        r#"
server_addr = "127.0.0.1"
server_port = 7000
token = "a${}b"
"#,
    )
    .unwrap();
    assert_eq!(
        cfg.auth.as_ref().unwrap().token,
        "ab",
        "${{}} expands to empty string"
    );
}

// ─── Template function expansion (Go frp `{{ parseNumberRange ... }}`) ──

/// Expand `{{ parseNumberRange ... }}` in a single string through the
/// `expand_template_functions` pass (the toml::Value tree entry point).
fn expand_template_in_str(s: &str) -> String {
    let mut value = toml::Value::String(s.to_string());
    super::normalize::expand_template_functions(&mut value);
    value.as_str().unwrap().to_string()
}

#[test]
fn test_parse_number_range_basic() {
    assert_eq!(
        expand_template_in_str(r#"{{ parseNumberRange "7000-7003" }}"#),
        "7000,7001,7002,7003"
    );
    assert_eq!(
        expand_template_in_str(r#"{{ parseNumberRange "7000" }}"#),
        "7000",
        "single number"
    );
}

#[test]
fn test_parse_number_range_mixed_segments() {
    assert_eq!(
        expand_template_in_str(r#"{{ parseNumberRange "7000-7001,7005" }}"#),
        "7000,7001,7005",
        "range and single numbers mixed in one expression"
    );
    assert_eq!(
        expand_template_in_str(r#"{{ parseNumberRange "7000 , 7003-7004" }}"#),
        "7000,7003,7004",
        "whitespace around components is trimmed (Go TrimSpace semantics)"
    );
}

#[test]
fn test_parse_number_range_embedded_in_longer_string() {
    assert_eq!(
        expand_template_in_str(r#"8080,{{ parseNumberRange "9000-9001" }}"#),
        "8080,9000,9001",
        "expansion concatenated with surrounding text"
    );
    assert_eq!(
        expand_template_in_str(r#"http://127.0.0.1:{{ parseNumberRange "8000-8001" }}/path"#),
        "http://127.0.0.1:8000,8001/path",
        "expansion inside a URL-like string"
    );
}

#[test]
fn test_parse_number_range_multiple_calls_in_one_string() {
    assert_eq!(
        expand_template_in_str(
            r#"{{ parseNumberRange "7000-7001" }}|{{ parseNumberRange "9000" }}"#
        ),
        "7000,7001|9000",
        "several calls each expand in place"
    );
}

#[test]
fn test_parse_number_range_whitespace_variants() {
    assert_eq!(
        expand_template_in_str(r#"{{  parseNumberRange  "7000"  }}"#),
        "7000",
        "whitespace after {{ and before }} is allowed"
    );
    assert_eq!(
        expand_template_in_str(r#"{{parseNumberRange "7000"}}"#),
        "7000",
        "no whitespace at all is also accepted"
    );
    assert_eq!(
        expand_template_in_str("{{\n\tparseNumberRange\t\"7000\"\n}}"),
        "7000",
        "newline/tab whitespace is allowed"
    );
}

#[test]
fn test_parse_number_range_invalid_kept_verbatim() {
    let invalid = r#"{{ parseNumberRange "abc" }}"#;
    assert_eq!(
        expand_template_in_str(invalid),
        invalid,
        "non-numeric expression kept verbatim"
    );
    let reversed = r#"{{ parseNumberRange "5-2" }}"#;
    assert_eq!(
        expand_template_in_str(reversed),
        reversed,
        "N > M range kept verbatim"
    );
    let multi_dash = r#"{{ parseNumberRange "1-2-3" }}"#;
    assert_eq!(
        expand_template_in_str(multi_dash),
        multi_dash,
        "segment with more than one '-' kept verbatim"
    );
    let empty = r#"{{ parseNumberRange "" }}"#;
    assert_eq!(
        expand_template_in_str(empty),
        empty,
        "empty expression kept verbatim"
    );
}

#[test]
fn test_parse_number_range_out_of_port_range_kept_verbatim() {
    let over = r#"{{ parseNumberRange "70000" }}"#;
    assert_eq!(
        expand_template_in_str(over),
        over,
        "port above 65535 kept verbatim"
    );
    let range_over = r#"{{ parseNumberRange "60000-70000" }}"#;
    assert_eq!(
        expand_template_in_str(range_over),
        range_over,
        "range reaching above 65535 kept verbatim"
    );
    let negative = r#"{{ parseNumberRange "-1" }}"#;
    assert_eq!(
        expand_template_in_str(negative),
        negative,
        "negative port kept verbatim"
    );
}

#[test]
fn test_parse_number_range_huge_expansion_capped() {
    // L12: an unbounded range expression (0-65535 → 65536 numbers, or an
    // arbitrarily long comma list) must not balloon the produced string
    // (~450 KB for the full port space) — or, via the legacy [range:...]
    // INI path, 65536 per-port proxies. The expansion is capped and the
    // expression is treated as invalid (kept verbatim, like other invalid
    // segments). Real configs stay far below the cap.
    let full_space = r#"{{ parseNumberRange "0-65535" }}"#;
    assert_eq!(
        expand_template_in_str(full_space),
        full_space,
        "full-port-space expansion exceeds the cap → kept verbatim"
    );
    // A many-single-number list also hits the cap.
    let huge_list = format!(
        r#"{{{{ parseNumberRange "{}" }}}}"#,
        (0..=7000)
            .collect::<Vec<_>>()
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(",")
    );
    assert_eq!(
        expand_template_in_str(&huge_list),
        huge_list,
        "7001 single numbers exceed the cap → kept verbatim"
    );
    // A large-but-legal expansion still works (cap is 4096).
    let ok = expand_template_in_str(r#"{{ parseNumberRange "1000-5000" }}"#);
    let nums: Vec<&str> = ok.split(',').collect();
    assert_eq!(nums.len(), 4001, "4001 numbers are within the cap");
    assert_eq!(nums[0], "1000");
    assert_eq!(nums[4000], "5000");
}

#[test]
fn test_template_envs_reference_expands() {
    // `{{ .Envs.NAME }}` is Go frp's documented environment pattern
    // (template data Values.Envs, pkg/config/load.go) — `token = "{{
    // .Envs.FRP_TOKEN }}"` is the canonical Go config. It must expand, not
    // stay verbatim (a literal `{{ .Envs.X }}` token fails auth silently).
    const NAME: &str = "FRP_RS_TEST_TEMPLATE_ENVS_1";
    std::env::remove_var(NAME);
    assert_eq!(
        expand_template_in_str(&format!("{{{{ .Envs.{NAME} }}}}")),
        "<no value>",
        // Go frp's RenderWithTemplate calls template.New without a
        // missingkey option (pkg/config/load.go:84-98), so the text/template
        // default applies: `{{ .Envs.UNSET }}` — a missing map key — prints
        // the literal "<no value>" when the template executes. Byte-parity
        // matters here: an empty string could silently disable token auth
        // (`token = "{{ .Envs.FRP_TOKEN }}"`), while "<no value>" never
        // matches any client config.
        "unset .Envs reference renders Go's '<no value>' placeholder"
    );
    std::env::set_var(NAME, "envval");
    assert_eq!(
        expand_template_in_str(&format!("{{{{ .Envs.{NAME} }}}}")),
        "envval",
        "set .Envs reference expands to the environment value"
    );
    let mixed = format!("a{{{{ parseNumberRange \"7000\" }}}}b{{{{ .Envs.{NAME} }}}}c");
    assert_eq!(
        expand_template_in_str(&mixed),
        "a7000benvvalc",
        "parseNumberRange and .Envs actions both expand in one string"
    );
    std::env::remove_var(NAME);
}

#[test]
fn test_template_non_envs_actions_kept_verbatim() {
    // Template syntax OUTSIDE the two recognized forms is not processed
    // (deliberate zero-engine subset): `.Envs` alone (Go renders the whole
    // map), dotted variable chains, index/range argument forms.
    let other = "{{ .SomeField.X }}";
    assert_eq!(
        expand_template_in_str(other),
        other,
        "non-Envs variable chain kept verbatim"
    );
    let envs_alone = "{{ .Envs }}";
    assert_eq!(
        expand_template_in_str(envs_alone),
        envs_alone,
        "bare {{ .Envs }} map render kept verbatim"
    );
    let index_form = "{{ index .Envs \"X-Y\" }}";
    assert_eq!(
        expand_template_in_str(index_form),
        index_form,
        "index-syntax .Envs access kept verbatim"
    );
    let range_arg = "{{ parseNumberRange .Envs.PORT_RANGE }}";
    assert_eq!(
        expand_template_in_str(range_arg),
        range_arg,
        ".Envs as a parseNumberRange argument kept verbatim"
    );
    // A `}}` missing entirely is not an action at all.
    let unclosed = "{{ .Envs.X";
    assert_eq!(expand_template_in_str(unclosed), unclosed);
}

#[test]
fn test_parse_number_range_env_then_template() {
    // Env expansion runs first (env → template), so a ${VAR} inside the
    // template argument is expanded before parseNumberRange sees it.
    // RAII guard: removes the var even if the loader panics.
    struct EnvGuard(&'static str);
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            std::env::remove_var(self.0);
        }
    }
    std::env::remove_var("FRP_RS_TEST_ENV_RANGE");
    let _guard = EnvGuard("FRP_RS_TEST_ENV_RANGE");
    std::env::set_var("FRP_RS_TEST_ENV_RANGE", "7000-7002");
    let cfg: ClientConfig = load_client_config_from_str(
        r#"
server_addr = "127.0.0.1"
server_port = 7000
token = '{{ parseNumberRange "${FRP_RS_TEST_ENV_RANGE}" }}'
"#,
    )
    .unwrap();
    assert_eq!(
        cfg.auth.as_ref().unwrap().token,
        "7000,7001,7002",
        "env var inside the template argument expanded first"
    );
}

#[test]
fn test_parse_number_range_full_pipeline_allow_ports() {
    // Server pipeline end-to-end: allow_ports is a comma-separated port-list
    // string, so the expansion result feeds straight into its validator.
    let cfg: ServerConfig = load_server_config_from_str(
        r#"
bind_port = 7000
allow_ports = '{{ parseNumberRange "7100-7102,7105" }}'
"#,
    )
    .unwrap();
    assert_eq!(cfg.allow_ports, "7100,7101,7102,7105");
}

#[test]
fn test_parse_number_range_array_and_table_positions() {
    let mut value: toml::Value = toml::from_str(
        r#"
port = '{{ parseNumberRange "7100-7101" }}'
list = ['{{ parseNumberRange "7200-7201" }}', 'x-{{ parseNumberRange "7300" }}-y']
[deep.nested]
range = '{{ parseNumberRange "7400-7402" }}'
"#,
    )
    .unwrap();
    super::normalize::expand_template_functions(&mut value);
    assert_eq!(
        value.get("port").and_then(toml::Value::as_str),
        Some("7100,7101"),
        "top-level string value"
    );
    let list = value.get("list").and_then(toml::Value::as_array).unwrap();
    assert_eq!(list[0].as_str(), Some("7200,7201"), "array element");
    assert_eq!(
        list[1].as_str(),
        Some("x-7300-y"),
        "embedded in array element"
    );
    assert_eq!(
        value
            .get("deep")
            .and_then(toml::Value::as_table)
            .and_then(|t| t.get("nested"))
            .and_then(toml::Value::as_table)
            .and_then(|t| t.get("range"))
            .and_then(toml::Value::as_str),
        Some("7400,7401,7402"),
        "nested table value"
    );
}

#[test]
fn test_parse_number_range_edge_inputs_kept_verbatim() {
    // Edge inputs that Go's ParseRangeNumbers rejects (or that fall outside
    // our minimal subset) must be kept verbatim, never half-expanded.
    let cases = [
        // trailing comma -> empty segment
        "{{ parseNumberRange \"7000,\" }}",
        // unclosed quote -> not a call
        "{{ parseNumberRange \"7000 }}",
        // u64-overflowing number -> no panic, kept verbatim
        "{{ parseNumberRange \"99999999999999999999\" }}",
        // escaped quote inside argument -> outside subset, kept verbatim
        "{{ parseNumberRange \"a\\\"b\" }}",
    ];
    for (i, input) in cases.iter().enumerate() {
        let mut value: toml::Value = toml::from_str(&format!("token = '{input}'")).unwrap();
        super::normalize::expand_template_functions(&mut value);
        let token = value.get("token").unwrap().as_str().unwrap();
        assert_eq!(token, *input, "case {i}: kept verbatim");
    }
}

// ─── Audit task 9 regression tests (Config/CLI Go-compat) ─────────────────

#[test]
fn test_strict_accepts_go_valid_client_keys() {
    // Go frp v0.70.1-valid client config that previously failed frpc verify
    // with "unknown field heartbeat_timeout" (audit task 9 finding 1):
    // transport.heartbeatTimeout is flattened to top-level heartbeat_timeout
    // by normalize_client_config, and the Go camelCase aliases reach the top
    // level untouched.
    let mut client_file = tempfile::NamedTempFile::new().unwrap();
    client_file
        .write_all(
            br#"serverAddr = "127.0.0.1"
serverPort = 7000
loginFailExit = true
poolCount = 4
tcpMux = true
udpPacketSize = 1500
dnsServer = "8.8.8.8"
webServer = { addr = "127.0.0.1", port = 7400 }
featureGates = { VirtualNet = true }

[transport]
heartbeatInterval = 10
heartbeatTimeout = 60
"#,
        )
        .unwrap();
    let cfg = load_client_config(client_file.path().to_str().unwrap(), true).unwrap();
    assert_eq!(cfg.heartbeat_interval, 10);
    assert_eq!(cfg.heartbeat_timeout, 60);
    assert_eq!(cfg.pool_count, 4);
    assert_eq!(cfg.udp_packet_size, 1500);
    assert_eq!(cfg.dns_server, "8.8.8.8");
    assert_eq!(cfg.web_server.port, 7400);
}

#[test]
fn test_strict_accepts_go_valid_server_aliases() {
    // Go frp v0.70.1 camelCase server aliases that normalization does not
    // rename away (audit task 9 finding 1).
    let mut server_file = tempfile::NamedTempFile::new().unwrap();
    server_file
        .write_all(
            br#"bindPort = 7000
detailedErrorsToClient = false
udpPacketSize = 2048
tcpmuxPassthrough = true
vhostHTTPTimeout = 30
maxConnections = 100
"#,
        )
        .unwrap();
    let cfg = load_server_config(server_file.path().to_str().unwrap(), true).unwrap();
    assert!(!cfg.detailed_errors_to_client);
    assert_eq!(cfg.udp_packet_size, 2048);
    assert!(cfg.tcp_mux_passthrough);
    assert_eq!(cfg.vhost_http_timeout, 30);
    assert_eq!(cfg.max_connections, Some(100));
}

#[test]
fn test_strict_rejects_nested_unknown_keys() {
    // Strict mode must recurse into sub-tables (audit task 9 finding 2):
    // unknown keys inside [log] / [auth] are caught even though the section
    // name itself is known.
    let mut log_file = tempfile::NamedTempFile::new().unwrap();
    log_file
        .write_all(
            br#"serverAddr = "127.0.0.1"
[log]
level = "info"
levell = "info"
"#,
        )
        .unwrap();
    let err = load_client_config(log_file.path().to_str().unwrap(), true)
        .unwrap_err()
        .to_string();
    assert!(err.contains("unknown field \"log.levell\""), "got: {err}");

    let mut auth_file = tempfile::NamedTempFile::new().unwrap();
    auth_file
        .write_all(
            br#"bindPort = 7000
[auth]
token = "secret"
tokenz = "secret"
"#,
        )
        .unwrap();
    let err = load_server_config(auth_file.path().to_str().unwrap(), true)
        .unwrap_err()
        .to_string();
    assert!(err.contains("unknown field \"auth.tokenz\""), "got: {err}");
}

/// Strict mode recurses into `[[proxies]]` / `[[visitors]]` / `[[httpPlugins]]`
/// array elements with one key set per **struct** (`strict.rs`:
/// `PROXY_KNOWN_KEYS`, `VISITOR_KNOWN_KEYS`, `CLIENT_PLUGIN_KNOWN_KEYS`,
/// `VISITOR_PLUGIN_KNOWN_KEYS`, `HTTP_PLUGIN_KNOWN_KEYS`), so an unknown field
/// inside an element is refused with the element index in the path — the
/// Go-faithful direction. Go frp v0.71.0 with strict mode on (its default)
/// refuses to start on the config below: `decode proxy at index 0: unmarshal
/// ProxyConfig error: json: unknown field "bogus_key_in_tcp_proxy"` (measured
/// on the v0.71.0 darwin/arm64 binary; `frpc verify -c` exits 1).
///
/// The key sets are generated from the struct definitions and held in place by
/// `strict_array_element_keys_match_struct_fields`, which fails when a field or
/// `alias` is added without updating the list. The older
/// `test_strict_rejects_unknown_proxy_field` covers the single-`tcp`-proxy
/// case; this one adds the visitor half, the plugin table, the server-side
/// `[[httpPlugins]]` array and the non-strict contrast.
#[test]
fn strict_mode_rejects_unknown_proxy_and_visitor_array_elements() {
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(
        br#"serverAddr = "127.0.0.1"
serverPort = 7000
token = "t"

[[proxies]]
name = "plain"
type = "tcp"
local_port = 80
remote_port = 7001
bogus_key_in_tcp_proxy = 1

[[proxies]]
name = "plug"
type = "tcp"
remote_port = 7002
bogus_key_in_plugin_proxy = 1
[proxies.plugin]
type = "http_proxy"
httpUser = "u"

[[visitors]]
name = "vis"
type = "xtcp"
server_name = "s"
bind_port = 7003
protocol = ""
bogus_key_in_visitor = 1
"#,
    )
    .unwrap();
    let err = load_client_config(f.path().to_str().unwrap(), true)
        .unwrap_err()
        .to_string();
    for expected in [
        "unknown field \"proxies[0].bogus_key_in_tcp_proxy\"",
        "unknown field \"proxies[1].bogus_key_in_plugin_proxy\"",
        "unknown field \"visitors[0].bogus_key_in_visitor\"",
    ] {
        assert!(
            err.contains(expected),
            "strict mode must refuse {expected:?}; got: {err}"
        );
    }

    // The same file without the three unknown keys loads under strict mode and
    // carries the element values the arrays declared — the refusal above is the
    // unknown keys, not a blanket refusal of proxies/visitors. (`protocol = ""`
    // on the xtcp visitor also exercises the normalizer's empty-protocol arm.)
    let mut clean = tempfile::NamedTempFile::new().unwrap();
    clean
        .write_all(
            br#"serverAddr = "127.0.0.1"
serverPort = 7000
token = "t"

[[proxies]]
name = "plain"
type = "tcp"
local_port = 80
remote_port = 7001

[[proxies]]
name = "plug"
type = "tcp"
remote_port = 7002
[proxies.plugin]
type = "http_proxy"
httpUser = "u"

[[visitors]]
name = "vis"
type = "xtcp"
server_name = "s"
bind_port = 7003
protocol = ""
"#,
        )
        .unwrap();
    let cfg = load_client_config(clean.path().to_str().unwrap(), true)
        .expect("the same config without the unknown keys must load");
    assert_eq!(cfg.proxies.len(), 2);
    assert_eq!(cfg.proxies[0].name, "plain");
    assert_eq!(cfg.proxies[0].remote_port, 7001);
    assert_eq!(cfg.proxies[1].name, "plug");
    assert_eq!(
        cfg.proxies[1].plugin.as_ref().unwrap().plugin_type,
        "http_proxy"
    );
    assert_eq!(cfg.visitors.len(), 1);
    assert_eq!(cfg.visitors[0].name, "vis");
    assert_eq!(cfg.visitors[0].protocol, "quic");

    // Non-strict mode keeps the old Go-ignores-unknown-fields behaviour: the
    // key is dropped, the rest of the element is honoured. Go with
    // `--strict-config=false` loads this file too (measured).
    let cfg = load_client_config(f.path().to_str().unwrap(), false)
        .expect("non-strict mode must still load the file");
    assert_eq!(cfg.proxies.len(), 2);
    assert_eq!(cfg.proxies[0].remote_port, 7001);
    assert_eq!(cfg.proxies[1].name, "plug");
    assert_eq!(cfg.visitors.len(), 1);

    // The server-side array is checked too: `[[httpPlugins]]` normalizes to
    // `http_plugins`, and the error path carries the element index.
    let mut sf = tempfile::NamedTempFile::new().unwrap();
    sf.write_all(
        br#"bindPort = 7000
[[httpPlugins]]
name = "hook"
addr = "http://127.0.0.1:4000"
path = "/handler"
ops = ["login"]
bogus_key_in_http_plugin = 1
"#,
    )
    .unwrap();
    let err = load_server_config(sf.path().to_str().unwrap(), true)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("unknown field \"http_plugins[0].bogus_key_in_http_plugin\""),
        "got: {err}"
    );

    let mut sclean = tempfile::NamedTempFile::new().unwrap();
    sclean
        .write_all(
            br#"bindPort = 7000
[[httpPlugins]]
name = "hook"
addr = "http://127.0.0.1:4000"
path = "/handler"
ops = ["login"]
"#,
        )
        .unwrap();
    let scfg = load_server_config(sclean.path().to_str().unwrap(), true)
        .expect("the same httpPlugins entry without the unknown key must load");
    assert_eq!(scfg.http_plugins.len(), 1);
    assert_eq!(scfg.http_plugins[0].name, "hook");

    // Control: the sections strict mode already recursed into still reject an
    // unknown key, so the refusal above cannot be a blanket failure. Server
    // configs are used so `[transport]`/`[web_server]` exercise the section
    // recursion itself (a *client* `[transport]` is flattened to top level
    // before the check, so it rejects too but with an unprefixed `full_key`).
    for (label, body, expected) in [
        (
            "log",
            "bindPort = 7000\n[log]\nlevel = \"info\"\nlevell = \"info\"\n",
            "unknown field \"log.levell\"",
        ),
        (
            "auth",
            "bindPort = 7000\n[auth]\ntoken = \"t\"\ntokenz = \"t\"\n",
            "unknown field \"auth.tokenz\"",
        ),
        (
            "transport",
            "bindPort = 7000\n[transport]\ntcpMux = true\ntcpMuxx = true\n",
            "unknown field \"transport.tcpMuxx\"",
        ),
        (
            "web_server",
            "bindPort = 7000\n[webServer]\naddr = \"127.0.0.1\"\nport = 7400\naddrr = \"x\"\n",
            "unknown field \"web_server.addrr\"",
        ),
    ] {
        let mut cf = tempfile::NamedTempFile::new().unwrap();
        cf.write_all(body.as_bytes()).unwrap();
        let err = load_server_config(cf.path().to_str().unwrap(), true)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains(expected),
            "control [{label}] must still reject: expected {expected:?}, got: {err}"
        );
    }

    // `[webServer]` is frpc's own admin block, not only frps's dashboard: the
    // client spelling normalizes to the same `web_server` section, so it is
    // caught there too (the doc names the section generically).
    let mut wf = tempfile::NamedTempFile::new().unwrap();
    wf.write_all(
        b"serverAddr = \"127.0.0.1\"\nserverPort = 7000\n[webServer]\naddr = \"127.0.0.1\"\nport = 7400\naddrr = \"x\"\n",
    )
    .unwrap();
    let err = load_client_config(wf.path().to_str().unwrap(), true)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("unknown field \"web_server.addrr\""),
        "client [webServer] control: got: {err}"
    );

    // Teeth, without touching `strict.rs`: the *identical* key one level up
    // (top level) is rejected by the same strict check, so the refusals above
    // are the array recursion, not a checker that rejects everything.
    let mut top = tempfile::NamedTempFile::new().unwrap();
    top.write_all(b"serverAddr = \"127.0.0.1\"\nserverPort = 7000\nbogus_key_in_tcp_proxy = 1\n")
        .unwrap();
    let err = load_client_config(top.path().to_str().unwrap(), true)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("unknown field \"bogus_key_in_tcp_proxy\""),
        "top-level control: the same key must be rejected outside the array; got: {err}"
    );
}

// ─── Strict mode: array-element key lists ─────────────────────────────

/// Serde attribute names the key extractor below **models** on a field. Any
/// other `#[serde(...)]` name is a hard error (see `serde_attr_key_names`), so
/// a future attribute that changes the accepted key set cannot slip past the
/// guard unnoticed; it has to be classified here first.
const SERDE_FIELD_ATTRS_MODELLED: &[&str] = &[
    "rename",
    "alias",
    "skip",
    "skip_deserializing",
    // Understood, and unable to change which keys are accepted:
    "default",
    "skip_serializing",
    "with",
    "deserialize_with",
    "serialize_with",
    "borrow",
    "bound",
    "getter",
    "expecting",
];

/// `#[serde(...)]` names on a **field** that would change the accepted key set
/// in a way this scanner does not model. Listed explicitly so the panic message
/// says what to do.
const SERDE_FIELD_ATTRS_UNMODELLED: &[&str] = &[
    "flatten",
    "rename_all",
    "rename_all_fields",
    "untagged",
    "tag",
    "content",
    "transparent",
    "remote",
    "from",
    "try_from",
    "into",
    "crate",
];

/// Same, for a `#[serde(...)]` on the **struct** itself. A container
/// `rename_all` rewrites every field spelling, which is exactly the kind of
/// two-way drift the guard exists to catch, so it panics rather than guessing a
/// case convention.
const SERDE_CONTAINER_ATTRS_MODELLED: &[&str] = &[
    "default",
    "deny_unknown_fields",
    "expecting",
    "bound",
    "crate",
];

const SERDE_CONTAINER_ATTRS_UNMODELLED: &[&str] = &[
    "rename_all",
    "rename_all_fields",
    "flatten",
    "untagged",
    "tag",
    "content",
    "transparent",
];

/// One `#[serde(...)]` entry: its name, an optional `= "value"`, and its
/// optional nested `(...)` entries (for `rename(deserialize = "…")`).
struct SerdeAttr {
    name: String,
    value: Option<String>,
    nested: Vec<SerdeAttr>,
}

/// Parse the argument list of a `#[serde(...)]` attribute (the text between the
/// outer parentheses) into entries, splitting on top-level commas.
fn parse_serde_args(text: &str) -> Vec<SerdeAttr> {
    let mut out = Vec::new();
    let mut rest = text;
    while !rest.trim().is_empty() {
        // name
        let trimmed = rest.trim_start();
        let name_end = trimmed
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(trimmed.len());
        let name = trimmed[..name_end].to_string();
        let mut rest2 = trimmed[name_end..].trim_start();
        let mut value = None;
        let mut nested = Vec::new();
        if let Some(r) = rest2.strip_prefix('=') {
            let r = r.trim_start();
            assert!(
                r.starts_with('"'),
                "serde attribute `{name}` has a non-string value this guard does not model: {text}"
            );
            let after = &r[1..];
            let end = after
                .find('"')
                .unwrap_or_else(|| panic!("unterminated string in serde attribute: {text}"));
            value = Some(after[..end].to_string());
            rest2 = &after[end + 1..];
        } else if let Some(r) = rest2.strip_prefix('(') {
            let (inner, after) = split_balanced_parens(r)
                .unwrap_or_else(|| panic!("unbalanced serde attribute parentheses: {text}"));
            nested = parse_serde_args(inner);
            rest2 = after;
        }
        out.push(SerdeAttr {
            name,
            value,
            nested,
        });
        rest2 = rest2.trim_start();
        if let Some(r) = rest2.strip_prefix(',') {
            rest = r;
        } else {
            assert!(
                rest2.is_empty(),
                "unexpected trailing text in serde attribute: {text}"
            );
            rest = "";
        }
    }
    out
}

/// Split `text` (the inside of a parenthesised group, with the opening paren
/// already consumed) at its matching close paren; returns `(inside, rest)`.
fn split_balanced_parens(text: &str) -> Option<(&str, &str)> {
    let mut depth = 1usize;
    let mut in_string = false;
    let mut prev_backslash = false;
    for (i, c) in text.char_indices() {
        if in_string {
            if c == '"' && !prev_backslash {
                in_string = false;
            }
            prev_backslash = c == '\\' && !prev_backslash;
            continue;
        }
        match c {
            '"' => in_string = true,
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some((&text[..i], &text[i + 1..]));
                }
            }
            _ => {}
        }
    }
    None
}

/// Classify the `#[serde(...)]` entries found on a field or a struct, and panic
/// on any name this guard does not model.
fn classify_serde_attrs(attrs: &[SerdeAttr], container: bool) {
    let (modelled, unmodelled) = if container {
        (
            SERDE_CONTAINER_ATTRS_MODELLED,
            SERDE_CONTAINER_ATTRS_UNMODELLED,
        )
    } else {
        (SERDE_FIELD_ATTRS_MODELLED, SERDE_FIELD_ATTRS_UNMODELLED)
    };
    for attr in attrs {
        let Some(name) = attr.name.as_str().into() else {
            unreachable!()
        };
        let name: &str = name;
        assert!(
            !unmodelled.contains(&name),
            "the strict-mode key guard does not model `#[serde({name})]` \
             ({}): it can change the accepted key set, so the key lists in \
             `strict.rs` cannot be checked against the struct until the \
             extractor is taught it",
            if container {
                "container attribute"
            } else {
                "field attribute"
            }
        );
        assert!(
            modelled.contains(&name),
            "the strict-mode key guard does not recognise `#[serde({name})]` \
             ({}): classify it in `SERDE_FIELD_ATTRS_*` / \
             `SERDE_CONTAINER_ATTRS_*` in `frp-core/src/config/tests.rs` before \
             relying on this guard",
            if container {
                "container attribute"
            } else {
                "field attribute"
            }
        );
    }
}

/// Accepted key names contributed by one field's attributes, or `None` when the
/// field is skipped for deserialization.
fn field_key_names(attrs: &[SerdeAttr], field: &str) -> Option<std::collections::BTreeSet<String>> {
    classify_serde_attrs(attrs, false);
    if attrs
        .iter()
        .any(|a| a.name == "skip" || a.name == "skip_deserializing")
    {
        return None;
    }
    let mut keys = std::collections::BTreeSet::new();
    // Deserialization name: `rename = "…"` and `rename(deserialize = "…")`
    // replace it; a `rename(serialize = "…")` **only** does not, because serde
    // then still deserializes from the field name — measured with a probe struct
    // (`{"inner":1}` parses, `{"out":1}` does not, for
    // `#[serde(rename(serialize = "out"))] inner`), which is also serde's
    // documented behaviour. Demanding `deserialize = …` there would fail the
    // guard on a legitimate edit.
    let renamed = attrs.iter().find(|a| a.name == "rename").map(|a| {
        if let Some(v) = &a.value {
            Some(v.clone())
        } else {
            a.nested
                .iter()
                .find(|n| n.name == "deserialize")
                .and_then(|n| n.value.clone())
        }
    });
    keys.insert(renamed.flatten().unwrap_or_else(|| field.to_string()));
    for alias in attrs.iter().filter(|a| a.name == "alias") {
        keys.insert(
            alias
                .value
                .clone()
                .expect("alias always has a string value"),
        );
    }
    Some(keys)
}

/// Extract the serde-accepted key set of `struct <name>` from a Rust source
/// file: each field's deserialization name (`rename = "…"` or
/// `rename(deserialize = "…")`, else the field name) plus every `alias`,
/// skipping `skip`/`skip_deserializing` fields. Any visibility is read
/// (`pub`, `pub(crate)`, `pub(super)`, `pub(in path)`, or none at all).
///
/// Panics when the struct is missing (the guard must not pass because it
/// matched nothing) and on any serde attribute it does not model — `flatten`
/// and `rename_all` above all, because they make the accepted set open-ended or
/// rewrite every field spelling. Not covered, and stated in
/// `docs/deployment.md`: a `#[cfg]`-gated field is read as if always present, so
/// with the feature off the key lists accept a key the build's serde ignores
/// (the safe direction — a missed typo, never a false 400).
fn serde_keys_of_struct(src: &str, name: &str) -> std::collections::BTreeSet<String> {
    // Any visibility is accepted (`pub`, `pub(crate)`, `pub(super)`,
    // `pub(in …)`, or private): the declaration keyword carries no key
    // information, so the scan starts at `struct <name>` and the container
    // attributes are read from the window before it.
    let needle = format!("struct {name}");
    let mut at = None;
    let mut from = 0usize;
    while let Some(found) = src[from..].find(&needle) {
        let abs = from + found;
        let after = &src[abs + needle.len()..];
        if after.starts_with(|c: char| c.is_whitespace() || c == '{' || c == '<') {
            at = Some(abs);
            break;
        }
        from = abs + needle.len();
    }
    let at =
        at.unwrap_or_else(|| panic!("struct {name} not found in the source passed to this guard"));
    // Container attributes sit between the end of the previous item and
    // `struct`; the derive/doc lines in that window are ignored, and a
    // `#[serde(...)]` there is classified as a container attribute.
    let window_start = src[..at].rfind("\n}").map(|i| i + 2).unwrap_or(0);
    let container_attrs = serde_attrs_in(&src[window_start..at]);
    classify_serde_attrs(&container_attrs, true);

    let open = at + src[at..].find('{').expect("struct body opens");
    let mut depth = 0usize;
    let mut close = None;
    for (offset, ch) in src[open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    close = Some(open + offset);
                    break;
                }
            }
            _ => {}
        }
    }
    let body = &src[open + 1..close.expect("struct body closes")];

    let mut keys = std::collections::BTreeSet::new();
    let mut pending: Vec<SerdeAttr> = Vec::new();
    let mut i = 0usize;
    // Only a position where a **field declaration** can start is tested, so an
    // identifier inside a field's type (`HashMap<String, std::path::PathBuf>`,
    // `dyn Iterator<Item: Clone>`) cannot be mistaken for a field. A boundary is
    // the body start, the byte after a `,` at bracket depth 0, and the byte
    // after an attribute or a comment **at depth 0** (comments inside a type
    // must not open one). `depth` counts `<>`, `()`, `[]` so a `,` inside
    // `HashMap<A, B>` does not open a boundary either.
    let mut at_boundary = true;
    let mut depth = 0i32;
    while i < body.len() {
        // Source in this crate carries non-ASCII (em dashes, arrows); every
        // slice below needs a char boundary and the scan advances byte-wise.
        if !body.is_char_boundary(i) {
            i += 1;
            at_boundary = false;
            continue;
        }
        if body[i..].starts_with("//") {
            i += body[i..].find('\n').unwrap_or(body.len() - i);
            at_boundary = depth == 0;
        } else if body[i..].starts_with("/*") {
            i += body[i..].find("*/").expect("block comment closes") + 2;
            at_boundary = depth == 0;
        } else if body[i..].starts_with("#[") {
            let (text, next) = split_attribute(&body[i..]);
            if let Some(args) = serde_args_of(&text) {
                pending.extend(parse_serde_args(args));
            }
            i += next;
            at_boundary = depth == 0;
        } else {
            let ch = body[i..].chars().next().expect("non-empty slice");
            if ch.is_whitespace() {
                // Whitespace between a boundary and the token it introduces must
                // not close the boundary (fields and attributes are indented).
                i += 1;
                continue;
            }
            match ch {
                ',' if depth == 0 => {
                    at_boundary = true;
                    i += 1;
                    continue;
                }
                '<' | '(' | '[' => {
                    depth += 1;
                    at_boundary = false;
                    i += 1;
                    continue;
                }
                '>' | ')' | ']' => {
                    depth = (depth - 1).max(0);
                    at_boundary = false;
                    i += 1;
                    continue;
                }
                _ => {}
            }
            match field_name_at(&body[i..]) {
                Some((field, after)) if at_boundary => {
                    if let Some(names) = field_key_names(&pending, &field) {
                        keys.extend(names);
                    }
                    pending.clear();
                    i += after;
                    at_boundary = false; // inside the field's type now
                }
                _ => {
                    at_boundary = false;
                    i += 1;
                }
            }
        }
    }
    keys
}

/// Every `#[serde(...)]` group in `text`, parsed (doc comments skipped).
fn serde_attrs_in(text: &str) -> Vec<SerdeAttr> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < text.len() {
        if !text.is_char_boundary(i) {
            i += 1;
            continue;
        }
        if text[i..].starts_with("//") {
            i += text[i..].find('\n').unwrap_or(text.len() - i);
        } else if text[i..].starts_with("#[") {
            let (attr, next) = split_attribute(&text[i..]);
            if let Some(args) = serde_args_of(&attr) {
                out.extend(parse_serde_args(args));
            }
            i += next;
        } else {
            i += 1;
        }
    }
    out
}

/// Arguments of a `#[serde(...)]` attribute, or `None` for any other attribute.
///
/// A `serde` attribute that is not exactly the `serde(...)` form — e.g.
/// `#[serde (rename = "…")]` with whitespace before the parenthesis — **panics**
/// rather than being skipped: skipping it would treat the field as unrenamed,
/// which is the drift this guard exists to catch. `rustfmt` normalises the space
/// form away, so the panic is belt-and-braces for hand-written code.
fn serde_args_of(attr: &str) -> Option<&str> {
    let rest = attr.strip_prefix("serde")?;
    if let Some(args) = rest.strip_prefix('(') {
        return args.strip_suffix(')');
    }
    assert!(
        !rest.starts_with(|c: char| c.is_whitespace()),
        "`#[{attr}]` starts with `serde` but is not the `#[serde(...)]` form this \
         guard parses; the key set cannot be derived from it"
    );
    None
}

/// Consume one balanced `#[...]` group at the start of `text`; returns the text
/// between the brackets and how many bytes were consumed.
fn split_attribute(text: &str) -> (String, usize) {
    let bytes = text.as_bytes();
    let mut i = 2usize; // past `#[`
    let mut depth = 1usize;
    let mut in_string = false;
    while i < bytes.len() {
        let c = bytes[i];
        if in_string {
            if c == b'\\' {
                i += 1;
            } else if c == b'"' {
                in_string = false;
            }
        } else if c == b'"' {
            in_string = true;
        } else if c == b'[' {
            depth += 1;
        } else if c == b']' {
            depth -= 1;
            if depth == 0 {
                return (text[2..i].to_string(), i + 1);
            }
        }
        i += 1;
    }
    panic!("unbalanced `#[` attribute in struct source: {text}");
}

/// If a field declaration starts at `text`, return its name and the number of
/// bytes it occupies up to (and including) the colon. Handles `pub`,
/// `pub(crate)`, `pub(super)`, `pub(in path)` and a field with **no visibility
/// modifier** (private or inherited) — the visibility carries no key
/// information, and a private field with a serde `alias` is a real way for the
/// lists to go stale (R2's `HealthCheckHttpHeader` mutant).
///
/// The colon must not be the first of a `::` path separator, so a type such as
/// `std::path::PathBuf` cannot be read as a field named `std`.
fn field_name_at(text: &str) -> Option<(String, usize)> {
    let mut consumed = 0usize;
    let mut rest = text;
    if let Some(after_pub) = rest.strip_prefix("pub") {
        // `pub` only counts as a visibility when it is not the start of a
        // longer identifier (`publish`), i.e. it is followed by `(` or space.
        if !after_pub.starts_with(|c: char| c == '(' || c.is_whitespace()) {
            return None;
        }
        consumed += 3;
        rest = after_pub;
        if let Some(r) = rest.trim_start().strip_prefix('(') {
            let (_, after) = split_balanced_parens(r)?;
            consumed += (rest.len() - rest.trim_start().len()) + 1 + (r.len() - after.len());
            rest = after;
        }
    }
    let ws = rest.len() - rest.trim_start().len();
    consumed += ws;
    rest = rest.trim_start();
    // Raw identifier: serde's accepted key is the **stripped** name — measured
    // with a probe struct (`{"match": …}` sets a `r#match` field, the alias
    // `{"aliasMatch": …}` does too, and the literal `{"r#match": …}` does not) —
    // so `r#` is dropped here. Before this, the field was not recognised at all
    // and the extractor returned an empty set for the struct.
    if let Some(stripped) = rest.strip_prefix("r#") {
        consumed += 2;
        rest = stripped;
    }
    let ident_len = rest
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .unwrap_or(rest.len());
    let ident = &rest[..ident_len];
    if ident.is_empty() || ident.starts_with(|c: char| c.is_ascii_digit()) {
        return None;
    }
    let after_ident = rest[ident_len..].trim_start();
    let colon = after_ident.strip_prefix(':')?;
    if colon.starts_with(':') {
        // `::` — a path segment, not a field declaration.
        return None;
    }
    consumed += ident_len + (rest[ident_len..].len() - after_ident.len()) + 1;
    Some((ident.to_string(), consumed))
}

/// The key sets `check_strict` uses for `proxies`/`visitors`/`[[httpPlugins]]`
/// elements and for the `plugin` tables must equal the serde surface of the
/// struct they stand for. This is the drift guard: adding, removing or renaming
/// a field or an `#[serde(alias = "…")]` on any of the six structs without
/// updating the matching list in `strict.rs` fails here, in either direction
/// (a stale list entry is also a bug: it admits a key the deserializer drops).
///
/// **What it does not cover**, stated rather than implied: a container
/// `#[serde(rename_all = …)]` or a field `#[serde(flatten)]`/`skip_*` — those
/// panic in the extractor instead of being modelled, so the suite goes red and
/// asks for the extractor to be taught the transformation; and a *new*
/// struct + array pair added to `child_table_keys`/`child_array_keys` — that
/// needs a new row in the table below, which
/// `strict_known_key_lists_are_all_covered` enforces for `strict.rs`'s
/// `*_KNOWN_KEYS` constants, but not for a wholesale reuse of an existing list.
#[test]
fn strict_array_element_keys_match_struct_fields() {
    use super::strict::{
        CLIENT_PLUGIN_KNOWN_KEYS, HEALTH_CHECK_HEADER_KNOWN_KEYS, HTTP_PLUGIN_KNOWN_KEYS,
        PROXY_KNOWN_KEYS, VISITOR_KNOWN_KEYS, VISITOR_PLUGIN_KNOWN_KEYS, WEB_SERVER_TLS_KNOWN_KEYS,
    };
    let client_src = include_str!("client.rs");
    let server_src = include_str!("server.rs");

    // Extractor self-check: a struct whose `#[serde(...)]` groups span several
    // lines must still yield every alias, and a `rename` must replace the field
    // name. Without this the whole guard could pass by extracting nothing.
    let quic = serde_keys_of_struct(server_src, "QuicOptions");
    let expected_quic: std::collections::BTreeSet<String> = [
        "keepalive_period",
        "keepalivePeriod",
        "max_idle_timeout",
        "maxIdleTimeout",
        "max_incoming_streams",
        "maxIncomingStreams",
        "stream_receive_window",
        "streamReceiveWindow",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    assert_eq!(
        quic, expected_quic,
        "the key extractor must read multi-line #[serde(...)] groups"
    );
    // `rename(deserialize = "…")` and a `pub(super)` field, both synthetic: the
    // tree has no live example of either, and the guard must handle them.
    let synthetic = concat!(
        "pub(super) struct Synthetic {\n",
        "    #[serde(rename(deserialize = \"renamed\", serialize = \"out\"))]\n",
        "    pub(crate) inner_name: String,\n",
        "    pub(in crate::config) plain: u8,\n",
        "    #[serde(skip_deserializing)]\n",
        "    pub skipped: u8,\n",
        "}\n",
    );
    let synthetic_keys = serde_keys_of_struct(synthetic, "Synthetic");
    let expected_synthetic: std::collections::BTreeSet<String> =
        ["renamed", "plain"].iter().map(|s| s.to_string()).collect();
    assert_eq!(
        synthetic_keys, expected_synthetic,
        "pub(crate)/pub(in …) fields and rename(deserialize = …) must be extracted"
    );

    for (label, src, struct_name, list) in [
        (
            "PROXY_KNOWN_KEYS",
            client_src,
            "ProxyConfig",
            PROXY_KNOWN_KEYS,
        ),
        (
            "VISITOR_KNOWN_KEYS",
            client_src,
            "VisitorConfig",
            VISITOR_KNOWN_KEYS,
        ),
        (
            "CLIENT_PLUGIN_KNOWN_KEYS",
            server_src,
            "PluginConfig",
            CLIENT_PLUGIN_KNOWN_KEYS,
        ),
        (
            "VISITOR_PLUGIN_KNOWN_KEYS",
            client_src,
            "VisitorPluginConfig",
            VISITOR_PLUGIN_KNOWN_KEYS,
        ),
        (
            "HTTP_PLUGIN_KNOWN_KEYS",
            server_src,
            "HttpPluginConfig",
            HTTP_PLUGIN_KNOWN_KEYS,
        ),
        (
            "HEALTH_CHECK_HEADER_KNOWN_KEYS",
            client_src,
            "HealthCheckHttpHeader",
            HEALTH_CHECK_HEADER_KNOWN_KEYS,
        ),
        (
            // The nested `web_server.tls` table the strict walker descends into
            // (a `child_table_keys` set, not an array element set — the guard is
            // the same shape).
            "WEB_SERVER_TLS_KNOWN_KEYS",
            server_src,
            "WebServerTlsConfig",
            WEB_SERVER_TLS_KNOWN_KEYS,
        ),
    ] {
        let extracted = serde_keys_of_struct(src, struct_name);
        let listed: std::collections::BTreeSet<String> =
            list.iter().map(|k| (*k).to_string()).collect();
        let missing: Vec<&String> = extracted.difference(&listed).collect();
        let stale: Vec<&String> = listed.difference(&extracted).collect();
        assert!(
            missing.is_empty(),
            "{label} is missing serde keys {missing:?} of {struct_name} \
             (frp-core/src/config/strict.rs)"
        );
        assert!(
            stale.is_empty(),
            "{label} lists keys {stale:?} that {struct_name} does not accept \
             (frp-core/src/config/strict.rs)"
        );
        assert!(
            !extracted.is_empty(),
            "{label}/{struct_name}: the extractor found no fields at all, so the \
             comparison above proved nothing"
        );
    }
}

/// Every `*_KNOWN_KEYS` list in `strict.rs` must be covered by the guard table
/// above. Without this, a new struct + array pair could add a list that no test
/// ever compares against its struct.
#[test]
fn strict_known_key_lists_are_all_covered() {
    let strict_src = include_str!("strict.rs");
    let mut declared: Vec<String> = Vec::new();
    for line in strict_src.lines() {
        let Some(rest) = line.trim().strip_prefix("pub(super) const ") else {
            continue;
        };
        let Some((name, _)) = rest.split_once(':') else {
            continue;
        };
        if name.ends_with("_KNOWN_KEYS") {
            declared.push(name.to_string());
        }
    }
    declared.sort();
    let covered = [
        "PROXY_KNOWN_KEYS",
        "VISITOR_KNOWN_KEYS",
        "CLIENT_PLUGIN_KNOWN_KEYS",
        "VISITOR_PLUGIN_KNOWN_KEYS",
        "HTTP_PLUGIN_KNOWN_KEYS",
        "HEALTH_CHECK_HEADER_KNOWN_KEYS",
        "WEB_SERVER_TLS_KNOWN_KEYS",
    ];
    let mut covered_sorted: Vec<String> = covered.iter().map(|s| s.to_string()).collect();
    covered_sorted.sort();
    assert_eq!(
        declared, covered_sorted,
        "a `*_KNOWN_KEYS` list in `frp-core/src/config/strict.rs` is not compared \
         against its struct by `strict_array_element_keys_match_struct_fields`; \
         add it there (and to the recursion in strict.rs)"
    );
}

/// Teeth for the extractor: a `#[serde(rename_all = "…")]` container attribute
/// rewrites every field spelling, and the guard must fail loudly instead of
/// comparing against a set it cannot compute (this is the mutant that slipped
/// through the first version of the guard).
#[test]
#[should_panic(expected = "does not model `#[serde(rename_all)]`")]
fn strict_key_extractor_refuses_rename_all() {
    let synthetic = "#[serde(rename_all = \"camelCase\")]\npub struct Cased {\n    pub health_check_type: String,\n}\n";
    let _ = serde_keys_of_struct(synthetic, "Cased");
}

/// Teeth: a `#[serde(flatten)]` field makes a struct's key set open-ended
/// (the repo's `FeatureConfig` is that shape), so the guard must fail rather
/// than compare against a set it cannot complete.
#[test]
#[should_panic(expected = "does not model `#[serde(flatten)]`")]
fn strict_key_extractor_refuses_open_ended_structs() {
    let synthetic = "pub struct Open {\n    #[serde(flatten)]\n    pub gates: std::collections::HashMap<String, bool>,\n}\n";
    let _ = serde_keys_of_struct(synthetic, "Open");
}

/// Teeth: an unrecognised serde attribute must not be ignored — if it changed
/// the key set, the two-way comparison would silently accept the drift.
#[test]
#[should_panic(expected = "does not recognise `#[serde(invented_attr)]`")]
fn strict_key_extractor_refuses_unknown_attrs() {
    let synthetic = "pub struct Odd {\n    #[serde(invented_attr)]\n    pub x: u8,\n}\n";
    let _ = serde_keys_of_struct(synthetic, "Odd");
}

/// A raw identifier contributes its **stripped** name, which is what serde
/// accepts: measured with a probe struct, `{"match": …}` sets a `r#match` field
/// and the alias `{"aliasMatch": …}` sets it too, while the literal
/// `{"r#match": …}` is ignored. Before this the field was not recognised at all
/// and the extractor returned an **empty** set for the whole struct, so adding a
/// raw-ident field to one of the six structs left the guard green while the
/// binary refused both the stripped name and the alias.
#[test]
fn strict_key_extractor_strips_raw_identifier_prefixes() {
    let synthetic = "pub struct Raw {\n    #[serde(default, alias = \"aliasMatch\")]\n    pub r#match: String,\n}\n";
    let keys = serde_keys_of_struct(synthetic, "Raw");
    let expected: std::collections::BTreeSet<String> = ["match", "aliasMatch"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    assert_eq!(keys, expected);
}

/// Teeth for the same hole on the open-ended path: a `#[serde(flatten)]` field
/// written as a raw identifier **in last position** used to leave the stale
/// attribute list unclassified, so the extractor returned a closed set
/// (`{"kept"}`) with no panic — the guard would have blessed a struct whose key
/// set is open-ended.
#[test]
#[should_panic(expected = "does not model `#[serde(flatten)]`")]
fn strict_key_extractor_refuses_open_ended_structs_behind_a_raw_ident() {
    let synthetic = "pub struct OpenRaw {\n    pub kept: u8,\n    #[serde(flatten)]\n    pub r#extra: std::collections::HashMap<String, String>,\n}\n";
    let _ = serde_keys_of_struct(synthetic, "OpenRaw");
}

/// Teeth: `#[serde (rename = "…")]` with whitespace before the parenthesis is
/// not parsed as a serde attribute, so skipping it silently would treat the
/// field as unrenamed. `rustfmt` normalises the spelling, but the extractor
/// fails closed anyway.
#[test]
#[should_panic(expected = "is not the `#[serde(...)]` form")]
fn strict_key_extractor_refuses_the_spaced_serde_attribute_form() {
    let _ = serde_keys_of_struct(
        "pub struct Spaced {\n    #[serde (rename = \"x\")]\n    pub inner: u8,\n}\n",
        "Spaced",
    );
}

/// Teeth: a struct that is not in the source must panic, not return an empty
/// set (a silently skipped struct would be a guard that proves nothing).
#[test]
#[should_panic(expected = "not found in the source")]
fn strict_key_extractor_refuses_missing_structs() {
    let _ = serde_keys_of_struct("pub struct Other { pub x: u8 }\n", "ProxyConfig");
}

/// A field with **no** visibility modifier still contributes its key. R2's
/// mutant — `#[serde(default, alias = "driftPriv")] drift_priv: String` on
/// `HealthCheckHeader` — compiles, is accepted by serde, and left the earlier
/// scanner (which required a literal `pub`) passing while the binary refused the
/// serde-accepted `driftPriv`: a green guard over a false 400.
#[test]
fn strict_key_extractor_reads_private_fields() {
    let synthetic = "pub struct Priv {\n    #[serde(default, alias = \"driftPriv\")]\n    drift_priv: String,\n}\n";
    let keys = serde_keys_of_struct(synthetic, "Priv");
    let expected: std::collections::BTreeSet<String> = ["drift_priv", "driftPriv"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    assert_eq!(
        keys, expected,
        "a private field and its serde alias must be extracted"
    );
}

/// `#[serde(rename(serialize = "…"))]` alone does **not** change the key serde
/// deserializes from — the field name does (measured with a probe struct:
/// `{{\"inner\":1}}` parses, `{{\"out\":1}}` does not, for
/// `#[serde(rename(serialize = \"out\"))] inner`). The scanner must therefore use
/// the field name rather than panicking or taking the serialized spelling.
#[test]
fn strict_key_extractor_uses_field_name_for_serialize_only_rename() {
    let synthetic =
        "pub struct SerOnly {\n    #[serde(rename(serialize = \"out\"))]\n    pub inner: u8,\n}\n";
    let keys = serde_keys_of_struct(synthetic, "SerOnly");
    let expected: std::collections::BTreeSet<String> =
        ["inner"].iter().map(|s| s.to_string()).collect();
    assert_eq!(keys, expected);
}
#[test]
fn test_strict_accepts_go_section_keys() {
    // Go-valid keys inside known sections must pass strict mode
    // (audit task 9 findings 1+2, fix round 1: auth.additionalAuthScopes and
    // transport.v2 — both used by scripts/compat-test.sh).
    let mut server_file = tempfile::NamedTempFile::new().unwrap();
    server_file
        .write_all(
            br#"bindPort = 7000
[log]
to = "console"
maxDays = 7
disablePrintColor = true

[web_server]
addr = "0.0.0.0"
port = 7500
assetsDir = "./static"
pprofEnable = true

[transport]
tcpMux = true
heartbeatTimeout = 90
tcpKeepalive = 7200
v2 = true

[auth]
token = "secret"
additionalAuthScopes = ["HeartBeats", "NewWorkConns"]

[ssh_tunnel_gateway]
bindPort = 2200
privateKeyFile = "/etc/frp/host.key"
authorizedKeysFile = "/etc/frp/auth.keys"
allowNoneAuth = false
"#,
        )
        .unwrap();
    let cfg = load_server_config(server_file.path().to_str().unwrap(), true).unwrap();
    assert!(cfg.log.disable_print_color);
    assert_eq!(cfg.log.max_days, 7);
    assert_eq!(cfg.web_server.port, 7500);
    assert_eq!(cfg.web_server.assets_dir, "./static");
    assert!(cfg.web_server.pprof_enable);
    assert_eq!(cfg.transport.heartbeat_timeout, 90);
    assert_eq!(cfg.transport.tcp_keepalive, 7200);
    assert_eq!(cfg.ssh_tunnel_gateway.bind_port, 2200);
    assert_eq!(
        cfg.auth.additional_auth_scopes,
        vec!["HeartBeats".to_string(), "NewWorkConns".to_string()]
    );

    // Same on the client side (compat test_auth_r2g_heartbeats writes
    // additionalAuthScopes under [auth] in frpc.toml).
    let mut client_file = tempfile::NamedTempFile::new().unwrap();
    client_file
        .write_all(
            br#"server_addr = "127.0.0.1"
[auth]
method = "token"
token = "secret"
additionalAuthScopes = ["HeartBeats"]
"#,
        )
        .unwrap();
    let cfg = load_client_config(client_file.path().to_str().unwrap(), true).unwrap();
    assert_eq!(
        cfg.auth
            .as_ref()
            .map(|a| a.additional_auth_scopes.clone())
            .unwrap_or_default(),
        vec!["HeartBeats".to_string()]
    );
}

#[test]
fn test_strict_flag_false_disables_unknown_key_check() {
    // --strict-config=false must parse and disable strict mode (audit task 9
    // finding 3). The CLI flag itself is exercised in frp-core/src/cli.rs
    // tests; here the loader honors the bool.
    let mut client_file = tempfile::NamedTempFile::new().unwrap();
    client_file
        .write_all(
            br#"server_addr = "127.0.0.1"
totally_unknown_key = 1
"#,
        )
        .unwrap();
    // strict = true rejects, strict = false accepts.
    assert!(load_client_config(client_file.path().to_str().unwrap(), true).is_err());
    load_client_config(client_file.path().to_str().unwrap(), false).unwrap();
}

#[test]
fn test_strict_accepts_legacy_log_way() {
    // Go frp legacy INI accepts `log_way` (pkg/config/legacy client.go/
    // server.go LogWay `ini:"log_way"`) and silently drops it: the legacy
    // conversion copies only LogFile/LogLevel/LogMaxDays into the new config
    // (conversion.go), never LogWay. Rust strict mode (default ON) must
    // accept-and-ignore it the same way, on both client and server sides.
    let mut client_file = tempfile::NamedTempFile::new().unwrap();
    client_file
        .write_all(
            br#"server_addr = "127.0.0.1"
server_port = 7000
log_way = "console"
log_file = "./frpc.log"
log_level = "info"
log_max_days = 7
"#,
        )
        .unwrap();
    // strict = true (the default): legacy log_way is a known-and-ignored key.
    load_client_config(client_file.path().to_str().unwrap(), true).unwrap();

    let mut server_file = tempfile::NamedTempFile::new().unwrap();
    server_file
        .write_all(
            br#"bind_port = 7000
log_way = "console"
log_file = "./frps.log"
log_level = "info"
log_max_days = 7
"#,
        )
        .unwrap();
    load_server_config(server_file.path().to_str().unwrap(), true).unwrap();
}

#[test]
fn test_strict_accepts_top_level_sub_domain_host() {
    // Go frp v0.71.0 canonical frps_full_example.toml sets the camelCase
    // top-level `subDomainHost`. normalize does not rename it away, so
    // strict mode (default ON) must accept the alias that the serde field
    // (ServerConfig.sub_domain_host) recognizes.
    let mut server_file = tempfile::NamedTempFile::new().unwrap();
    server_file
        .write_all(
            br#"bind_port = 7000
subDomainHost = "frps.com"
"#,
        )
        .unwrap();
    let cfg = load_server_config(server_file.path().to_str().unwrap(), true).unwrap();
    assert_eq!(cfg.sub_domain_host, "frps.com");
}

#[test]
fn test_allow_ports_single_form_normalized() {
    // Go allowPorts [{single=N}] must normalize to "{single=N}", not the
    // previously emitted "0-0" (audit task 9 finding 6).
    let toml_str = r#"
bind_port = 7000

[[allowPorts]]
single = 40000

[[allowPorts]]
start = 10000
end = 20000
"#;
    let cfg: ServerConfig = load_server_config_from_str(toml_str).unwrap();
    assert_eq!(cfg.allow_ports, "{single=40000},10000-20000");
    let ranges = parse_allow_ports(&cfg.allow_ports).unwrap();
    assert_eq!(ranges.len(), 2);
    assert_eq!(ranges[0].single, 40000, "single-port semantics preserved");
    assert!(ranges[0].contains(40000));
    assert!(!ranges[0].contains(40001));
    assert!(ranges[1].contains(15000));
}

#[test]
fn test_reversed_allow_ports_range_rejected() {
    // Go's ParseRangeNumbers rejects max < min ("range number is invalid")
    // instead of silently swapping (audit task 9 finding 7).
    let err = load_server_config_from_str("bind_port = 7000\nallow_ports = \"20000-10000\"\n")
        .unwrap_err()
        .to_string();
    assert!(err.contains("range number is invalid"), "got: {err}");
}

#[test]
fn test_proxy_validation_rejections() {
    // Go frp v0.70.1 client proxy validation (audit task 9 finding 8).
    let base = "server_addr = \"127.0.0.1\"\n[[proxies]]\nname = \"p\"\n";

    // Empty proxy name.
    let err = load_client_config_from_str(
        "server_addr = \"127.0.0.1\"\n[[proxies]]\nname = \"\"\ntype = \"tcp\"\n",
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("name should not be empty"), "got: {err}");

    // Invalid proxy protocol version.
    let err = load_client_config_from_str(&format!(
        "{base}type = \"tcp\"\nproxyProtocolVersion = \"v3\"\n"
    ))
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("not support proxy protocol version: v3"),
        "got: {err}"
    );
    // Valid versions still parse.
    for version in ["", "v1", "v2"] {
        let cfg = load_client_config_from_str(&format!(
            "{base}type = \"tcp\"\nproxyProtocolVersion = \"{version}\"\n"
        ))
        .unwrap();
        assert_eq!(cfg.proxies[0].proxy_protocol_version, version);
    }

    // Invalid health check type (Go nests health check config under
    // [proxies.healthCheck]).
    let err = load_client_config_from_str(&format!(
        "{base}type = \"tcp\"\n[proxies.healthCheck]\ntype = \"icmp\"\n"
    ))
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("not support health check type: icmp"),
        "got: {err}"
    );

    // http health check without a path.
    let err = load_client_config_from_str(&format!(
        "{base}type = \"tcp\"\n[proxies.healthCheck]\ntype = \"http\"\n"
    ))
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("health check path should not be empty"),
        "got: {err}"
    );

    // http proxy without subdomain or custom domains.
    let err = load_client_config_from_str(&format!("{base}type = \"http\"\n"))
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("subdomain and custom domains should not be both empty"),
        "got: {err}"
    );

    // subdomain with '.' or '*'.
    for bad in ["a.b", "a*b"] {
        let err =
            load_client_config_from_str(&format!("{base}type = \"http\"\nsubdomain = \"{bad}\"\n"))
                .unwrap_err()
                .to_string();
        assert!(
            err.contains("'.' and '*' are not supported in subdomain"),
            "subdomain {bad:?}: got: {err}"
        );
    }

    // tcpmux also requires domains (Go validateTCPMuxProxyConfigForClient).
    let err = load_client_config_from_str(&format!(
        "{base}type = \"tcpmux\"\nmultiplexer = \"httpconnect\"\n"
    ))
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("subdomain and custom domains should not be both empty"),
        "got: {err}"
    );
}

#[test]
fn test_strict_accepts_repo_frps_toml_legacy_keys() {
    // The repo's own frps.toml example uses the frp-rs legacy keys
    // `subdomain_host` and `tls_trusted_ca_file` under [common]; strict mode
    // must accept them and serde must apply them (audit task 9 finding 1
    // family — the documented `cargo run --bin frps -- -c frps.toml`
    // workflow was broken by strict rejection).
    let toml = r#"
[common]
bind_addr = "0.0.0.0"
bind_port = 17000
subdomain_host = "example.com"
tls_enable = true
tls_trusted_ca_file = "/etc/frp/ca.pem"
auth_method = "token"
token = "secret"
log_level = "debug"
web_server_addr = "0.0.0.0"
web_server_port = 7500
tcp_mux = true
"#;
    let cfg: ServerConfig = load_server_config_from_str(toml).unwrap();
    assert_eq!(cfg.sub_domain_host, "example.com");
    assert_eq!(cfg.tls_ca_file, "/etc/frp/ca.pem");
}

#[test]
fn test_tls_skip_verify_client_config_parsed() {
    // Both snake_case and the Go-inspired camel alias map to tls_skip_verify
    // (default false preserves Go-compatible behavior — no CA ⇒ skip).
    let snake: ClientConfig =
        load_client_config_from_str("server_addr = '127.0.0.1'\ntls_skip_verify = true\n").unwrap();
    assert!(snake.tls_skip_verify);

    let camel: ClientConfig =
        load_client_config_from_str("server_addr = '127.0.0.1'\ntlsSkipVerify = true\n").unwrap();
    assert!(camel.tls_skip_verify);

    // Default is false.
    let def: ClientConfig = load_client_config_from_str("server_addr = '127.0.0.1'\n").unwrap();
    assert!(!def.tls_skip_verify);
}

#[test]
fn test_tcp_socket_buffer_client_config_parsed() {
    // tcpSendBuffer/tcpRecvBuffer (frp-rs extension) map to the socket
    // buffer size fields; defaults are 0 (OS default).
    let snake: ClientConfig = load_client_config_from_str(
        "server_addr = '127.0.0.1'\ntcp_send_buffer_size = 262144\ntcp_recv_buffer_size = 524288\n",
    )
    .unwrap();
    assert_eq!(snake.tcp_send_buffer_size, 262144);
    assert_eq!(snake.tcp_recv_buffer_size, 524288);

    let camel: ClientConfig = load_client_config_from_str(
        "server_addr = '127.0.0.1'\ntcpSendBuffer = 131072\ntcpRecvBuffer = 65536\n",
    )
    .unwrap();
    assert_eq!(camel.tcp_send_buffer_size, 131072);
    assert_eq!(camel.tcp_recv_buffer_size, 65536);

    let def: ClientConfig = load_client_config_from_str("server_addr = '127.0.0.1'\n").unwrap();
    assert_eq!(def.tcp_send_buffer_size, 0);
    assert_eq!(def.tcp_recv_buffer_size, 0);

    // Server side.
    let srv: ServerConfig = load_server_config_from_str(
        "bind_port = 7000\ntcpSendBuffer = 1048576\ntcpRecvBuffer = 1048576\n",
    )
    .unwrap();
    assert_eq!(srv.transport.tcp_send_buffer_size, 1048576);
    assert_eq!(srv.transport.tcp_recv_buffer_size, 1048576);
}

#[test]
fn test_log_disable_print_color_parsed() {
    // log.disablePrintColor must be honored from the config file (audit task
    // 9 finding 9 — wired into resolve_ansi by the frps/frpc binaries).
    let cfg: ClientConfig =
        load_client_config_from_str("server_addr = '127.0.0.1'\n[log]\ndisablePrintColor = true\n")
            .unwrap();
    assert!(cfg.log.disable_print_color);

    let cfg: ServerConfig =
        load_server_config_from_str("bind_port = 7000\n[log]\ndisable_print_color = true\n")
            .unwrap();
    assert!(cfg.log.disable_print_color);
}

/// Go legacy INI client keys are mapped to their canonical locations
/// (Go pkg/config/legacy conversion.go).
#[test]
fn test_legacy_ini_client_gaps_mapped() {
    let cfg: ClientConfig = load_client_config_from_str(
        r#"server_addr = "127.0.0.1"
server_port = 7000
token = "t"
authenticate_heartbeats = true
authenticate_new_work_conns = true
http_proxy = "http://proxy.example:8080"
disable_log_color = true
oidc_additional_foo = "bar"
oidc_additional_aud = "baz"
"#,
    )
    .unwrap();
    let scopes = cfg
        .auth
        .as_ref()
        .map(|a| a.additional_auth_scopes.clone())
        .unwrap_or_default();
    assert!(
        scopes.contains(&"HeartBeats".to_string()),
        "scopes: {scopes:?}"
    );
    assert!(
        scopes.contains(&"NewWorkConns".to_string()),
        "scopes: {scopes:?}"
    );
    assert_eq!(cfg.proxy_url, "http://proxy.example:8080");
    assert!(cfg.log.disable_print_color);
    let oidc_params = cfg
        .auth
        .as_ref()
        .map(|a| a.additional_endpoint_params.clone())
        .unwrap_or_default();
    assert_eq!(oidc_params.get("foo"), Some(&"bar".to_string()));
    assert_eq!(oidc_params.get("aud"), Some(&"baz".to_string()));
}

#[test]
fn test_legacy_ini_client_quic_keys_folded() {
    // Go legacy INI client keys quic_keepalive_period / quic_max_idle_timeout
    // / quic_max_incoming_streams -> [transport.quic] (Go legacy client.go
    // QUICKeepalivePeriod/QUICMaxIdleTimeout/QUICMaxIncomingStreams,
    // conversion.go -> Transport.QUIC), which the client normalize then
    // flattens into the top-level `quic` table.
    let cfg: ClientConfig = load_client_config_from_str(
        r#"server_addr = "127.0.0.1"
server_port = 7000
quic_keepalive_period = 15
quic_max_idle_timeout = 60
quic_max_incoming_streams = 4096
"#,
    )
    .unwrap();
    let q = cfg.quic_options.expect("quic_options populated");
    assert_eq!(q.keepalive_period, 15);
    assert_eq!(q.max_idle_timeout, 60);
    assert_eq!(q.max_incoming_streams, 4096);
}

/// Go legacy INI server keys (pprof_enable, dashboard_tls_mode, and the
/// dashboard_* -> web_server migration) are accepted without strict-mode
/// rejection and land in the canonical fields.
#[test]
fn test_legacy_ini_server_gaps_mapped() {
    let cfg: ServerConfig = load_server_config_from_str(
        r#"bind_port = 7000
token = "t"
dashboard_addr = "127.0.0.1"
dashboard_port = 7500
dashboard_user = "admin"
dashboard_pwd = "pw"
dashboard_tls_cert_file = "/tmp/cert.pem"
dashboard_tls_key_file = "/tmp/key.pem"
dashboard_tls_mode = true
pprof_enable = true
assets_dir = "/srv/frp/assets"
disable_log_color = true
log_way = "console"
"#,
    )
    .unwrap();
    assert_eq!(cfg.web_server.addr, "127.0.0.1");
    assert_eq!(cfg.web_server.port, 7500);
    assert_eq!(cfg.web_server.user, "admin");
    assert_eq!(cfg.web_server.password, "pw");
    assert_eq!(cfg.web_server.tls_cert(), "/tmp/cert.pem");
    assert_eq!(cfg.web_server.tls_key(), "/tmp/key.pem");
    assert!(cfg.web_server.pprof_enable);
    // dashboard_tls_mode is consumed as a no-op (TLS driven by cert/key).
    assert!(cfg.web_server.tls_cert_file.contains("cert.pem"));
    // Go legacy server keys: assets_dir -> web_server.assets_dir (Go
    // conversion.go WebServer.AssetsDir), disable_log_color -> [log]
    // disable_print_color (conversion.go Log.DisablePrintColor), and
    // log_way consumed-and-dropped (Go never maps LogWay into the new
    // config).
    assert_eq!(cfg.web_server.assets_dir, "/srv/frp/assets");
    assert!(cfg.log.disable_print_color);
}

/// The new web_server whitelist keys are accepted in strict mode.
#[test]
fn test_strict_accepts_web_server_tls_ca_and_server_name() {
    let cfg: ServerConfig = load_server_config_from_str(
        r#"bind_port = 7000
token = "t"
[web_server]
addr = "127.0.0.1"
port = 7500
tls_cert_file = "/tmp/c.pem"
tls_key_file = "/tmp/k.pem"
trustedCaFile = "/tmp/ca.pem"
serverName = "example.com"
custom404Page = "<h1>nope</h1>"
"#,
    )
    .unwrap();
    assert_eq!(cfg.web_server.tls_ca_file, "/tmp/ca.pem");
    assert_eq!(cfg.web_server.tls_server_name, "example.com");
    assert_eq!(cfg.web_server.custom_404_page, "<h1>nope</h1>");
}

/// The nested `[web_server.tls]` section is **hoisted** onto the flat
/// `web_server.tls_*` fields by `normalize_web_server_section`
/// (`frp-core/src/config/normalize.rs`), because the `tls` table's **mapped**
/// keys are removed before serde sees them. (The table itself survives whenever
/// it holds an unmapped key, and that residue is exactly what `check_strict`
/// walks to report `web_server.tls.<key>` — see
/// `unknown_nested_web_server_tls_key_names_the_true_nested_path`.) Two claims
/// about that hoist are pinned here, each in **both** loader modes and — for
/// precedence — in **both** orders, because the input shape the claim is about is
/// what differs:
///
/// 1. **Both spelling families reach the field.** `WebServerTlsConfig` declares
///    `cert_file` / `key_file` / `trusted_ca_file` / `server_name` as its
///    canonical serde names and the Go camelCase spellings only as `alias`es,
///    so the *canonical* spelling is `cert_file`. Before this pin the hoist
///    renamed **only** the four camelCase spellings and re-inserted `cert_file`
///    under its own name, producing `web_server.cert_file` — not a field, so
///    the value was **dropped** with `strict = false` (the reload path,
///    `load_server_config(&path, false)` in `frp-server/src/service.rs`) and
///    **refused** with `strict = true`, naming `web_server.cert_file` — a path
///    the user never wrote — with the hint `did you mean 'certFile'?`.
/// 2. **The nested spelling wins when both are set.** The struct's doc comment
///    claimed it while `or_insert` made the flat key win, so the claim and the
///    code disagreed; the hoist now overwrites, which is what makes the doc
///    true. Both orders are exercised because `or_insert` is order-sensitive
///    only in the direction that matters (flat first), and TOML table order is
///    the writer's free choice.
///
/// The nested struct itself is asserted **empty** in every case: the `tls`
/// table's mapped keys are removed before serde, so the effective value is
/// always the flat field `tls_cert()` falls back to. (An unmapped key keeps the
/// table alive, but serde ignores it and none of them is a field.) `enable` is deliberately absent from the
/// value table — it is dropped by the hoist (see its doc comment) and pinned by
/// `nested_web_server_tls_enable_is_accepted_and_inert_in_both_modes`.
///
/// **What this models.** The loader entry points the two callers use —
/// `load_server_config(path, strict)` on a real file, one `tempfile::tempdir()`
/// per case, with `strict` in {`false`, `true`}.
///
/// **What it does not cover.** Go's own behaviour on these configs (this pins
/// frp-rs's surface, not parity: Go's `WebServerConfig.TLS` is a `*TLSConfig`
/// whose fields carry camelCase json tags only — `pkg/config/v1/common.go:68`,
/// `:76-84` — so Go refuses a `cert_file` key under strict decoding and has no
/// `enable` field at all); the reload path end to end (the `strict = false`
/// arm is exactly what that path calls, and is exercised directly here); and
/// the YAML/JSON/INI format arms (the hoist runs on the parsed `toml::Value`
/// before format-specific typing).
#[test]
fn nested_web_server_tls_spellings_reach_the_accessor_in_both_modes() {
    const HEADER: &str = "bind_port = 7000\ntoken = \"t\"\n";

    // (tls_cert(), tls_key(), tls_ca_file, tls_server_name, nested tls struct)
    type Loaded = (
        String,
        String,
        String,
        String,
        (String, String, String, String),
    );

    /// Write `body` into its own temp dir and load it in both modes,
    /// returning `(strict = false, strict = true)`.
    fn load_both_modes(body: &str) -> (Loaded, Loaded) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("frps.toml");
        std::fs::write(&path, body).unwrap();
        let p = path.to_str().unwrap();
        let read = |strict: bool| -> Loaded {
            let cfg = load_server_config(p, strict)
                .unwrap_or_else(|e| panic!("strict={strict} must load:\n{e}"));
            let ws = cfg.web_server;
            (
                ws.tls_cert().to_string(),
                ws.tls_key().to_string(),
                ws.tls_ca_file.clone(),
                ws.tls_server_name.clone(),
                (
                    ws.tls.cert_file.clone(),
                    ws.tls.key_file.clone(),
                    ws.tls.trusted_ca_file.clone(),
                    ws.tls.server_name.clone(),
                ),
            )
        };
        (read(false), read(true))
    }

    let expect = |cert: &str, key: &str, ca: &str, sn: &str| -> Loaded {
        (
            cert.into(),
            key.into(),
            ca.into(),
            sn.into(),
            (String::new(), String::new(), String::new(), String::new()),
        )
    };

    // ── 1. The canonical snake_case spelling, nested ───────────────────────
    let snake = format!(
        "{HEADER}[web_server]\naddr = \"127.0.0.1\"\nport = 7500\n\
         [web_server.tls]\ncert_file = \"/snake/cert.pem\"\nkey_file = \"/snake/key.pem\"\n\
         trusted_ca_file = \"/snake/ca.pem\"\nserver_name = \"snake.example.com\"\n",
    );
    let (loose, strict) = load_both_modes(&snake);
    // `strict = false` first: it is the reload path's mode
    // (`load_server_config(&config_path, false)`, `frp-server/src/service.rs`),
    // and the arm whose failure mode was a silent drop rather than an error.
    for (mode, got) in [
        ("strict=false (the reload path)", loose),
        ("strict=true", strict),
    ] {
        assert_eq!(
            got,
            expect(
                "/snake/cert.pem",
                "/snake/key.pem",
                "/snake/ca.pem",
                "snake.example.com"
            ),
            "nested snake_case, {mode}: the struct's own canonical names must \
             reach the accessor, and the nested struct stays unpopulated \
             (normalization removes the table's mapped keys before serde)",
        );
    }

    // ── 2. The Go camelCase spelling, nested (kept working) ────────────────
    let camel = format!(
        "{HEADER}[web_server]\naddr = \"127.0.0.1\"\nport = 7500\n\
         [web_server.tls]\ncertFile = \"/camel/cert.pem\"\nkeyFile = \"/camel/key.pem\"\n\
         trustedCaFile = \"/camel/ca.pem\"\nserverName = \"camel.example.com\"\n",
    );
    let (loose, strict) = load_both_modes(&camel);
    for (mode, got) in [("strict=false", loose), ("strict=true", strict)] {
        assert_eq!(
            got,
            expect(
                "/camel/cert.pem",
                "/camel/key.pem",
                "/camel/ca.pem",
                "camel.example.com"
            ),
            "nested camelCase, {mode}",
        );
    }

    // ── 3. Precedence over a flat key that is already set, both orders ─────
    let both_set = [
        (
            "flat-first/nested-camel",
            format!(
                "{HEADER}[web_server]\naddr = \"127.0.0.1\"\nport = 7500\n\
                 tls_cert_file = \"/flat/cert.pem\"\ntls_key_file = \"/flat/key.pem\"\n\
                 tls_ca_file = \"/flat/ca.pem\"\ntls_server_name = \"flat.example.com\"\n\
                 [web_server.tls]\ncertFile = \"/nested/cert.pem\"\n\
                 keyFile = \"/nested/key.pem\"\ntrustedCaFile = \"/nested/ca.pem\"\n\
                 serverName = \"nested.example.com\"\n"
            ),
        ),
        (
            "flat-first/nested-snake",
            format!(
                "{HEADER}[web_server]\naddr = \"127.0.0.1\"\nport = 7500\n\
                 tls_cert_file = \"/flat/cert.pem\"\ntls_key_file = \"/flat/key.pem\"\n\
                 tls_ca_file = \"/flat/ca.pem\"\ntls_server_name = \"flat.example.com\"\n\
                 [web_server.tls]\ncert_file = \"/nested/cert.pem\"\n\
                 key_file = \"/nested/key.pem\"\ntrusted_ca_file = \"/nested/ca.pem\"\n\
                 server_name = \"nested.example.com\"\n"
            ),
        ),
        (
            "nested-first/nested-camel",
            format!(
                "{HEADER}[web_server.tls]\ncertFile = \"/nested/cert.pem\"\n\
                 keyFile = \"/nested/key.pem\"\ntrustedCaFile = \"/nested/ca.pem\"\n\
                 serverName = \"nested.example.com\"\n\
                 [web_server]\naddr = \"127.0.0.1\"\nport = 7500\n\
                 tls_cert_file = \"/flat/cert.pem\"\ntls_key_file = \"/flat/key.pem\"\n\
                 tls_ca_file = \"/flat/ca.pem\"\ntls_server_name = \"flat.example.com\"\n"
            ),
        ),
        (
            "nested-first/nested-snake",
            format!(
                "{HEADER}[web_server.tls]\ncert_file = \"/nested/cert.pem\"\n\
                 key_file = \"/nested/key.pem\"\ntrusted_ca_file = \"/nested/ca.pem\"\n\
                 server_name = \"nested.example.com\"\n\
                 [web_server]\naddr = \"127.0.0.1\"\nport = 7500\n\
                 tls_cert_file = \"/flat/cert.pem\"\ntls_key_file = \"/flat/key.pem\"\n\
                 tls_ca_file = \"/flat/ca.pem\"\ntls_server_name = \"flat.example.com\"\n"
            ),
        ),
    ];
    for (name, body) in both_set {
        let (loose, strict) = load_both_modes(&body);
        for (mode, got) in [("strict=false", loose), ("strict=true", strict)] {
            assert_eq!(
                got,
                expect(
                    "/nested/cert.pem",
                    "/nested/key.pem",
                    "/nested/ca.pem",
                    "nested.example.com"
                ),
                "{name}, {mode}: the nested section's values take precedence over \
                 the flat key that is already set — a restart cannot reorder them",
            );
        }
    }

    // ── 4. A flat-only config is untouched (control) ───────────────────────
    let flat_only = format!(
        "{HEADER}[web_server]\naddr = \"127.0.0.1\"\nport = 7500\n\
         tls_cert_file = \"/flat/cert.pem\"\ntls_key_file = \"/flat/key.pem\"\n\
         tls_ca_file = \"/flat/ca.pem\"\ntls_server_name = \"flat.example.com\"\n",
    );
    let (loose, strict) = load_both_modes(&flat_only);
    for (mode, got) in [("strict=false", loose), ("strict=true", strict)] {
        assert_eq!(
            got,
            expect(
                "/flat/cert.pem",
                "/flat/key.pem",
                "/flat/ca.pem",
                "flat.example.com"
            ),
            "flat-only, {mode}",
        );
    }
}

/// `[webServer]` and `[web_server]` are the **same section**, merged per key,
/// with `[web_server]` (the snake_case spelling) winning every key both define.
///
/// The all-or-nothing `table.entry("web_server").or_insert(v)` this replaces
/// discarded the camelCase table **whole** — so a nested `[webServer.tls]`
/// never reached the hoist, and a file that wrote the nested section beside a
/// flat key in the other spelling silently got the *flat* value: the one shape
/// in which the documented "the nested values take precedence" claim was false.
/// Measured before this change in both loader modes (probe
/// probe cases A1–A6, transcript `/tmp/ws-probe-before.txt`): `tls_cert()` was
/// `/flat`, and
/// distinct keys written only in `[webServer]` (`user`, `port`) vanished.
///
/// The merge preserves the **old winner** rather than inverting it: for a key
/// both sections define, `[web_server]` wins — the order the flatten resolved
/// in. Nested tables merge recursively the same way.
///
/// **What this models.** Both loader modes on a real file, for: the nested-tls
/// shape (A1), disjoint flat keys (A2), a key both sections define (A3), a
/// camelCase alias against the snake canonical (A4 — which a naive merge turns
/// into a serde `duplicate field`, so this is the row the canonicalization in
/// `normalize_web_server_section` exists for), two `tls` tables with disjoint
/// keys (A5), YAML with both spellings, and the client admin section.
///
/// **What it does not cover.** A present-but-not-a-table `web_server` (e.g.
/// `web_server = 1`): the merge keeps the old drop-camelCase-whole behaviour
/// there, mirrored by `ConfigPresence::web_server_tls_enable_set_in`, and it is
/// not a shape any real config has. The `[common]` flatten is **not** part of
/// this merge — it is still `or_insert` on the whole value, so a top-level
/// `web_server` drops `[common] web_server` whole (pinned in
/// `frp-core/tests/web_server_tls_enable_warning.rs`).
#[test]
fn both_web_server_sections_merge_per_key_in_both_modes() {
    /// Write `body` as `frps.toml` and return
    /// `(cert, key, ca, server_name, user, password, port)` in both modes.
    fn load_both(body: &str) -> Vec<(String, String, String, String, String, String, u16)> {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("frps.toml");
        std::fs::write(&path, body).unwrap();
        let p = path.to_str().unwrap();
        [false, true]
            .into_iter()
            .map(|strict| {
                let cfg = load_server_config(p, strict)
                    .unwrap_or_else(|e| panic!("strict={strict} must load:\n{e}"));
                let ws = cfg.web_server;
                (
                    ws.tls_cert().to_string(),
                    ws.tls_key().to_string(),
                    ws.tls_ca_file.clone(),
                    ws.tls_server_name.clone(),
                    ws.user.clone(),
                    ws.password.clone(),
                    ws.port,
                )
            })
            .collect()
    }

    // A1: the nested camelCase table is reachable and wins over a flat snake key.
    for (cert, key, ca, sn, user, pwd, port) in load_both(
        "bind_port = 7000\ntoken = \"t\"\n[webServer.tls]\ncert_file = \"/nested/cert.pem\"\n\
         [web_server]\nport = 7500\ntls_cert_file = \"/flat/cert.pem\"\n",
    ) {
        assert_eq!(cert, "/nested/cert.pem", "A1: nested wins");
        assert_eq!((key.as_str(), ca.as_str(), sn.as_str()), ("", "", ""));
        assert_eq!((user.as_str(), pwd.as_str(), port), ("", "", 7500));
    }

    // A2: disjoint flat keys from both sections all survive.
    for (_, _, _, _, user, pwd, port) in load_both(
        "bind_port = 7000\ntoken = \"t\"\n[webServer]\nuser = \"camel\"\nport = 7501\n\
         [web_server]\npassword = \"snake\"\n",
    ) {
        assert_eq!(user, "camel", "A2: the camelCase table is not discarded");
        assert_eq!(pwd, "snake");
        assert_eq!(port, 7501);
    }

    // A3: a key both sections define -> snake wins (the old flatten order).
    for (_, _, _, _, user, _, _) in load_both(
        "bind_port = 7000\ntoken = \"t\"\n[webServer]\nuser = \"camel\"\n\
         [web_server]\nuser = \"snake\"\n",
    ) {
        assert_eq!(user, "snake", "A3: the order is not inverted");
    }

    // A4: camelCase alias in `[webServer]` beside the snake canonical in
    // `[web_server]` — one field, two names, and a naive merge would make serde
    // report `duplicate field \`tls_cert_file\``. The canonical wins.
    for (cert, _, _, _, _, _, _) in load_both(
        "bind_port = 7000\ntoken = \"t\"\n[webServer]\ncertFile = \"/camel/cert.pem\"\n\
         [web_server]\ntls_cert_file = \"/snake/cert.pem\"\n",
    ) {
        assert_eq!(cert, "/snake/cert.pem", "A4: canonical wins, no duplicate");
    }

    // A5: two `tls` tables with disjoint keys both survive.
    for (cert, key, _, _, _, _, _) in load_both(
        "bind_port = 7000\ntoken = \"t\"\n[webServer.tls]\ncertFile = \"/camel/cert.pem\"\n\
         [web_server.tls]\nkey_file = \"/snake/key.pem\"\n",
    ) {
        assert_eq!(cert, "/camel/cert.pem", "A5: camel tls key survives");
        assert_eq!(key, "/snake/key.pem");
    }

    // Same shape in YAML, where the two spellings are sibling keys of one map.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("frps.yaml");
    std::fs::write(
        &path,
        "bind_port: 7000\ntoken: \"t\"\nwebServer:\n  tls:\n    cert_file: \"/nested/cert.pem\"\n\
         web_server:\n  port: 7500\n  tls_cert_file: \"/flat/cert.pem\"\n",
    )
    .unwrap();
    for strict in [false, true] {
        let cfg = load_server_config(path.to_str().unwrap(), strict).unwrap();
        assert_eq!(
            cfg.web_server.tls_cert(),
            "/nested/cert.pem",
            "YAML, strict={strict}"
        );
    }

    // Client admin section: same normalizer, same merge.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("frpc.toml");
    std::fs::write(
        &path,
        "server_addr = \"127.0.0.1\"\nserver_port = 7000\ntoken = \"t\"\n\
         [webServer.tls]\ncert_file = \"/nested/cert.pem\"\n\
         [web_server]\nport = 7400\ntls_cert_file = \"/flat/cert.pem\"\n",
    )
    .unwrap();
    for strict in [false, true] {
        let cfg = load_client_config(path.to_str().unwrap(), strict).unwrap();
        assert_eq!(
            cfg.web_server.tls_cert(),
            "/nested/cert.pem",
            "client, strict={strict}"
        );
    }
}

/// A dotted `.ini` section header whose first segment is a v1 section name
/// becomes a **nested table**, so `.ini` reaches the same normalizers as every
/// other format — and a legacy `[plugin.NAME]` header (or any other non-v1
/// first segment) stays a flat section name.
///
/// Before this, `[webServer.tls]` / `[web_server.tls]` were stored verbatim as
/// the top-level key `webServer.tls` / `web_server.tls`: non-strict dropped the
/// whole section and strict reported `unknown field "webServer.tls"` (measured
/// in both modes, probe case B1/B2). The neighbouring shapes worked, which is
/// the trap the item names: `[webServer] certFile = …` and the legacy
/// `dashboard_tls_cert_file` both load.
///
/// The first-segment restriction is what keeps Go's legacy sections working:
/// Go's `.ini` path is the legacy loader (`pkg/config/legacy/server.go`), which
/// reads `[common]` and the flat `plugin.NAME` sections from `gopkg.in/ini.v1`
/// — `section.Name()` is the raw `plugin.user-manager`, matched with
/// `strings.HasPrefix(name, "plugin.")` — and frp-rs mirrors that in
/// `collect_legacy_ini_proxy_sections` / the `plugin.` fold. Expanding every
/// dotted header broke the shipped Go fixture (measured: `unknown field
/// "plugin"` in strict mode), which is why the restriction exists.
///
/// **What this models.** Both loader modes on real `.ini` files: the two
/// spellings, the nested-wins precedence, the legacy `plugin.` boundary, a
/// literal top-level `webServer.tls` key (which must stay a distinct unknown
/// key, not collide with the expanded table), and a genuine path conflict
/// (`[webServer] tls = 1` beside `[webServer.tls]`), which is reported rather
/// than clobbered.
///
/// **What it does not cover.** Quoting (`[a."b.c"]`), which is out of scope and
/// keeps its header verbatim; `[a..b]`; and Go parity for the expansion itself —
/// Go never reads `[webServer.tls]` in an `.ini` at all (its legacy loader
/// ignores the section), so this is an frp-rs extension that makes `.ini` a
/// first-class spelling of the v1 config, not a parity fix.
#[test]
fn dotted_ini_section_headers_become_nested_tables_in_both_modes() {
    fn load_ini_both(body: &str) -> Vec<(String, String)> {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("frps.ini");
        std::fs::write(&path, body).unwrap();
        let p = path.to_str().unwrap();
        [false, true]
            .into_iter()
            .map(|strict| {
                let cfg = load_server_config(p, strict).unwrap_or_else(|e| {
                    panic!("strict={strict} must load:\n{e}");
                });
                (
                    cfg.web_server.tls_cert().to_string(),
                    cfg.web_server.tls_key().to_string(),
                )
            })
            .collect()
    }

    // The Go-style spelling, with the values under the nested section.
    for (cert, key) in load_ini_both(
        "[common]\nbind_port = 7000\n[webServer]\nport = 7500\n\
         [webServer.tls]\ncertFile = /nested/cert.pem\nkeyFile = /nested/key.pem\n",
    ) {
        assert_eq!(cert, "/nested/cert.pem");
        assert_eq!(key, "/nested/key.pem");
    }

    // The snake_case spelling.
    for (cert, _) in load_ini_both(
        "[common]\nbind_port = 7000\n[web_server]\nport = 7500\n\
         [web_server.tls]\ncert_file = /snake/cert.pem\n",
    ) {
        assert_eq!(cert, "/snake/cert.pem");
    }

    // Nested wins over a flat key in the same section, as in every other format.
    for (cert, _) in load_ini_both(
        "[common]\nbind_port = 7000\n[webServer]\nport = 7500\ncertFile = /flat/cert.pem\n\
         [webServer.tls]\ncertFile = /nested/cert.pem\n",
    ) {
        assert_eq!(cert, "/nested/cert.pem");
    }

    // The legacy boundary: `[plugin.NAME]` is not a v1 section root, so it is
    // NOT split — the plugin still lands in `http_plugins` (whose strict walk
    // needs the flat key).
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("frps.ini");
    std::fs::write(
        &path,
        "[common]\nbind_port = 7000\n[plugin.user-manager]\naddr = 127.0.0.1:9000\n\
         path = /handler\nops = login\ntlsVerify = true\n",
    )
    .unwrap();
    for strict in [false, true] {
        let cfg = load_server_config(path.to_str().unwrap(), strict)
            .unwrap_or_else(|e| panic!("legacy plugin section, strict={strict}: {e}"));
        assert_eq!(cfg.http_plugins.len(), 1, "strict={strict}");
        assert_eq!(cfg.http_plugins[0].name, "user-manager", "strict={strict}");
        assert_eq!(cfg.http_plugins[0].addr, "127.0.0.1:9000");
    }

    // A literal top-level key named `webServer.tls` is a *different* key from the
    // expanded table, so it must not be swallowed by it: it stays an unknown
    // field for strict mode to report.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("frps.ini");
    std::fs::write(
        &path,
        "webServer.tls = 1\n[common]\nbind_port = 7000\n[webServer]\nport = 7500\n",
    )
    .unwrap();
    let err = format!(
        "{}",
        load_server_config(path.to_str().unwrap(), true).unwrap_err()
    );
    assert!(
        err.contains("unknown field \"webServer.tls\""),
        "the literal key is still reported: {err}"
    );
    load_server_config(path.to_str().unwrap(), false).unwrap();

    // A conflict — a scalar where the expanded path needs a table — is reported
    // when the containing section comes **first** (the item's "must not collide"
    // clause) …
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("frps.ini");
    std::fs::write(
        &path,
        "[common]\nbind_port = 7000\n[webServer]\nport = 7500\ntls = 1\n\
         [webServer.tls]\ncertFile = /nested/cert.pem\n",
    )
    .unwrap();
    for strict in [false, true] {
        let err = format!(
            "{}",
            load_server_config(path.to_str().unwrap(), strict).unwrap_err()
        );
        assert!(
            err.contains("conflicts with the value already set at `webServer.tls`"),
            "strict={strict}: got {err}"
        );
    }

    // … and the reverse order is pinned too, because it does **not** error: the
    // expansion builds the table first and the later verbatim `[webServer]`
    // section merges `tls = 1` into it, overwriting the table. The file loads in
    // both modes with the nested values gone (`tls_cert() == ""`). The asymmetry
    // is stated in `insert_ini_section`'s doc and in `CHANGELOG.md`; pinning it
    // here is what keeps the "reported instead of silently clobbered" sentence
    // from quietly becoming false again.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("frps.ini");
    std::fs::write(
        &path,
        "[common]\nbind_port = 7000\n[webServer.tls]\ncertFile = /nested/cert.pem\n\
         [webServer]\nport = 7500\ntls = 1\n",
    )
    .unwrap();
    for strict in [false, true] {
        let cfg = load_server_config(path.to_str().unwrap(), strict)
            .unwrap_or_else(|e| panic!("reverse order must load, strict={strict}: {e}"));
        assert_eq!(
            cfg.web_server.tls_cert(),
            "",
            "strict={strict}: the later scalar `tls` overwrites the expanded table"
        );
        assert_eq!(cfg.web_server.port, 7500, "strict={strict}");
    }
}

/// The **other** direction of the `.ini` dotted-header rule: a section whose
/// name merely *looks* like a v1 path but is a legacy **proxy name** stays a
/// proxy.
///
/// In the legacy INI dialect every section other than `[common]` is a proxy, and
/// `collect_legacy_ini_proxy_sections` decides membership by the section's own
/// `type` key — or, since the typeless-default fix, by a `local_port` /
/// `remote_port` pair, because Go defaults a missing proxy `type` to `tcp`. So
/// `[auth.foo]`, `[store.frontend]` and `[log.svc]` are proxies *named*
/// `auth.foo` / `store.frontend` / `log.svc`, not the `foo` / `frontend` / `svc`
/// children of an `auth` / `store` / `log` table — Go's legacy loader looks
/// sections up by their raw name too (`pkg/config/legacy/server.go`,
/// `section.Name()`). The first cut of the dotted-header expansion split them on
/// the first segment alone and the proxies **silently disappeared** (measured on
/// the real binaries: base and Go v0.71.0 register them, `proxy added:
/// [auth.foo]`; the frozen tree registered nothing), which is the silent drop
/// item B's Done-when forbids. `ini_section_path` therefore holds a section back
/// when it carries `type` or a proxy port.
///
/// **What this models.** Both loader modes on a real `.ini`, for the three
/// v1-first-segment names the reviewers probed plus a non-v1 control
/// (`[my.proxy]`), each with an explicit `type = tcp`, asserting the proxy's
/// `type` / `local_port` / `remote_port` survive; then the expansion direction in
/// the same file family, so one test pins both. The typeless half of the
/// dialect is pinned separately by
/// `typeless_ini_proxy_section_defaults_to_tcp_in_both_modes`.
///
/// **What it does not cover.** A v1 nested table that itself carries a `type`
/// key (a `[visitors.plugin]`-style table in an `.ini`) is not merely "left
/// unexpanded": it stays a flat section, and on the client the legacy collector
/// then reads it as a proxy named after the header and proxy validation refuses
/// it (measured: `[visitors.plugin] type = "https2http"` → rc 1, `proxy
/// 'visitors.plugin': invalid proxy_type 'https2http'`; on the server it is an
/// unknown strict-mode field). That is the cost of the discriminator, it matches
/// the base tree (which never expanded anything), and it is stated in
/// `docs/config.md` and `ini_section_path`'s doc. It shares the port-based
/// discriminator documented there: a dotted v1 sub-table with neither `type` nor
/// a proxy port still expands, one with a port is a proxy.
#[test]
fn dotted_ini_headers_that_are_legacy_proxy_names_stay_proxies() {
    for name in ["auth.foo", "store.frontend", "log.svc", "my.proxy"] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("frpc.ini");
        std::fs::write(
            &path,
            format!(
                "server_addr = 127.0.0.1\nserver_port = 7000\ntoken = t\n\
                 [{name}]\ntype = tcp\nlocal_port = 8080\nremote_port = 9080\n"
            ),
        )
        .unwrap();
        for strict in [false, true] {
            let cfg = load_client_config(path.to_str().unwrap(), strict)
                .unwrap_or_else(|e| panic!("[{name}], strict={strict}: {e}"));
            let proxy = cfg
                .proxies
                .iter()
                .find(|p| p.name == name)
                .unwrap_or_else(|| {
                    panic!(
                    "[{name}], strict={strict}: the legacy proxy section must register; got {:?}",
                    cfg.proxies.iter().map(|p| p.name.clone()).collect::<Vec<_>>()
                )
                });
            assert_eq!(proxy.proxy_type, "tcp", "[{name}], strict={strict}");
            assert_eq!(proxy.local_port, 8080, "[{name}], strict={strict}");
            assert_eq!(proxy.remote_port, 9080, "[{name}], strict={strict}");
        }
    }

    // …and the v1 direction still expands: a portless `[webServer.tls]` reaches
    // the hoist, and a portless `[auth.*]` sub-table is still a nested table
    // (the port-key discriminator only fires on a proxy's own section).
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("frps.ini");
    std::fs::write(
        &path,
        "[common]\nbind_port = 7000\n[webServer]\nport = 7500\n\
         [webServer.tls]\ncertFile = /nested/cert.pem\n",
    )
    .unwrap();
    for strict in [false, true] {
        let cfg = load_server_config(path.to_str().unwrap(), strict).unwrap();
        assert_eq!(
            cfg.web_server.tls_cert(),
            "/nested/cert.pem",
            "strict={strict}"
        );
    }
}

/// A `type`-less **camelCase** `[webServer]` in a client `.ini` is frpc's admin
/// block, not a phantom legacy proxy.
///
/// `collect_legacy_ini_proxy_sections` also collects a `type`-less section in
/// the `.ini` dialect (Go's legacy default: the section is a `tcp` proxy — see
/// `typeless_ini_proxy_section_defaults_to_tcp_in_both_modes`). Its
/// known-section filter listed only the snake_case spelling of each v1 root, so
/// while `[web_server]` was safe, a typeless `[webServer]` was stolen **before**
/// `merge_section_into(table, "webServer", "web_server")` could run. Measured on
/// the commit that added the typeless rule: a client `.ini` with
/// `[webServer] port = 7500` loaded with `Proxies: 1` and `web_server.port == 0`
/// (base `b8e1dd6d`: `Proxies: 0`, port 7500), and `[webServer]
/// zzz_unknown_key = 1` passed strict mode — a collected legacy section is
/// strict-exempt — where base reported `unknown field
/// "web_server.zzz_unknown_key"`. The fix narrows the typeless rule to a
/// section that names a port (`local_port`/`remote_port`) — the same
/// discriminator `format.rs`'s nest gate uses, and a key no admin block
/// carries. The first cut instead listed the camelCase aliases (`webServer`,
/// `httpPlugins`, `sshTunnelGateway`) in the known-section set, which traded
/// this bug for its mirror image: a *typed* `[webServer]` proxy was dropped
/// (base971 and the final rule both give `Proxies: 1`).
///
/// **What this models.** Both loader modes on a real client `.ini`, for the flat
/// `[webServer]`, the nested `[webServer.tls]`, the nested-under-`[common]`
/// `[common.webServer.tls]`, and the documented `[webServer]` + `[web_server]`
/// per-key merge; plus that an unknown key under `[webServer]` is ignored in
/// **both** loader modes (Go's INI reader ignores section keys, item 1 of the
/// legacy-dialect parity work).
///
/// **What it does not cover.** The server path never runs the collector, so it
/// was never affected (frps `[webServer]` / `[webServer.tls]` is pinned in
/// `dotted_ini_headers_that_are_legacy_proxy_names_stay_proxies`); a typeless
/// section with no port key at all is pinned in
/// `typeless_ini_section_without_ports_stays_a_v1_section`; and the
/// mirror-image row — a camelCase root that *does* carry `type` — is pinned in
/// `typed_camelcase_v1_root_headers_are_still_legacy_proxies`. The
/// `[common.webServer.tls]` row is written **alone**:
/// a top-level `[webServer]` beside it drops the `[common]` table whole, the
/// pre-existing `or_insert` flatten of `[common]` pinned in
/// `both_web_server_sections_merge_per_key_in_both_modes`, not this collector.
#[test]
fn typeless_camelcase_web_server_ini_is_not_a_phantom_proxy() {
    fn write(body: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("frpc.ini");
        std::fs::write(&path, body).unwrap();
        (dir, path)
    }
    const HEAD: &str = "[common]\nserver_addr = 127.0.0.1\nserver_port = 7000\n";

    // The flat camelCase admin block: loaded, and not taken as a proxy.
    let (_d, p) = write(&format!("{HEAD}[webServer]\nport = 7500\n"));
    for strict in [false, true] {
        let cfg = load_client_config(p.to_str().unwrap(), strict)
            .unwrap_or_else(|e| panic!("[webServer] strict={strict}: {e}"));
        assert_eq!(cfg.web_server.port, 7500, "strict={strict}");
        assert!(
            cfg.proxies.is_empty(),
            "[webServer] must not become a proxy, strict={strict}; got {:?}",
            cfg.proxies
                .iter()
                .map(|p| p.name.clone())
                .collect::<Vec<_>>()
        );
    }

    // The nested camelCase TLS table, on its own and under `[common]`.
    for (label, body) in [
        (
            "[webServer.tls]",
            format!(
                "{HEAD}[webServer]\nport = 7500\n[webServer.tls]\n\
                 certFile = /nested/cert.pem\nkeyFile = /nested/key.pem\n"
            ),
        ),
        (
            "[common.webServer.tls]",
            format!(
                "{HEAD}[common.webServer]\nport = 7500\n[common.webServer.tls]\n\
                 certFile = /nested/cert.pem\nkeyFile = /nested/key.pem\n"
            ),
        ),
    ] {
        let (_d, p) = write(&body);
        for strict in [false, true] {
            let cfg = load_client_config(p.to_str().unwrap(), strict)
                .unwrap_or_else(|e| panic!("{label} strict={strict}: {e}"));
            assert_eq!(cfg.web_server.port, 7500, "{label} strict={strict}");
            assert_eq!(
                cfg.web_server.tls_cert(),
                "/nested/cert.pem",
                "{label} strict={strict}"
            );
            assert_eq!(
                cfg.web_server.tls_key(),
                "/nested/key.pem",
                "{label} strict={strict}"
            );
            assert!(cfg.proxies.is_empty(), "{label} strict={strict}");
        }
    }

    // The documented per-key merge: `[web_server]` (snake) wins every key both
    // sections define, and the camelCase table is not stolen first.
    let (_d, p) = write(&format!(
        "{HEAD}[webServer]\nuser = camel\nport = 7500\n\
         [web_server]\npassword = snake\nport = 7501\n"
    ));
    for strict in [false, true] {
        let cfg = load_client_config(p.to_str().unwrap(), strict)
            .unwrap_or_else(|e| panic!("merge strict={strict}: {e}"));
        assert_eq!(cfg.web_server.user, "camel", "strict={strict}");
        assert_eq!(cfg.web_server.password, "snake", "strict={strict}");
        assert_eq!(
            cfg.web_server.port, 7501,
            "the snake spelling wins; strict={strict}"
        );
        assert!(cfg.proxies.is_empty(), "merge strict={strict}");
    }

    // A key the admin block does not name is *ignored* in both modes, exactly as
    // Go's legacy INI reader ignores it (item 1 of the legacy-dialect parity
    // work): the `.ini` dialect is exempt from the section-level strict check, so
    // `strict_config` cannot refuse a file Go loads. It must still not be taken
    // for a proxy.
    let (_d, p) = write(&format!("{HEAD}[webServer]\nzzz_unknown_key = 1\n"));
    for strict in [false, true] {
        let cfg = load_client_config(p.to_str().unwrap(), strict)
            .unwrap_or_else(|e| panic!("unknown section key strict={strict}: {e}"));
        assert!(
            cfg.proxies.is_empty(),
            "not a proxy, and the unknown key is dropped; strict={strict}"
        );
    }
}

/// A typeless legacy `.ini` proxy section is Go's `tcp` proxy, in **both** loader
/// modes, while a `role = "visitor"` section is not defaulted.
///
/// Go's legacy loader (`pkg/config/legacy/client.go`) treats every section other
/// than `[common]`/`range:*` as a proxy, and its proxy config defaults a missing
/// `type` to `tcp`. Measured on the real v0.71.0 binaries: `.ini` files whose
/// only section is a typeless `[myproxy]`, `[auth.foo]`, `[store.frontend]` or
/// `[my.proxy]` give `frpc verify` rc 0 (`frpc: the configuration file <f>
/// syntax is ok`) under both `--strict-config` values, and a real run logs `new
/// proxy [myproxy] type [tcp] success`; a typeless `role = "visitor"` section is
/// refused in both modes (`failed to parse visitor v1, err: type shouldn't be
/// empty`, rc 1). frp-rs required `type`: non-strict `frpc verify` returned rc 0
/// with `Proxies: 0` (the silent drop `TODO.md`'s item forbids) and strict mode
/// rc 1 `unknown field "myproxy" in config file …`.
///
/// **What this models.** Both loader modes on a real `.ini` for a flat name, a
/// v1-first-segment name, and a non-v1 dotted name, asserting the defaulted
/// `type` plus the surviving ports; then the visitor exclusion; then a portless
/// v1 dotted section (`[webServer.tls]`) still nesting on the server side.
///
/// **What it does not cover.** The typeless visitor **divergence** is pinned as
/// it is, not fixed: Go exits 1 in both modes where frp-rs non-strict loads the
/// file with nothing registered (rc 0). Defaulting a typeless visitor to a
/// proxy would invent a *new* divergence — Go never does — so the strict-mode
/// refusal is asserted and no `tcp` proxy may appear.
#[test]
fn typeless_ini_proxy_section_defaults_to_tcp_in_both_modes() {
    for name in ["myproxy", "auth.foo", "store.frontend", "my.proxy"] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("frpc.ini");
        std::fs::write(
            &path,
            format!(
                "[common]\nserver_addr = 127.0.0.1\nserver_port = 7000\n\
                 [{name}]\nlocal_port = 8080\nremote_port = 9080\n"
            ),
        )
        .unwrap();
        for strict in [false, true] {
            let cfg = load_client_config(path.to_str().unwrap(), strict)
                .unwrap_or_else(|e| panic!("[{name}], strict={strict}: {e}"));
            let proxy = cfg
                .proxies
                .iter()
                .find(|p| p.name == name)
                .unwrap_or_else(|| {
                    panic!(
                        "[{name}], strict={strict}: the typeless legacy proxy must register; got {:?}",
                        cfg.proxies
                            .iter()
                            .map(|p| p.name.clone())
                            .collect::<Vec<_>>()
                    )
                });
            assert_eq!(
                proxy.proxy_type, "tcp",
                "[{name}], strict={strict}: Go defaults the missing type to tcp"
            );
            assert_eq!(proxy.local_port, 8080, "[{name}], strict={strict}");
            assert_eq!(proxy.remote_port, 9080, "[{name}], strict={strict}");
        }
    }

    // Go refuses a typeless visitor in **both** modes, before it ever reads a
    // port, so nothing may be registered for it and the refusal must carry Go's
    // own wording (`failed to parse visitor v1, err: type shouldn't be empty`) —
    // not the v1 validator's `visitor 'v1': unknown visitor type ''`, which is
    // what a section that silently fell through to the v1 path would produce.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("visitor.ini");
    std::fs::write(
        &path,
        "[common]\nserver_addr = 127.0.0.1\nserver_port = 7000\n\
         [v1]\nrole = visitor\nserver_name = s1\nbind_addr = 127.0.0.1\nbind_port = 18100\n",
    )
    .unwrap();
    for strict in [false, true] {
        let err = format!(
            "{}",
            load_client_config(path.to_str().unwrap(), strict)
                .expect_err("a typeless visitor is refused in both modes")
        );
        assert!(
            err.contains("failed to parse visitor v1, err: type shouldn't be empty"),
            "strict={strict}: Go's typeless-visitor message; got {err}"
        );
    }

    // The port-key discriminator must not swallow the v1 nesting: a portless
    // dotted sub-table under a nested root still expands.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("frps.ini");
    std::fs::write(
        &path,
        "[common]\nbind_port = 7000\n[webServer]\nport = 7500\n\
         [webServer.tls]\ncertFile = /nested/cert.pem\n",
    )
    .unwrap();
    for strict in [false, true] {
        let cfg = load_server_config(path.to_str().unwrap(), strict).unwrap();
        assert_eq!(
            cfg.web_server.tls_cert(),
            "/nested/cert.pem",
            "strict={strict}"
        );
    }
}

/// A **typed** `.ini` section whose header is a camelCase v1 root name is still
/// Go's legacy proxy, named after the header.
///
/// Go's legacy loader looks sections up by raw name, so `[webServer]` is one
/// section there too, and frp-rs's known-section list holds only the snake_case
/// spellings — the camelCase ones are exactly the headers whose INI nesting
/// `ini_section_path` expands, so reserving them would drop the proxy.
/// Measured with the final rule, `frpc verify` on `[webServer] type = tcp` with
/// `local_port`/`remote_port`, `[httpPlugins] type = tcp ports = …` and
/// `[sshTunnelGateway] type = tcp ports = …`: rc 0 with `Proxies: 1` under both
/// `--strict-config` values, exactly as base971 (`971e0fa0`); the alias list the
/// first cut added made those same rows `Proxies: 0` (lenient) / rc 1 (strict).
///
/// **Mutation teeth.** Re-adding any of the three names to `KNOWN_SECTIONS`
/// fails the `find` below for that row; deleting the `if t.contains_key("type")`
/// clause fails the two `ports`-only rows, which carry no `local_port` /
/// `remote_port` to satisfy the typeless clause either.
#[test]
fn typed_camelcase_v1_root_headers_are_still_legacy_proxies() {
    for (name, body) in [
        (
            "webServer",
            "[webServer]\ntype = tcp\nlocal_port = 8080\nremote_port = 9080\n",
        ),
        (
            "httpPlugins",
            "[httpPlugins]\ntype = tcp\nports = 7000,7001\n",
        ),
        (
            "sshTunnelGateway",
            "[sshTunnelGateway]\ntype = tcp\nports = 7000,7001\n",
        ),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("frpc.ini");
        std::fs::write(
            &path,
            format!("[common]\nserver_addr = 127.0.0.1\nserver_port = 7000\n{body}"),
        )
        .unwrap();
        for strict in [false, true] {
            let cfg = load_client_config(path.to_str().unwrap(), strict)
                .unwrap_or_else(|e| panic!("[{name}], strict={strict}: {e}"));
            let proxy = cfg
                .proxies
                .iter()
                .find(|p| p.name == name)
                .unwrap_or_else(|| {
                    panic!(
                        "[{name}], strict={strict}: the typed legacy proxy must register; got {:?}",
                        cfg.proxies
                            .iter()
                            .map(|p| p.name.clone())
                            .collect::<Vec<_>>()
                    )
                });
            assert_eq!(
                proxy.proxy_type, "tcp",
                "[{name}], strict={strict}: the declared type must win"
            );
            if name == "webServer" {
                assert_eq!(proxy.local_port, 8080, "strict={strict}");
                assert_eq!(proxy.remote_port, 9080, "strict={strict}");
            }
        }
    }
}

/// A `type`-less `.ini` section that names **no** port stays a v1 section — the
/// deliberately narrow half of frp-rs's `.ini` proxy rule, pinned in both modes.
///
/// Go's legacy loader would make it a `tcp` proxy named after its header (with
/// port 0); frp-rs collects a typeless section only when it carries
/// `local_port`/`remote_port`, the discriminator that also keeps the typeless
/// `[webServer]` admin block out of the collector. Measured with the final rule
/// and on base971 (`971e0fa0`), `frpc verify` on `[myproxy] custom_domains =
/// a.com`: non-strict rc 0 with `Proxies: 0` (the table is dropped as an unknown
/// field), strict rc 1 `unknown field "myproxy" in config file …`.
///
/// **Mutation teeth.** Deleting the `local_port`/`remote_port` clause makes the
/// non-strict load register a phantom `tcp` proxy (the `is_empty` assert below
/// fails, as do all four shapes in
/// `typeless_camelcase_web_server_ini_is_not_a_phantom_proxy`) and lets this
/// strict mode load (the `unwrap_err` below fails).
#[test]
fn typeless_ini_section_without_ports_stays_a_v1_section() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("frpc.ini");
    std::fs::write(
        &path,
        "[common]\nserver_addr = 127.0.0.1\nserver_port = 7000\n\
         [myproxy]\ncustom_domains = a.com\n",
    )
    .unwrap();
    let lenient = load_client_config(path.to_str().unwrap(), false).unwrap();
    assert!(
        lenient.proxies.is_empty(),
        "a typeless, port-less section must not become a tcp proxy; got {:?}",
        lenient
            .proxies
            .iter()
            .map(|p| p.name.clone())
            .collect::<Vec<_>>()
    );
    let err = format!(
        "{}",
        load_client_config(path.to_str().unwrap(), true).unwrap_err()
    );
    assert!(
        err.contains("unknown field \"myproxy\""),
        "strict mode must still report the typeless, port-less section: {err}"
    );
}

/// A typeless `.ini` section that declares itself a **visitor** *and* names a
/// port is refused in **both** loader modes, with Go's own message — the
/// port-key discriminator must never turn it into a tcp proxy, and it must never
/// be dropped either.
///
/// The port-key discriminator alone cannot separate this shape from a typeless
/// proxy — `local_port`/`remote_port` are the very keys it tests for — so the
/// `role` clause is what keeps it out of `[proxies]`, and the visitor refusal in
/// `collect_legacy_ini_proxy_sections` is what replaces the silent drop that used
/// to happen when such a section was neither collected nor deserialized.
///
/// **Measured.** Go v0.71.0 refuses it in *both* loader modes (`failed to parse
/// visitor v, err: type shouldn't be empty` — `LoadAllProxyConfsFromIni`
/// dispatches on `role` before it reads a port, `pkg/config/legacy/client.go`).
/// Before this change frp-rs loaded rc 0 in non-strict mode with nothing
/// collected and refused in strict mode with `unknown field "v"`; both halves of
/// that were a different verdict from Go's.
///
/// **Mutation teeth.** Replacing the `role` clause with `true` collects the
/// section and routes it into `[visitors]` carrying an invented `type = "tcp"`,
/// so the load succeeds and the `expect_err` below fails; removing the
/// pre-collection visitor refusal restores the old silent drop, so the same
/// assertion fails with a loaded config instead of a refusal.
#[test]
fn typeless_port_carrying_ini_visitor_is_refused_with_go_message() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("frpc.ini");
    std::fs::write(
        &path,
        "[common]\nserver_addr = 127.0.0.1\nserver_port = 7000\n\
         [v]\nrole = \"visitor\"\nlocal_port = 1\nremote_port = 2\n",
    )
    .unwrap();

    for strict in [false, true] {
        let err = format!(
            "{}",
            load_client_config(path.to_str().unwrap(), strict)
                .expect_err("a typeless visitor is refused in both modes")
        );
        assert!(
            err.contains("failed to parse visitor v, err: type shouldn't be empty"),
            "strict={strict}: Go's typeless-visitor message; got {err}"
        );
    }
}

/// **Legacy-dialect parity, item 1.** An unknown key *inside* an `.ini` section is
/// accepted in **both** loader modes, because Go never applies `strict_config` to
/// the legacy dialect at all: `LoadClientConfigResult` (`pkg/config/load.go`)
/// branches on `DetectLegacyINIFormat` first and hands a legacy file to
/// `legacy.ParseClientConfig` / `legacy.UnmarshalServerConfFromIni`, whose
/// `gopkg.in/ini` reads ignore a key the typed struct does not name. Measured on
/// the real v0.71.0 binaries: `[common]` + `[webServer] zzz_unknown_key = 1` and
/// `[common]` + `[webServer.foo] bar = 1` give `frpc verify` rc 0 under both
/// `--strict-config` values (frps rc 0 for the server-side spelling); before this
/// change frp-rs was rc 1 in strict mode with `unknown field
/// "web_server.zzz_unknown_key"` / `unknown field "web_server.foo"`.
///
/// The exemption is **section-level and `.ini`-only**, which the two sibling
/// halves below pin:
///
/// * the same key in **TOML** is still refused in strict mode, exactly as Go's v1
///   decoder refuses it (`json: unknown field "web_server"`, rc 1);
/// * a **top-level** `.ini` key is still refused, because a DefaultSection key is
///   a v1 spelling (`webServer.tls = 1`) — pinned by
///   `dotted_ini_section_headers_become_nested_tables_in_both_modes`.
///
/// **Residual, measured and deliberately not fixed.** `[common]` is merged onto
/// the top level *before* the strict check, so an unknown key written there is
/// still reported by the top-level half (strict rc 1) where Go is rc 0. Closing
/// that means exempting the keys the `[common]` merge created, which would also
/// blind the top-level check to a genuine v1 typo spelled under `[common]`; the
/// item's Done-when allows the measurement instead, and the last block below is
/// that measurement.
#[test]
fn legacy_ini_section_keys_are_exempt_from_strict_only_in_ini() {
    let head = "[common]\nserver_addr = 127.0.0.1\nserver_port = 7000\n";

    // `.ini`: the unknown section key is ignored, in both modes, and the section
    // stays the settings table it looks like.
    let dir = tempfile::tempdir().unwrap();
    let ini = dir.path().join("frpc.ini");
    std::fs::write(&ini, format!("{head}[webServer]\nzzz_unknown_key = 1\n")).unwrap();
    for strict in [false, true] {
        let cfg = load_client_config(ini.to_str().unwrap(), strict)
            .unwrap_or_else(|e| panic!("unknown section key, strict={strict}: {e}"));
        assert!(cfg.proxies.is_empty(), "still not a proxy, strict={strict}");
    }

    // TOML: the identical key is a strict-mode unknown field — the v1 dialect
    // keeps the check Go's v1 decoder applies.
    let dir = tempfile::tempdir().unwrap();
    let toml_path = dir.path().join("frpc.toml");
    std::fs::write(
        &toml_path,
        "serverAddr = \"127.0.0.1\"\nserverPort = 7000\n[web_server]\nzzz_unknown_key = 1\n",
    )
    .unwrap();
    assert!(
        load_client_config(toml_path.to_str().unwrap(), false).is_ok(),
        "lenient TOML still loads"
    );
    let err = format!(
        "{}",
        load_client_config(toml_path.to_str().unwrap(), true).unwrap_err()
    );
    assert!(
        err.contains("unknown field \"web_server.zzz_unknown_key\""),
        "TOML must keep refusing it in strict mode: {err}"
    );

    // Residual: the `[common]` merge puts the key at the top level, where the
    // exemption does not reach. Go accepts this file (rc 0) in both modes.
    let dir = tempfile::tempdir().unwrap();
    let common = dir.path().join("frpc_common.ini");
    std::fs::write(
        &common,
        "[common]\nserver_addr = 127.0.0.1\nserver_port = 7000\nzzz_unknown_common = 1\n",
    )
    .unwrap();
    assert!(
        load_client_config(common.to_str().unwrap(), false).is_ok(),
        "lenient mode drops it"
    );
    let err = format!(
        "{}",
        load_client_config(common.to_str().unwrap(), true).unwrap_err()
    );
    assert!(
        err.contains("unknown field \"zzz_unknown_common\""),
        "residual: Go is rc 0 here, frp-rs reports the merged top-level key: {err}"
    );
}

/// **Legacy-dialect parity, item 2.** An **empty** `type` in an `.ini` section is
/// Go's `tcp`, exactly like a missing one.
///
/// `NewProxyConfFromIni` reads `section.Key("type").String()`
/// (`pkg/config/legacy/proxy.go:78`) and `ini.Key.String()` cannot tell an absent
/// key from an empty value, so `type = ""` falls into the same `== ""` branch.
/// Measured on the real v0.71.0 binaries: `[p] type = "" local_port = 8080
/// remote_port = 18080` gives `frpc verify` rc 0 in both modes with one proxy
/// registered; frp-rs was rc 1 in both modes with `proxy 'p': invalid proxy_type
/// ''`.
///
/// The empty-string default is **`.ini`-only**, and the TOML half below pins that
/// boundary: Go's v1 decoder still refuses an empty `type` (`decode proxy at
/// index 0: unknown proxy type: `, rc 1), and so does frp-rs.
#[test]
fn legacy_ini_empty_type_defaults_to_tcp_like_go() {
    let head = "[common]\nserver_addr = 127.0.0.1\nserver_port = 7000\n";

    let dir = tempfile::tempdir().unwrap();
    let ini = dir.path().join("frpc.ini");
    std::fs::write(
        &ini,
        format!("{head}[p]\ntype = \"\"\nlocal_port = 8080\nremote_port = 18080\n"),
    )
    .unwrap();
    for strict in [false, true] {
        let cfg = load_client_config(ini.to_str().unwrap(), strict)
            .unwrap_or_else(|e| panic!("empty type, strict={strict}: {e}"));
        let proxy = cfg
            .proxies
            .iter()
            .find(|p| p.name == "p")
            .unwrap_or_else(|| panic!("the section must register, strict={strict}"));
        assert_eq!(proxy.proxy_type, "tcp", "strict={strict}");
        assert_eq!(proxy.local_port, 8080, "strict={strict}");
        assert_eq!(proxy.remote_port, 18080, "strict={strict}");
    }

    // The v1 dialect keeps the refusal: an empty type is not a `tcp` default there.
    let dir = tempfile::tempdir().unwrap();
    let toml_path = dir.path().join("frpc.toml");
    std::fs::write(
        &toml_path,
        "serverAddr = \"127.0.0.1\"\nserverPort = 7000\n[[proxies]]\nname = \"p\"\n\
         type = \"\"\nlocalPort = 8080\nremotePort = 18080\n",
    )
    .unwrap();
    for strict in [false, true] {
        let err = format!(
            "{}",
            load_client_config(toml_path.to_str().unwrap(), strict)
                .expect_err("TOML keeps refusing an empty type")
        );
        assert!(
            err.contains("invalid proxy_type ''"),
            "strict={strict}: the v1 refusal; got {err}"
        );
    }
}

/// **Legacy-dialect parity, items 4 and 5.** An `.ini` section whose **header**
/// names a v1 root is the legacy section Go reads under that raw name, not the
/// root it looks like — for the reserved settings roots (`web_server`,
/// `transport`) when the section carries a proxy port, and for the v1 **array**
/// roots (`proxies`, `visitors`) always.
///
/// Go's legacy loader has no reserved-name list at all: `LoadAllProxyConfsFromIni`
/// skips only the default section, `common` and `range:*`, and uses
/// `section.Name()` as the proxy name, while `ini.v1` never expands a dotted
/// header — so `[web_server]` with ports, `[transport]` with a port and
/// `[visitors.foo]`/`[proxies.foo]` are each one proxy named after the header
/// (`pkg/config/legacy/client.go:204`). Measured on the real v0.71.0 binaries: all
/// of these give `frpc verify` rc 0 in both modes. Before this change frp-rs
/// dropped the proxy in lenient mode (`Proxies: 0`) and refused the file in strict
/// mode (`unknown field "web_server.local_port"`), while the dotted array-root
/// spellings failed in **both** modes with `invalid type: map, expected a
/// sequence` — the header had been expanded into a v1 sub-table, so the collector
/// never saw a section to collect.
///
/// The reserved-root bypass keys on the **port** keys, never on `type`:
/// `[log] type = "custom"` must stay a settings table, and a portless
/// `[web_server] port = 7500` must stay the admin block (pinned by
/// `typeless_camelcase_web_server_ini_is_not_a_phantom_proxy`).
#[test]
fn legacy_ini_headers_naming_v1_roots_are_still_proxies() {
    let head = "[common]\nserver_addr = 127.0.0.1\nserver_port = 7000\n";
    let cases: &[(&str, &str, &str)] = &[
        (
            "reserved settings root with type and ports",
            "[web_server]\ntype = \"tcp\"\nlocal_port = 8080\nremote_port = 18080\n",
            "web_server",
        ),
        (
            "reserved settings root with a port only",
            "[transport]\nlocal_port = 8080\n",
            "transport",
        ),
        (
            "dotted v1 array root, no port",
            "[visitors.foo]\nserver_name = s\n",
            "visitors.foo",
        ),
        (
            "dotted v1 array root, empty",
            "[proxies.foo]\n",
            "proxies.foo",
        ),
        ("bare v1 array root", "[visitors]\n", "visitors"),
        (
            "dotted v1 array root with a type",
            "[proxies.foo]\ntype = \"tcp\"\nlocal_port = 8081\nremote_port = 18081\n",
            "proxies.foo",
        ),
    ];
    for (label, body, want_name) in cases {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("frpc.ini");
        std::fs::write(&path, format!("{head}{body}")).unwrap();
        for strict in [false, true] {
            let cfg = load_client_config(path.to_str().unwrap(), strict)
                .unwrap_or_else(|e| panic!("{label}, strict={strict}: {e}"));
            let names: Vec<&str> = cfg.proxies.iter().map(|p| p.name.as_str()).collect();
            assert_eq!(
                names,
                vec![*want_name],
                "{label}, strict={strict}: Go registers one proxy named after the header"
            );
            assert_eq!(cfg.proxies[0].proxy_type, "tcp", "{label}, strict={strict}");
            assert!(
                cfg.visitors.is_empty(),
                "{label}, strict={strict}: an INI header cannot build a v1 visitor"
            );
        }
    }
}

/// **Legacy-dialect parity, typeless visitor at any depth.** A
/// `role = "visitor"` `.ini` section with a missing or empty `type` is refused in
/// **both** loader modes with Go's message, whatever its header names and
/// wherever that header puts it.
///
/// Go dispatches on `role` *before* it looks at the header
/// (`LoadAllProxyConfsFromIni`, `pkg/config/legacy/client.go:204`) and iterates
/// `f.Sections()`, which `gopkg.in/ini.v1` never expands: `[auth.foo]` is one
/// section literally named `auth.foo` and `[v]` is one named `v`. frp-rs
/// *expands* a dotted header under an `INI_NESTED_SECTION_ROOTS` entry into a v1
/// sub-table, so the pre-collection refusal has to walk the expanded tree to see
/// the same section. Iterating the top level only missed `[auth.foo] role =
/// "visitor" server_name = s` and let it load (rc 0 in both modes, `Proxies: 0`)
/// where Go v0.71.0 is rc 1 in both modes with `failed to parse visitor
/// auth.foo, err: type shouldn't be empty`; the portless `[v]` spelling was the
/// same silent drop in lenient mode.
#[test]
fn legacy_ini_typeless_visitor_is_refused_at_any_depth() {
    let head = "[common]\nserver_addr = 127.0.0.1\nserver_port = 7000\n";
    let cases: &[(&str, &str, &str)] = &[
        (
            "portless top level",
            "[v]\nrole = \"visitor\"\nserver_name = s\n",
            "v",
        ),
        (
            "port-carrying top level",
            "[v]\nrole = \"visitor\"\nlocal_port = 1\nremote_port = 2\n",
            "v",
        ),
        (
            "dotted settings root",
            "[auth.foo]\nrole = \"visitor\"\nserver_name = s\n",
            "auth.foo",
        ),
        (
            "dotted camelCase settings root",
            "[webServer.foo]\nrole = \"visitor\"\nserver_name = s\n",
            "webServer.foo",
        ),
        (
            "dotted store root",
            "[store.frontend]\nrole = \"visitor\"\nserver_name = s\n",
            "store.frontend",
        ),
        (
            "port-carrying reserved root",
            "[transport]\nlocal_port = 8080\nrole = \"visitor\"\n",
            "transport",
        ),
        (
            "port-carrying camelCase reserved root",
            "[webServer]\nlocal_port = 8080\nrole = \"visitor\"\n",
            "webServer",
        ),
    ];
    for (label, body, want_name) in cases {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("frpc.ini");
        std::fs::write(&path, format!("{head}{body}")).unwrap();
        for strict in [false, true] {
            let err = format!(
                "{}",
                load_client_config(path.to_str().unwrap(), strict)
                    .expect_err("a typeless visitor is refused in both modes, at any depth")
            );
            assert!(
                err.contains(&format!(
                    "failed to parse visitor {want_name}, err: type shouldn't be empty"
                )),
                "{label}, strict={strict}: Go's refusal under the raw header name; got {err}"
            );
        }
    }
}

/// **Legacy-dialect parity, typed visitor naming a reserved settings root.** A
/// typed `role = "visitor"` section is a **visitor** even when its header names a
/// v1 settings root or carries proxy port keys — `role` is authoritative in Go,
/// where it is read before the header.
///
/// Measured on Go v0.71.0, rc 1 in both loader modes: `[web_server] type = "stcp"
/// local_port = 8080 role = "visitor" server_name = s` → `visitor web_server:
/// bind port is required`, and `[auth] remote_port = 7500 role = "visitor" type =
/// "stcp" server_name = s` → `visitor auth: bind port is required`. The untyped
/// spelling of both was already refused with Go's `type shouldn't be empty`; the
/// typed one was dropped in lenient mode (`Proxies: 0`, `Visitors: 0`) and, for
/// the reserved-root spelling, accepted in strict mode too, where origin/main had
/// refused it with `unknown field "web_server.local_port"`. Adding a bind port
/// must still register the visitor, so the section is genuinely collected rather
/// than rejected for an unrelated reason.
#[test]
fn legacy_ini_typed_reserved_root_visitor_is_refused_like_go() {
    let head = "[common]\nserver_addr = 127.0.0.1\nserver_port = 7000\n";
    let cases: &[(&str, &str, &str)] = &[
        (
            "reserved root, type and ports",
            "[web_server]\ntype = \"stcp\"\nlocal_port = 8080\nrole = \"visitor\"\nserver_name = s\n",
            "visitor web_server: bind port is required",
        ),
        (
            "reserved root, port only",
            "[auth]\nremote_port = 7500\nrole = \"visitor\"\ntype = \"stcp\"\nserver_name = s\n",
            "visitor auth: bind port is required",
        ),
        (
            "reserved root, no port at all",
            "[log]\ntype = \"stcp\"\nrole = \"visitor\"\nserver_name = s\n",
            "visitor log: bind port is required",
        ),
    ];
    for (label, body, want) in cases {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("frpc.ini");
        std::fs::write(&path, format!("{head}{body}")).unwrap();
        for strict in [false, true] {
            let err = format!(
                "{}",
                load_client_config(path.to_str().unwrap(), strict)
                    .expect_err("the missing bind port is refused in both modes")
            );
            assert!(
                err.contains(want),
                "{label}, strict={strict}: Go's visitor validation message; got {err}"
            );
        }
    }

    // The same shape with a bind port is the visitor it says it is.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("frpc.ini");
    std::fs::write(
        &path,
        format!(
            "{head}[web_server]\ntype = \"stcp\"\nlocal_port = 8080\nrole = \"visitor\"\n\
             bind_port = 19000\nserver_name = s\n"
        ),
    )
    .unwrap();
    for strict in [false, true] {
        let cfg = load_client_config(path.to_str().unwrap(), strict).unwrap_or_else(|e| {
            panic!("a reserved-root visitor with a port, strict={strict}: {e}")
        });
        assert!(cfg.proxies.is_empty(), "strict={strict}: not a proxy");
        assert_eq!(cfg.visitors.len(), 1, "strict={strict}");
        assert_eq!(cfg.visitors[0].name, "web_server", "strict={strict}");
        assert_eq!(cfg.visitors[0].visitor_type, "stcp", "strict={strict}");
        assert_eq!(cfg.visitors[0].bind_port, 19000, "strict={strict}");
    }
}

/// A typed `.ini` header naming a v1 **array** root is collected under its raw
/// name, and `role = "visitor"` sends it to `[visitors]` — the type-dispatching
/// half of `legacy_ini_headers_naming_v1_roots_are_still_proxies`, which covers
/// the typeless and proxy spellings.
///
/// This pin is about the *routing* (a `visitors.foo` / `proxies.foo` header with
/// `role = "visitor"` ends up in `cfg.visitors` under its raw name, not in
/// `cfg.proxies`), not about which collector clause collects it: both the
/// authoritative-`role` clause (`frp-core/src/config/normalize.rs:2084-2086`) and
/// the array-root clause (`frp-core/src/config/normalize.rs:2100-2102`) accept
/// this input, so deleting either one alone leaves this test green. Each clause
/// has its own single-path pin instead — the `role` clause via
/// `legacy_ini_typed_reserved_root_visitor_is_refused_like_go`, the array-root
/// clause via `legacy_ini_headers_naming_v1_roots_are_still_proxies` — and both
/// were measured to go red when their clause is deleted.
#[test]
fn legacy_ini_typed_array_root_visitor_is_collected() {
    let head = "[common]\nserver_addr = 127.0.0.1\nserver_port = 7000\n";
    for (header, want_name) in [
        ("visitors.foo", "visitors.foo"),
        ("proxies.foo", "proxies.foo"),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("frpc.ini");
        std::fs::write(
            &path,
            format!(
                "{head}[{header}]\ntype = \"stcp\"\nrole = \"visitor\"\nbind_port = 19100\n\
                 server_name = s\n"
            ),
        )
        .unwrap();
        for strict in [false, true] {
            let cfg = load_client_config(path.to_str().unwrap(), strict).unwrap_or_else(|e| {
                panic!("typed array-root visitor [{header}], strict={strict}: {e}")
            });
            assert!(cfg.proxies.is_empty(), "[{header}], strict={strict}");
            assert_eq!(cfg.visitors.len(), 1, "[{header}], strict={strict}");
            assert_eq!(
                cfg.visitors[0].name, want_name,
                "[{header}], strict={strict}"
            );
            assert_eq!(
                cfg.visitors[0].visitor_type, "stcp",
                "[{header}], strict={strict}"
            );
        }
    }
}

/// **Disclosed residual.** A typed v1 **settings** root in an `.ini` stays the
/// settings table frp-rs has always read it as, in both loader modes, where Go
/// reads it as a legacy proxy and refuses it.
///
/// `[log] type = "custom" disable_print_color = true`: Go v0.71.0 is rc 1 in both
/// modes with `failed to parse proxy log, err: invalid type [custom]`; frp-rs is
/// rc 0 in both with `Proxies: 0`. origin/main happened to be rc 1 in strict mode
/// for an unrelated reason (`unknown field "log.type"`, which the section-level
/// `.ini` strict exemption removed). The rc-0 verdict is deliberate: the
/// reserved-root bypass keys on the **port** keys and never on `type`, because
/// keying it on `type` would collect every typed settings root and contradict
/// `test_legacy_ini_known_section_with_type_not_collected`
/// (`frp-core/src/config/tests.rs:10581`) and the `[web_server] type`-only v1
/// boundary. This test pins the strict verdict so the delta is measured rather
/// than silent.
#[test]
fn legacy_ini_typed_settings_root_with_type_stays_a_settings_table() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("frpc.ini");
    std::fs::write(
        &path,
        "[common]\nserver_addr = 127.0.0.1\nserver_port = 7000\n\
         [log]\ntype = \"custom\"\ndisable_print_color = true\n",
    )
    .unwrap();
    for strict in [false, true] {
        let cfg = load_client_config(path.to_str().unwrap(), strict).unwrap_or_else(|e| {
            panic!("residual: frp-rs accepts what Go refuses, strict={strict}: {e}")
        });
        assert!(
            cfg.proxies.is_empty(),
            "strict={strict}: stays a settings table"
        );
        assert!(
            cfg.log.disable_print_color,
            "strict={strict}: the log section is still read"
        );
    }
}

/// A **non-string** `type` in a legacy `.ini` section is not the empty string.
///
/// Go reads `section.Key("type").String()` (`pkg/config/legacy/proxy.go:78`), so
/// `type = 1` is the text `"1"` and `DefaultProxyConf` has no such variant:
/// measured on Go v0.71.0, `[p] type = 1 local_port = 8080 remote_port = 18080`
/// is rc 1 in both loader modes with `failed to parse proxy p, err: invalid type
/// [1]`. frp-rs refuses it too, through the v1 type check and with its own
/// wording. Only a *string* `type` may be defaulted to `tcp`, so a value of any
/// other shape must not be treated as missing — that would turn this rc-1 file
/// into an rc-0 `tcp` proxy.
#[test]
fn legacy_ini_non_string_type_is_not_defaulted_to_tcp() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("frpc.ini");
    std::fs::write(
        &path,
        "[common]\nserver_addr = 127.0.0.1\nserver_port = 7000\n\
         [p]\ntype = 1\nlocal_port = 8080\nremote_port = 18080\n",
    )
    .unwrap();
    for strict in [false, true] {
        let err = format!(
            "{}",
            load_client_config(path.to_str().unwrap(), strict)
                .expect_err("a non-string type is not a tcp default")
        );
        assert!(
            err.contains("invalid proxy_type '1'"),
            "strict={strict}: Go refuses `type = 1`; got {err}"
        );
    }
}

/// **Legacy-dialect parity, the `[includes]` / `[include]` guard bypass.** A
/// *table*-shaped `includes`/`include` is a section, not a directive, and has to
/// stay where the legacy guard and collector can see it.
///
/// Go reads its include list from the `[common]` section
/// (`IncludeConfigFiles []string \`ini:"includes"\``,
/// `pkg/config/legacy/client.go:166`) and turns every other section into a legacy
/// proxy or visitor named after its raw header, so a typeless
/// `[includes] role = "visitor"` is refused. Measured on Go v0.71.0: rc 1 in both
/// loader modes, `failed to parse visitor includes, err: type shouldn't be
/// empty`; `[include]` singular gives the same with `include`. frp-rs returned
/// rc 0 with `Proxies: 0 Visitors: 0` — `process_includes` removed the table
/// whatever its shape (`frp-core/src/config/file.rs:158` on b4b60b91; the shape
/// gate is now `frp-core/src/config/file.rs:312-313`) and it runs from
/// `frp-core/src/config/normalize.rs:634`, before the guard at `frp-core/src/config/normalize.rs:1991`, so the section was gone before
/// anything could refuse it. A dotted `[includes.foo]` was never reached by that
/// removal, but not because it is absent from the top level: `includes` is not in
/// `INI_NESTED_SECTION_ROOTS` (`frp-core/src/config/format.rs:259-275`), so the
/// header is kept verbatim as the top-level key `includes.foo` and only the
/// exact-key match in `process_includes` skipped it. The strict check then
/// refuses `includes.foo` as an unknown field where Go v0.71.0 is rc 0 in both
/// modes — a pre-existing residue, recorded rather than fixed here.
#[test]
fn legacy_ini_includes_section_is_not_a_visitor_directive() {
    let head = "[common]\nserver_addr = 127.0.0.1\nserver_port = 7000\n";
    for key in ["includes", "include"] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("frpc.ini");
        std::fs::write(
            &path,
            format!("{head}[{key}]\nrole = \"visitor\"\nserver_name = s\n"),
        )
        .unwrap();
        for strict in [false, true] {
            let err = format!(
                "{}",
                load_client_config(path.to_str().unwrap(), strict)
                    .expect_err("a table-shaped includes is not a directive")
            );
            assert!(
                err.contains(&format!(
                    "failed to parse visitor {key}, err: type shouldn't be empty"
                )),
                "[{key}], strict={strict}: Go's refusal under the raw header name; got {err}"
            );
        }
    }
}

/// **Legacy-dialect parity, `[includes]` carrying ports.** Removing a table-shaped
/// `includes` did not only hide a refusal — it also silently dropped proxies.
///
/// Measured on Go v0.71.0: `[includes] local_port = 8080 remote_port = 18080` is
/// rc 0 in both loader modes and registers a `tcp` proxy named `includes` (`new
/// proxy [includes] type [tcp]`); `[include]` the same with `include`. frp-rs
/// removed the section in `process_includes` and reported `Proxies: 0`, so a real
/// user config simply disappeared.
#[test]
fn legacy_ini_includes_section_with_ports_is_a_proxy() {
    let head = "[common]\nserver_addr = 127.0.0.1\nserver_port = 7000\n";
    for key in ["includes", "include"] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("frpc.ini");
        std::fs::write(
            &path,
            format!("{head}[{key}]\nlocal_port = 8080\nremote_port = 18080\n"),
        )
        .unwrap();
        for strict in [false, true] {
            let cfg = load_client_config(path.to_str().unwrap(), strict)
                .unwrap_or_else(|e| panic!("[{key}], strict={strict}: {e}"));
            assert!(cfg.visitors.is_empty(), "[{key}], strict={strict}");
            assert_eq!(cfg.proxies.len(), 1, "[{key}], strict={strict}");
            assert_eq!(cfg.proxies[0].name, key, "[{key}], strict={strict}");
            assert_eq!(cfg.proxies[0].proxy_type, "tcp", "[{key}], strict={strict}");
            assert_eq!(cfg.proxies[0].local_port, 8080, "[{key}], strict={strict}");
            assert_eq!(
                cfg.proxies[0].remote_port, 18080,
                "[{key}], strict={strict}"
            );
        }
    }
}

/// A table-shaped `[includes]` / `[include]` carrying no proxy keys is inert in
/// Go: `[includes] foo = 1` loads rc 0 in both dialects, on the client and on the
/// server (the server legacy reader only reads `[common]`, and the client's
/// proxy-name rule finds no `type`/port to act on). The shape gate at
/// `frp-core/src/config/file.rs:312-313` deliberately lets the table through so the
/// typeless-visitor guard (`frp-core/src/config/normalize.rs:1991`) and the
/// collector can see it, so the loader drops whatever table is still there after
/// normalization (`frp-core/src/config/file.rs:499`, run by the two `normalize`
/// wrappers at `frp-core/src/config/file.rs:467` and
/// `frp-core/src/config/file.rs:484`, `.ini` only). Without
/// that drop the leftover reached the v1 `includes: Vec<String>` decode and frp-rs
/// refused a file Go loads: client rc 1 both modes, server rc 1 both modes for
/// `[includes] foo = 1` and `[include] foo = 1` in strict mode.
#[test]
fn legacy_ini_table_shaped_include_without_proxy_keys_is_inert() {
    let client_head = "[common]\nserver_addr = 127.0.0.1\nserver_port = 7000\n";
    for key in ["includes", "include"] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("frpc.ini");
        std::fs::write(&path, format!("{client_head}[{key}]\nfoo = 1\n")).unwrap();
        for strict in [false, true] {
            let cfg = load_client_config(path.to_str().unwrap(), strict)
                .unwrap_or_else(|e| panic!("client [{key}], strict={strict}: {e}"));
            assert!(cfg.proxies.is_empty(), "client [{key}], strict={strict}");
            assert!(cfg.visitors.is_empty(), "client [{key}], strict={strict}");
        }
    }
    let server_head = "[common]\nbind_port = 7000\ntoken = t\n";
    for key in ["includes", "include"] {
        for tail in ["foo = 1\n", "local_port = 8080\n"] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("frps.ini");
            std::fs::write(&path, format!("{server_head}[{key}]\n{tail}")).unwrap();
            for strict in [false, true] {
                load_server_config(path.to_str().unwrap(), strict)
                    .unwrap_or_else(|e| panic!("server [{key}] {tail:?}, strict={strict}: {e}"));
            }
        }
    }
}

/// **Legacy-dialect parity, a *scalar* `includes` is inert.** Go selects its
/// legacy reader by the presence of `[common]`, not by the extension
/// (`DetectLegacyINIFormat`, `pkg/config/load.go:65`; the `strict` argument never
/// reaches that branch), and that reader skips `ini.DefaultSection`
/// (`pkg/config/legacy/client.go:204`), taking the include list from `[common]`
/// alone (`IncludeConfigFiles []string \`ini:"includes"\``,
/// `pkg/config/legacy/client.go:166`). A scalar `includes = 1` / `1.5` / `true` /
/// `include = 1` in the section-less top level — or nested in `[common]` — is
/// therefore inert: measured on Go v0.71.0, rc 0 in both loader modes on the
/// client and the server. frp-rs carried it into the v1 `includes: Vec<String>`
/// decode and refused a file Go loads (client and server rc 1 in both modes,
/// `invalid type: integer \`1\`, expected a sequence`), which
/// `drop_ini_scalar_include_keys` (`frp-core/src/config/file.rs:521`) removes. A
/// `.ini` **without** `[common]` goes down Go's v1 path too, so its type error
/// must stay, in both modes (the other include shapes that diverge from Go are listed in the "Known bounds" comment above `go_dir` in `frp-core/src/config/file.rs:543`).
#[test]
fn legacy_ini_scalar_includes_is_inert_like_go() {
    let client_head = "[common]\nserver_addr = 127.0.0.1\nserver_port = 7000\n";
    let server_head = "[common]\nbind_port = 7000\ntoken = t\n";
    for body in [
        "includes = 1\n",
        "includes = 1.5\n",
        "includes = true\n",
        "include = 1\n",
    ] {
        for (shape, text) in [
            ("top level", format!("{body}{client_head}")),
            ("inside [common]", format!("{client_head}{body}")),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("frpc.ini");
            std::fs::write(&path, text).unwrap();
            for strict in [false, true] {
                load_client_config(path.to_str().unwrap(), strict).unwrap_or_else(|e| {
                    panic!("client {shape} {body:?}, strict={strict}: Go loads this: {e}")
                });
            }
        }
        for (shape, text) in [
            ("top level", format!("{body}{server_head}")),
            ("inside [common]", format!("{server_head}{body}")),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("frps.ini");
            std::fs::write(&path, text).unwrap();
            for strict in [false, true] {
                load_server_config(path.to_str().unwrap(), strict).unwrap_or_else(|e| {
                    panic!("server {shape} {body:?}, strict={strict}: Go loads this: {e}")
                });
            }
        }
    }

    // The `.ini` *without* `[common]` is v1 for Go as well: rc 1 in both modes,
    // so the type error has to survive the legacy scrub. Only `includes` is
    // pinned here: the singular `include` is not a `ClientConfig` serde field,
    // so frp-rs loads `include = 1` on the v1 path while Go is rc 1 in both
    // modes — a pre-existing over-acceptance, measured (`c_nocommon_inc.ini`
    // in the round-4 probe set) and disclosed rather than fixed in this PR.
    for body in ["includes = 1\n"] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("frpc.ini");
        std::fs::write(
            &path,
            format!("{body}server_addr = 127.0.0.1\nserver_port = 7000\n"),
        )
        .unwrap();
        for strict in [false, true] {
            let err = format!(
                "{}",
                load_client_config(path.to_str().unwrap(), strict)
                    .expect_err("a v1 `.ini` keeps the includes type error")
            );
            assert!(
                err.contains("expected a sequence"),
                "no-[common] {body:?}, strict={strict}: {err}"
            );
        }
    }
}

/// **v1 formats keep the table-shaped `includes` type error.** The `.ini`-only
/// cleanup (`drop_legacy_ini_include_tables`,
/// `frp-core/src/config/file.rs:499`) is gated on the format
/// (`if format != ConfigFormat::Ini { return; }`,
/// `frp-core/src/config/file.rs:501`). Without that gate a table-shaped
/// `includes` in TOML/YAML/JSON is dropped and frp-rs loads a file Go refuses:
/// measured on Go v0.71.0, all three formats are rc 1 in both loader modes with
/// `field "ClientCommonConfig.includes": cannot unmarshal object into []string`
/// (`tab.toml`/`tab.yaml`/`tab.json`).
///
/// The server half below pins **frp-rs** behaviour, not Go's: measured on Go
/// v0.71.0, a server `.toml` with a table-shaped `includes` is rc 1 strict
/// (`json: unknown field "includes"` — the server v1 config has no such field)
/// but **rc 0 non-strict** (`syntax is ok`), while frp-rs refuses it in both
/// modes with `invalid type: map, expected a sequence`. That pre-existing server
/// divergence is a recorded residue, deliberately frozen here so the
/// `.ini`-only gate mutant is caught.
#[test]
fn table_shaped_includes_in_v1_formats_is_still_a_type_error() {
    let dir = tempfile::tempdir().unwrap();
    let client_cases = [
        (
            "frpc.toml",
            "server_addr = \"127.0.0.1\"\n[includes]\nfoo = 1\n",
        ),
        ("frpc.yaml", "server_addr: 127.0.0.1\nincludes:\n  foo: 1\n"),
        (
            "frpc.json",
            "{\"server_addr\":\"127.0.0.1\",\"includes\":{\"foo\":1}}\n",
        ),
    ];
    for (file, body) in client_cases {
        let path = dir.path().join(file);
        std::fs::write(&path, body).unwrap();
        for strict in [false, true] {
            let err = format!(
                "{}",
                load_client_config(path.to_str().unwrap(), strict)
                    .expect_err("a table-shaped includes is a type error in v1 formats")
            );
            assert!(
                err.contains("invalid type: map, expected a sequence"),
                "client {file}, strict={strict}: {err}"
            );
        }
    }

    let path = dir.path().join("frps.toml");
    std::fs::write(&path, "bind_port = 7000\n[includes]\nfoo = 1\n").unwrap();
    for strict in [false, true] {
        let err = format!(
            "{}",
            load_server_config(path.to_str().unwrap(), strict)
                .expect_err("a table-shaped includes is a type error in v1 formats")
        );
        assert!(
            err.contains("invalid type: map, expected a sequence"),
            "server frps.toml, strict={strict}: {err}"
        );
    }
}

/// **Legacy-dialect parity, `role` is read before the section is classified.**
/// `LoadAllProxyConfsFromIni` (`pkg/config/legacy/client.go:255-285`) reads
/// `role` (default `server`, and `role = ""` is the same as missing), then
/// switches on it; the `default:` arm is
/// `proxy %s role should be 'server' or 'visitor'`, with `%s` the raw header.
/// Measured on Go v0.71.0, rc 1 in both loader modes for every shape below —
/// including the reserved headers `[proxies]` / `[visitors]` (the header is just
/// the proxy's name) and a section the collector would otherwise drop. frp-rs
/// routed every non-`visitor` string to the proxy path, so all of these were rc 0
/// with one synthetic proxy. The accepted spellings are exact and
/// case-sensitive, and Go sees the *text* of the value, so an unquoted
/// `role = 1` is refused too. `[range:...]` is expanded before the switch, so a
/// bad role there is reported under the generated `{prefix}_{i}` name
/// (measured: `proxy p_0 role should be 'server' or 'visitor'`).
///
/// The switch belongs to the legacy *client* reader: the legacy server reader
/// maps `[common]` only, so it ignores these sections (rc 0, measured; the
/// non-strict half is pinned below, the strict half is pre-existing residue — the
/// top-level check refuses the unknown section where Go does not).
#[test]
fn legacy_ini_bad_role_is_refused_like_go() {
    let head = "[common]\nserver_addr = 127.0.0.1\nserver_port = 7000\n";
    let refused = [
        ("proxies", "[proxies]\nrole = \"weird\"\n"),
        ("visitors", "[visitors]\nrole = \"weird\"\n"),
        ("proxies", "[proxies]\nrole = \"Server\"\n"),
        ("visitors", "[visitors]\nrole = 1\n"),
        ("foo", "[foo]\nrole = \"weird\"\n"),
        (
            "p",
            "[p]\nrole = 1\nlocal_port = 8080\nremote_port = 18080\n",
        ),
    ];
    for (name, body) in refused {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("frpc.ini");
        std::fs::write(&path, format!("{head}{body}")).unwrap();
        for strict in [false, true] {
            let err = format!(
                "{}",
                load_client_config(path.to_str().unwrap(), strict)
                    .expect_err("Go refuses a role that is not server/visitor")
            );
            assert!(
                err.contains(&format!(
                    "proxy {name} role should be 'server' or 'visitor'"
                )),
                "[{name}] {body:?}, strict={strict}: {err}"
            );
        }
    }

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("frpc.ini");
    std::fs::write(
        &path,
        format!("{head}[range:p]\nrole = \"weird\"\nlocal_port = 8080\nremote_port = 18080\n"),
    )
    .unwrap();
    for strict in [false, true] {
        let err = format!(
            "{}",
            load_client_config(path.to_str().unwrap(), strict)
                .expect_err("Go refuses the generated range section's role")
        );
        assert!(
            err.contains("proxy p_0 role should be 'server' or 'visitor'"),
            "range, strict={strict}: the refusal names the generated section: {err}"
        );
    }

    // The accepted spellings still load: `server`, missing, `""` (all `server`)
    // and an exact `visitor` with visitor keys.
    let accepted = [
        (
            "server",
            "[proxies]\nrole = \"server\"\nlocal_port = 8080\nremote_port = 18080\n",
            "proxies",
        ),
        (
            "empty",
            "[p]\nrole = \"\"\nlocal_port = 8080\nremote_port = 18080\n",
            "p",
        ),
        (
            "absent",
            "[p]\nlocal_port = 8080\nremote_port = 18080\n",
            "p",
        ),
    ];
    for (label, body, name) in accepted {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("frpc.ini");
        std::fs::write(&path, format!("{head}{body}")).unwrap();
        for strict in [false, true] {
            let cfg = load_client_config(path.to_str().unwrap(), strict)
                .unwrap_or_else(|e| panic!("{label}, strict={strict}: Go loads this: {e}"));
            assert!(cfg.visitors.is_empty(), "{label}, strict={strict}");
            assert_eq!(cfg.proxies.len(), 1, "{label}, strict={strict}");
            assert_eq!(cfg.proxies[0].name, name, "{label}, strict={strict}");
        }
    }

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("frpc.ini");
    std::fs::write(
        &path,
        format!("{head}[visitors]\nrole = \"visitor\"\ntype = \"stcp\"\nbind_port = 19100\nserver_name = s\n"),
    )
    .unwrap();
    for strict in [false, true] {
        let cfg = load_client_config(path.to_str().unwrap(), strict)
            .unwrap_or_else(|e| panic!("visitor, strict={strict}: Go loads this: {e}"));
        assert!(cfg.proxies.is_empty(), "visitor, strict={strict}");
        assert_eq!(cfg.visitors.len(), 1, "visitor, strict={strict}");
        assert_eq!(cfg.visitors[0].name, "visitors", "visitor, strict={strict}");
    }

    // The refusal is client-only. The legacy *server* reader maps `[common]`
    // alone (`UnmarshalServerConfFromIni`, `pkg/config/legacy/server.go:220-241`)
    // and never reaches the role switch, so all three headers are rc 0 there in
    // both loader modes — measured on Go v0.71.0. Pinned in the non-strict mode
    // only: strict mode's top-level check refuses the section as an unknown
    // field (`proxies`/`visitors`/`foo` are not `ServerConfig` fields) while Go
    // is rc 0; that is pre-existing strict residue, disclosed in the round-4
    // report. It is a different shape from the scalar `include`/`includes`
    // refusal the round-4 scrub fixes (`s_inc_int.ini` now loads in both modes).
    let server_head = "[common]\nbind_port = 7000\ntoken = t\n";
    for body in [
        "[proxies]\nrole = \"weird\"\nlocal_port = 8080\nremote_port = 18080\n",
        "[visitors]\nrole = \"weird\"\nlocal_port = 8080\nremote_port = 18080\n",
        "[foo]\nrole = \"weird\"\n",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("frps.ini");
        std::fs::write(&path, format!("{server_head}{body}")).unwrap();
        load_server_config(path.to_str().unwrap(), false)
            .unwrap_or_else(|e| panic!("{body:?} (non-strict): Go loads this: {e}"));
    }
}

/// A **non-table** `webServer` / `web_server` (top level or under `[common]`)
/// must still reach serde as a type error.
///
/// The whole-table `or_insert` this merge replaced *moved* the value whatever its
/// type, so serde refused it: base `frps verify` rc 1 both modes with
/// `invalid type: string "not a table", expected struct WebServerConfig`. The
/// first cut of `merge_section_into` matched `Value::Table` **after**
/// `table.remove(from)`, so a non-table `webServer` was deleted instead of being
/// carried across and both modes returned rc 0 "syntax is ok" — on the server and
/// the client, at the top level and under `[common]`. The merge now moves the
/// value first and only pattern-matches in the `Occupied` arm.
///
/// **What this models.** Both loader modes on real files, server and client, for
/// `webServer` and `web_server` at the top level and under `[common]`, as a
/// string and as an integer.
///
/// **What it does not cover.** A non-table `web_server` *beside* a camelCase
/// table: `into` wins and `from` is dropped, which is the old `or_insert`
/// behaviour and is pinned by `both_web_server_sections_merge_per_key_in_both_modes`
/// only for the table case.
#[test]
fn non_table_web_server_section_is_still_a_type_error() {
    let server_shapes = [
        (
            "webServer = string",
            "bind_port = 7000\nwebServer = \"not a table\"\n",
        ),
        ("web_server = int", "bind_port = 7000\nweb_server = 5\n"),
        (
            "[common] webServer = string",
            "bind_port = 7000\n[common]\nwebServer = \"not a table\"\n",
        ),
        (
            "[common] web_server = int",
            "bind_port = 7000\n[common]\nweb_server = 5\n",
        ),
    ];
    for (name, body) in server_shapes {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("frps.toml");
        std::fs::write(&path, body).unwrap();
        for strict in [false, true] {
            let err = format!(
                "{}",
                load_server_config(path.to_str().unwrap(), strict).unwrap_err()
            );
            assert!(
                err.contains("WebServerConfig"),
                "server {name}, strict={strict}: the non-table section must reach serde: {err}"
            );
        }
    }

    let client_shapes = [
        (
            "webServer = string",
            "server_addr = \"127.0.0.1\"\nserver_port = 7000\ntoken = \"t\"\nwebServer = \"not a table\"\n",
        ),
        (
            "web_server = int",
            "server_addr = \"127.0.0.1\"\nserver_port = 7000\ntoken = \"t\"\nweb_server = 5\n",
        ),
        (
            "[common] webServer = string",
            "server_addr = \"127.0.0.1\"\nserver_port = 7000\ntoken = \"t\"\n[common]\nwebServer = \"not a table\"\n",
        ),
        (
            "[common] web_server = int",
            "server_addr = \"127.0.0.1\"\nserver_port = 7000\ntoken = \"t\"\n[common]\nweb_server = 5\n",
        ),
    ];
    for (name, body) in client_shapes {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("frpc.toml");
        std::fs::write(&path, body).unwrap();
        for strict in [false, true] {
            let err = format!(
                "{}",
                load_client_config(path.to_str().unwrap(), strict).unwrap_err()
            );
            assert!(
                err.contains("WebServerConfig"),
                "client {name}, strict={strict}: the non-table section must reach serde: {err}"
            );
        }
    }
}

/// The parent-level `certFile` / `keyFile` / `trustedCaFile` / `serverName`
/// serde **aliases** are canonicalized away, so the same field can never reach
/// serde twice — a pre-existing `duplicate field \`tls_cert_file\`` in **both**
/// loader modes, with no nested key involved at all.
///
/// serde binds `web_server.certFile` as an `alias` of
/// `web_server.tls_cert_file`, so writing both at the parent level used to fail
/// to deserialize (measured: rc 1, `config validation error: duplicate field
/// \`tls_cert_file\``, both modes — probe case E1/E2, and `frps verify` on a
/// real binary). `normalize_web_server_section` now canonicalizes the whole
/// four-spelling group down to `flat_key` whenever the `tls` table is present
/// *or absent*, and the first **non-empty** spelling wins in the order nested
/// snake → nested camel → parent canonical → parent alias — so the parent
/// canonical (the struct's own field name) wins.
///
/// **What this models.** Both loader modes, each of the four pairs alone and all
/// four together, plus the empty-canonical case (where "first non-empty" makes
/// the alias supply the value, consistent with the empty-means-unset rule) and
/// the control with the alias alone.
///
/// **What it does not cover.** A parent-level **snake** `cert_file` (the nested
/// spelling written at the parent level) — that is not a field and must keep
/// being reported, pinned by
/// `parent_level_snake_spelling_is_still_reported_in_strict_mode`; and YAML,
/// where a duplicate key is the parser's business before this runs.
#[test]
fn parent_alias_beside_parent_canonical_loads_in_both_modes() {
    const HEADER: &str = "bind_port = 7000\ntoken = \"t\"\n";
    const WS: &str = "[web_server]\naddr = \"127.0.0.1\"\nport = 7500\n";

    // (name, parent lines, expected cert/key/ca/sn)
    type Case<'a> = (&'a str, &'a str, (&'a str, &'a str, &'a str, &'a str));
    let cases: [Case; 6] = [
        (
            "certFile + tls_cert_file",
            "certFile = \"/alias/c.pem\"\ntls_cert_file = \"/canon/c.pem\"\n",
            ("/canon/c.pem", "", "", ""),
        ),
        (
            "keyFile + tls_key_file",
            "keyFile = \"/alias/k.pem\"\ntls_key_file = \"/canon/k.pem\"\n",
            ("", "/canon/k.pem", "", ""),
        ),
        (
            "trustedCaFile + tls_ca_file",
            "trustedCaFile = \"/alias/ca.pem\"\ntls_ca_file = \"/canon/ca.pem\"\n",
            ("", "", "/canon/ca.pem", ""),
        ),
        (
            "serverName + tls_server_name",
            "serverName = \"alias.example\"\ntls_server_name = \"canon.example\"\n",
            ("", "", "", "canon.example"),
        ),
        (
            "all four pairs",
            "certFile = \"/a/c\"\ntls_cert_file = \"/c/c\"\nkeyFile = \"/a/k\"\ntls_key_file = \"/c/k\"\n\
             trustedCaFile = \"/a/ca\"\ntls_ca_file = \"/c/ca\"\nserverName = \"a.example\"\n\
             tls_server_name = \"c.example\"\n",
            ("/c/c", "/c/k", "/c/ca", "c.example"),
        ),
        (
            "empty canonical + non-empty alias",
            "certFile = \"/alias/c.pem\"\ntls_cert_file = \"\"\n",
            ("/alias/c.pem", "", "", ""),
        ),
    ];

    for (name, parent, want) in cases {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("frps.toml");
        std::fs::write(&path, format!("{HEADER}{WS}{parent}")).unwrap();
        let p = path.to_str().unwrap();
        for strict in [false, true] {
            let cfg = load_server_config(p, strict)
                .unwrap_or_else(|e| panic!("{name}, strict={strict}: must load:\n{e}"));
            let ws = &cfg.web_server;
            assert_eq!(
                (
                    ws.tls_cert(),
                    ws.tls_key(),
                    ws.tls_ca_file.as_str(),
                    ws.tls_server_name.as_str()
                ),
                want,
                "{name}, strict={strict}",
            );
            // The alias key itself never survives normalization, so strict mode
            // does not see a key the loader already folded.
            assert_eq!(
                cfg.web_server.tls.cert_file, "",
                "{name}: the nested struct stays default"
            );
        }
    }

    // Control: the alias alone still works (no canonical to win).
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("frps.toml");
    std::fs::write(
        &path,
        format!("{HEADER}{WS}certFile = \"/alias/c.pem\"\nkeyFile = \"/alias/k.pem\"\n"),
    )
    .unwrap();
    for strict in [false, true] {
        let cfg = load_server_config(path.to_str().unwrap(), strict).unwrap();
        assert_eq!(cfg.web_server.tls_cert(), "/alias/c.pem", "strict={strict}");
        assert_eq!(cfg.web_server.tls_key(), "/alias/k.pem", "strict={strict}");
    }

    // Client: same normalizer, same canonicalization.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("frpc.toml");
    std::fs::write(
        &path,
        "server_addr = \"127.0.0.1\"\nserver_port = 7000\ntoken = \"t\"\n\
         [web_server]\nport = 7400\ncertFile = \"/alias/c.pem\"\ntls_cert_file = \"/canon/c.pem\"\n",
    )
    .unwrap();
    for strict in [false, true] {
        let cfg = load_client_config(path.to_str().unwrap(), strict).unwrap();
        assert_eq!(
            cfg.web_server.tls_cert(),
            "/canon/c.pem",
            "client, strict={strict}"
        );
    }
}

/// An explicitly **empty** nested value is *unset*: it does not clear a value
/// the flat or alias spelling already supplies.
///
/// The hoist's `insert` used to treat `[web_server.tls] cert_file = ""` as "the
/// nested value wins", so a certificate written for the flat/alias spelling was
/// silently dropped and the dashboard fell back to plaintext HTTP — measured
/// `tls_cert() == ""` in both loader modes (probe cases F1/F2). Emptiness is how
/// these fields say *disabled*, so the fail-safe reading is that an empty
/// spelling falls through to the next one; the alternative (empty wins) is a
/// silent loss of a configured certificate. `docs/config.md` states the same
/// rule.
///
/// **What this models.** Both loader modes on a real file: empty nested beside a
/// parent alias, empty nested beside the parent canonical, empty nested alone,
/// empty snake beside a set camelCase sibling, and empty nested beside a
/// **nested** camelCase sibling for all four destinations.
///
/// **What it does not cover.** A non-string empty (`cert_file = 0`) is treated
/// as present rather than empty and reaches serde, which rejects it — the type
/// error is the honest outcome. The rejected alternative (empty wins) is not
/// pinned by a test, because it is exactly what the assertions below forbid.
#[test]
fn empty_nested_value_is_unset_in_both_modes() {
    const HEADER: &str = "bind_port = 7000\ntoken = \"t\"\n";
    const WS: &str = "[web_server]\naddr = \"127.0.0.1\"\nport = 7500\n";

    type Loaded = (String, String, String, String);
    fn load_both(body: &str) -> [(Loaded, String); 2] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("frps.toml");
        std::fs::write(&path, body).unwrap();
        let p = path.to_str().unwrap();
        [false, true].map(|strict| {
            let cfg = load_server_config(p, strict)
                .unwrap_or_else(|e| panic!("strict={strict} must load:\n{e}"));
            let ws = cfg.web_server;
            (
                (
                    ws.tls_cert().to_string(),
                    ws.tls_key().to_string(),
                    ws.tls_ca_file.clone(),
                    ws.tls_server_name.clone(),
                ),
                format!("strict={strict}"),
            )
        })
    }

    // Empty nested beside a parent alias: the alias value survives.
    for (got, mode) in load_both(&format!(
        "{HEADER}{WS}certFile = \"/p.pem\"\n[web_server.tls]\ncert_file = \"\"\n"
    )) {
        assert_eq!(got.0, "/p.pem", "alias survives, {mode}");
    }

    // Empty nested beside the parent canonical: the canonical value survives.
    for (got, mode) in load_both(&format!(
        "{HEADER}{WS}tls_cert_file = \"/p.pem\"\ntls_key_file = \"/k.pem\"\n\
         [web_server.tls]\ncert_file = \"\"\nkey_file = \"\"\n"
    )) {
        assert_eq!(
            (got.0.as_str(), got.1.as_str()),
            ("/p.pem", "/k.pem"),
            "{mode}"
        );
    }

    // Empty nested alone: the field stays empty (the default), and nothing is
    // invented.
    for (got, mode) in load_both(&format!(
        "{HEADER}{WS}[web_server.tls]\ncert_file = \"\"\nkey_file = \"\"\n\
         trusted_ca_file = \"\"\nserver_name = \"\"\n"
    )) {
        assert_eq!(
            got,
            (String::new(), String::new(), String::new(), String::new()),
            "{mode}"
        );
    }

    // Empty snake beside a set camelCase sibling: the empty spelling is skipped,
    // so the camel one supplies the value (the same rule, one level down).
    for (got, mode) in load_both(&format!(
        "{HEADER}{WS}[web_server.tls]\ncert_file = \"\"\ncertFile = \"/camel.pem\"\n"
    )) {
        assert_eq!(got.0, "/camel.pem", "empty snake falls through, {mode}");
    }

    // …and the reverse: a non-empty snake wins over an empty camel spelling.
    for (got, mode) in load_both(&format!(
        "{HEADER}{WS}[web_server.tls]\ncert_file = \"/snake.pem\"\ncertFile = \"\"\n"
    )) {
        assert_eq!(got.0, "/snake.pem", "{mode}");
    }

    // All four destinations, empty nested beside set flat values.
    for (got, mode) in load_both(&format!(
        "{HEADER}{WS}tls_cert_file = \"/f/c\"\ntls_key_file = \"/f/k\"\n\
         tls_ca_file = \"/f/ca\"\ntls_server_name = \"f.example\"\n\
         [web_server.tls]\ncert_file = \"\"\nkey_file = \"\"\ntrusted_ca_file = \"\"\n\
         server_name = \"\"\n"
    )) {
        assert_eq!(
            got,
            (
                "/f/c".to_string(),
                "/f/k".to_string(),
                "/f/ca".to_string(),
                "f.example".to_string()
            ),
            "{mode}"
        );
    }

    // Client: same rule.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("frpc.toml");
    std::fs::write(
        &path,
        "server_addr = \"127.0.0.1\"\nserver_port = 7000\ntoken = \"t\"\n\
         [web_server]\nport = 7400\ncertFile = \"/p.pem\"\n\
         [web_server.tls]\ncert_file = \"\"\n",
    )
    .unwrap();
    for strict in [false, true] {
        let cfg = load_client_config(path.to_str().unwrap(), strict).unwrap();
        assert_eq!(
            cfg.web_server.tls_cert(),
            "/p.pem",
            "client, strict={strict}"
        );
    }
}

/// Both spellings of one nested `[web_server.tls]` key in the same file: the
/// canonical snake_case wins, and the loser does **not** survive under its own
/// name at the parent level.
///
/// **Corrected scope (fix round).** The first version of this comment claimed
/// the base tree failed this shape with `duplicate field`, i.e. that the
/// collision was a previously unrecorded pre-existing defect. **It was not.**
/// Measured on base (`5717fa2`): `strict = false` returned the **camelCase**
/// value (`tls_cert() == "/camel/cert.pem"` — `certFile` is mapped, the
/// snake_case sibling was dropped as an unknown key) and `strict = true`
/// reported `unknown field "web_server.cert_file"`. The `duplicate field`
/// failure appears only in a **half-implemented mapping** — removing just the
/// winning spelling and letting the loser fall through to the "anything else"
/// re-insert at the end of `normalize_web_server_section` — which is what the
/// first attempt did; both fix-round reviewers reproduced it independently as a
/// scratch variant / mutant.
///
/// So this test pins a hazard of the mapping, not a base defect: it is what
/// keeps a future edit to the removal loop from reintroducing the collision.
/// (The *pre-existing* `duplicate field` shape is a different one — a
/// **parent-level** `[web_server] certFile` beside a nested one — which base
/// failed in both modes and the fix round closed; see
/// `parent_level_alias_beside_nested_spelling_still_loads`.)
///
/// Also covers the three camelCase-plus-snake pairs that share a destination
/// through the `MAPPED` table, so a future edit to that table cannot silently
/// reintroduce the collision for `key_file` / `trusted_ca_file` /
/// `server_name`.
///
/// **What this models.** Both loader modes on a real file with all four pairs
/// written twice.
///
/// **What it does not cover.** Which of the two spellings a user *meant* — the
/// choice (snake_case) is a decision recorded on
/// `normalize_web_server_section`, not a measurement; the base-tree behaviour,
/// which this test would pass through if the mapping were removed entirely (the
/// snake spelling would then be an unknown key, not a duplicate); and YAML,
/// where duplicate or aliased keys behave differently in the parser itself.
#[test]
fn both_spellings_of_one_nested_key_do_not_collide() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("frps.toml");
    std::fs::write(
        &path,
        "bind_port = 7000\ntoken = \"t\"\n[web_server]\naddr = \"127.0.0.1\"\nport = 7500\n\
         [web_server.tls]\ncert_file = \"/snake/cert.pem\"\ncertFile = \"/camel/cert.pem\"\n\
         key_file = \"/snake/key.pem\"\nkeyFile = \"/camel/key.pem\"\n\
         trusted_ca_file = \"/snake/ca.pem\"\ntrustedCaFile = \"/camel/ca.pem\"\n\
         server_name = \"snake.example.com\"\nserverName = \"camel.example.com\"\n",
    )
    .unwrap();
    let p = path.to_str().unwrap();
    for strict in [false, true] {
        let cfg = load_server_config(p, strict)
            .unwrap_or_else(|e| panic!("strict={strict}: both spellings must load:\n{e}"));
        assert_eq!(
            cfg.web_server.tls_cert(),
            "/snake/cert.pem",
            "strict={strict}"
        );
        assert_eq!(
            cfg.web_server.tls_key(),
            "/snake/key.pem",
            "strict={strict}"
        );
        assert_eq!(
            cfg.web_server.tls_ca_file, "/snake/ca.pem",
            "strict={strict}"
        );
        assert_eq!(
            cfg.web_server.tls_server_name, "snake.example.com",
            "strict={strict}"
        );
        // The camelCase losers are not left behind as parent-level keys.
        assert_eq!(
            cfg.web_server.tls_cert_file, "/snake/cert.pem",
            "strict={strict}"
        );
        // …and the nested struct itself is still default: the hoist is the only
        // way a nested value reaches a field.
        assert_eq!(cfg.web_server.tls.cert_file, "", "strict={strict}");
    }
}

/// `[web_server.tls] enable` is accepted in **both** loader modes and inert in
/// both — the decision recorded on `normalize_web_server_section`.
///
/// It is inert because nothing reads it: `normalize_web_server_section` removes
/// `enable` with the table's other mapped keys before serde, so
/// `WebServerTlsConfig::enable` is default-`false` in every loaded config (`frp-core/src/config/restart_only.rs` destructures it as
/// unreachable), and there is no reader anywhere in `frp-server`/`frps`
/// (`grep -rn 'tls\.enable' frp-server/src frps/src` matches only
/// `transport.tls.enable` spellings in test fixtures). frp-rs enables the
/// dashboard TLS from a non-empty cert/key pair
/// (`frp-server/src/service.rs`, `web_server.tls_cert()`), which is also what Go
/// does: Go's `TLSConfig` (`pkg/config/v1/common.go:76-84`) has **no** `Enable`
/// field and its HTTP server starts TLS when `cfg.TLS != nil`
/// (`pkg/util/http/server.go:77`), so `enable` is not even a Go key to be
/// compatible with.
///
/// Before this pin the key was re-inserted as `web_server.enable` (not a
/// field): dropped under `strict = false` but **refused** under `strict =
/// true` — the same silent/refuse split as the snake_case spellings, both
/// naming a path the user never wrote (`web_server.enable`, not
/// `web_server.tls.enable`). Dropped in both modes now, so the two modes agree
/// and neither invents a key.
///
/// **What this models.** Both loader modes on a real file for `enable` alone,
/// for `enable` beside all four mapped spellings, and for `enable = false` with
/// a cert/key pair — the three shapes the decision has to hold for. The
/// rejected alternative (map `enable` onto the cert/key pair, i.e. `false`
/// suppresses TLS) is the third shape.
///
/// **What it does not cover.** Whether a future reader is ever wired to the
/// field — if one is, this test must change with it (that is the point of
/// pinning the decision); Go's runtime, which is cited from source
/// (`pkg/util/http/server.go:77`) but not probed with a binary here; and the
/// `transport.tls.enable` key, which is a different field of a different
/// section.
#[test]
fn nested_web_server_tls_enable_is_accepted_and_inert_in_both_modes() {
    const HEADER: &str = "bind_port = 7000\ntoken = \"t\"\n";

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("frps.toml");
    let p = path.to_str().unwrap();
    let write = |body: &str| std::fs::write(&path, body).unwrap();

    // (a) `enable` alone: loads in both modes, stores nothing, is not a cert.
    write(&format!(
        "{HEADER}[web_server]\naddr = \"127.0.0.1\"\nport = 7500\n\
         [web_server.tls]\nenable = true\n"
    ));
    for strict in [false, true] {
        let cfg = load_server_config(p, strict)
            .unwrap_or_else(|e| panic!("strict={strict}: `enable` must load:\n{e}"));
        assert!(
            !cfg.web_server.tls.enable,
            "strict={strict}: inert, not stored"
        );
        assert_eq!(cfg.web_server.tls_cert(), "", "strict={strict}: not a cert");
    }

    // (b) `enable` alongside the four mapped spellings: still loads in both
    // modes, and no branch reports a path the user never wrote. Before the
    // mapping, strict mode named one invented sibling per key —
    // `web_server.cert_file`, `…key_file`, `…trusted_ca_file`, `…server_name`,
    // `…enable` — which is defect (3) of the item.
    write(&format!(
        "{HEADER}[web_server]\naddr = \"127.0.0.1\"\nport = 7500\n\
         [web_server.tls]\nenable = true\ncert_file = \"/tls/cert.pem\"\n\
         key_file = \"/tls/key.pem\"\ntrusted_ca_file = \"/tls/ca.pem\"\n\
         server_name = \"tls.example.com\"\n"
    ));
    for strict in [false, true] {
        let cfg = load_server_config(p, strict)
            .unwrap_or_else(|e| panic!("strict={strict}: the mapped spellings must load:\n{e}"));
        assert_eq!(
            cfg.web_server.tls_cert(),
            "/tls/cert.pem",
            "strict={strict}"
        );
        assert_eq!(cfg.web_server.tls_key(), "/tls/key.pem", "strict={strict}");
        assert_eq!(cfg.web_server.tls_ca_file, "/tls/ca.pem", "strict={strict}");
        assert_eq!(
            cfg.web_server.tls_server_name, "tls.example.com",
            "strict={strict}"
        );
    }

    // (c) `enable = false` is as inert as `true`: it neither removes a cert/key
    // pair nor changes any flat value. Pinned because "map `enable` onto the
    // TLS switch" was the rejected alternative decision — this is what that
    // decision would have broken.
    write(&format!(
        "{HEADER}[web_server]\naddr = \"127.0.0.1\"\nport = 7500\n\
         [web_server.tls]\nenable = false\ncert_file = \"/off/cert.pem\"\n\
         key_file = \"/off/key.pem\"\n"
    ));
    for strict in [false, true] {
        let cfg = load_server_config(p, strict)
            .unwrap_or_else(|e| panic!("strict={strict}: `enable = false` must load:\n{e}"));
        assert_eq!(
            cfg.web_server.tls_cert(),
            "/off/cert.pem",
            "strict={strict}"
        );
        assert_eq!(cfg.web_server.tls_key(), "/off/key.pem", "strict={strict}");
    }
}

/// A genuinely unknown key inside `[web_server.tls]` is refused in strict mode,
/// and the path it names is the one the user actually wrote —
/// `web_server.tls.bogus_key`.
///
/// **The residue this replaced.** The hoist used to re-insert every unmapped
/// nested key at the **parent** level under its own name, so strict mode said
/// `web_server.bogus_key` for a key written as `web_server.tls.bogus_key`; the
/// previous round's test pinned that wrong path on purpose and named the fix
/// ("would need `check_strict` to see the pre-removal shape"). That is what this
/// change does: the residue stays inside `tls` (it can no longer bind a real
/// `WebServerConfig` field either — see
/// `nested_web_server_tls_credentials_do_not_become_the_parent_fields`), and the
/// walker descends `web_server` → `tls` with
/// [`super::strict::WEB_SERVER_TLS_KNOWN_KEYS`].
///
/// **What this models.** Both loader modes on a real file whose only nested key
/// is unknown, for the server and for the client admin section (same
/// normalizer).
///
/// **What it does not cover.** The `did you mean` suggestion for a *typo* of a
/// mapped spelling (e.g. `cert_fil`): the suggestion list is now the nested TLS
/// key set, so it can suggest `cert_file` / `certFile`, never `tls_cert_file`.
/// Not pinned here because that heuristic is best-effort everywhere.
#[test]
fn unknown_nested_web_server_tls_key_names_the_true_nested_path() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("frps.toml");
    std::fs::write(
        &path,
        "bind_port = 7000\ntoken = \"t\"\n[web_server]\naddr = \"127.0.0.1\"\nport = 7500\n\
         [web_server.tls]\nbogus_key = \"x\"\n",
    )
    .unwrap();
    let p = path.to_str().unwrap();

    let err = load_server_config(p, true).unwrap_err();
    let err = format!("{err}");
    assert!(
        err.contains("unknown field \"web_server.tls.bogus_key\""),
        "the diagnostic names the path the user wrote: got {err}"
    );
    assert!(
        !err.contains("unknown field \"web_server.bogus_key\""),
        "the fabricated parent-level path is gone: got {err}"
    );
    assert!(
        !err.contains("web_server.cert_file"),
        "no mapped snake_case spelling is unknown: got {err}"
    );

    // Non-strict keeps the drop, so the two modes differ only in loudness here
    // — the same shape as every other unknown key (`check_strict`'s job), and
    // unlike the pre-fix `cert_file` case, whose *value* was lost.
    load_server_config(p, false).unwrap();

    // Same for the client's admin `[web_server]` — `load_client_config` calls
    // the same normalizer and the same walker.
    let cdir = tempfile::tempdir().unwrap();
    let cpath = cdir.path().join("frpc.toml");
    std::fs::write(
        &cpath,
        "server_addr = \"127.0.0.1\"\nserver_port = 7000\ntoken = \"t\"\n\
         [web_server]\nport = 7400\n[web_server.tls]\nbogus_key = \"x\"\n",
    )
    .unwrap();
    let cerr = format!(
        "{}",
        load_client_config(cpath.to_str().unwrap(), true).unwrap_err()
    );
    assert!(
        cerr.contains("unknown field \"web_server.tls.bogus_key\""),
        "client: got {cerr}"
    );
    load_client_config(cpath.to_str().unwrap(), false).unwrap();
}

/// A nested `[web_server.tls]` key that names a real `WebServerConfig` field
/// must **not** become that field.
///
/// Before this change `normalize_web_server_section` re-inserted every unmapped
/// nested key at the parent level with `or_insert`, and `user` / `password`
/// (plus `addr`, `port`, `enable_prometheus`, `assets_dir`, `pprof_enable`,
/// `custom_404_page` and the four flat `tls_*` spellings, and both key cases of
/// each) are real fields — so `[web_server.tls] user = "nested-user"` loaded
/// with `web_server.user == "nested-user"`: a nested section silently *became*
/// the dashboard Basic Auth credentials. Measured in both loader modes (probe
/// case C2, and C3 for the other fields).
///
/// Go refuses these keys: its `TLSConfig` has neither `user` nor `password` and
/// its decoder rejects unknown members — probed on the v0.71.0 `frps`, which
/// exits 1 with `json: unknown field "password"` for the same shape. frp-rs
/// keeps the accept-and-ignore divergence for `.ini`-style leniency but reports
/// it in strict mode at the true path, so it is never a **silent** credential
/// substitution.
///
/// **What this models.** Both loader modes, every `WebServerConfig` field name
/// (snake and both Go camelCase spellings where they exist), with and without a
/// parent value to collide with, server and client.
///
/// **What it does not cover.** A *future* `WebServerConfig` field added without
/// updating this list: `strict_array_element_keys_match_struct_fields` compares
/// `WEB_SERVER_TLS_KNOWN_KEYS` against `WebServerTlsConfig`, not against
/// `WebServerConfig`, so a new parent field would need a new row here. The
/// `enable` key, which is dropped-and-warned rather than reported (a deliberate
/// divergence, pinned by
/// `nested_web_server_tls_enable_is_accepted_and_inert_in_both_modes`).
#[test]
fn nested_web_server_tls_credentials_do_not_become_the_parent_fields() {
    const HEADER: &str = "bind_port = 7000\ntoken = \"t\"\n";
    const PARENT: &str = "[web_server]\naddr = \"127.0.0.1\"\nport = 7500\n";

    // Every real `WebServerConfig` field name, in every spelling serde accepts,
    // paired with the `(field, value)` the nested key used to reach.
    let shapes: [(&str, &str); 14] = [
        ("user", "nested-user"),
        ("password", "nested-secret"),
        ("addr", "0.0.0.0"),
        ("port", "1"),
        ("enable_prometheus", "true"),
        ("enablePrometheus", "true"),
        ("assets_dir", "/nested-assets"),
        ("assetsDir", "/nested-assets"),
        ("pprof_enable", "true"),
        ("pprofEnable", "true"),
        ("custom_404_page", "<nested-404>"),
        ("custom404Page", "<nested-404>"),
        ("tls_cert_file", "/nested-flat-cert.pem"),
        ("tls_key_file", "/nested-flat-key.pem"),
    ];

    for (key, value) in shapes {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("frps.toml");
        // No parent value at all: this is the shape that used to *invent* a
        // credential/field out of the nested section.
        let body = format!("{HEADER}{PARENT}[web_server.tls]\n{key} = \"{value}\"\n");
        std::fs::write(&path, &body).unwrap();
        let p = path.to_str().unwrap();

        // Strict refuses, naming the true nested path.
        let err = format!("{}", load_server_config(p, true).unwrap_err());
        assert!(
            err.contains(&format!("unknown field \"web_server.tls.{key}\"")),
            "{key}: strict must name the true path, got {err}"
        );

        // Non-strict drops it: the parent fields keep their defaults.
        let cfg = load_server_config(p, false)
            .unwrap_or_else(|e| panic!("{key}: non-strict must load:\n{e}"));
        let ws = &cfg.web_server;
        assert_eq!(ws.user, "", "{key} must not set web_server.user");
        assert_eq!(ws.password, "", "{key} must not set web_server.password");
        assert_eq!(ws.addr, "127.0.0.1", "{key}: addr default");
        assert_eq!(ws.port, 7500, "{key}: the parent port");
        assert!(!ws.enable_prometheus, "{key}");
        assert_eq!(ws.assets_dir, "", "{key}");
        assert!(!ws.pprof_enable, "{key}");
        assert_eq!(ws.custom_404_page, "", "{key}");
        assert_eq!(ws.tls_cert(), "", "{key}");
        assert_eq!(ws.tls_key(), "", "{key}");
    }

    // The item's own shape: nested credentials beside *different* parent
    // credentials keep the parent ones rather than being overwritten (the
    // `or_insert` masked this one before — only the collision-free shapes above
    // were observable, but the guarantee must hold either way).
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("frps.toml");
    std::fs::write(
        &path,
        format!(
            "{HEADER}[web_server]\naddr = \"127.0.0.1\"\nport = 7500\n\
             user = \"parent-user\"\npassword = \"parent-pw\"\n\
             [web_server.tls]\nuser = \"nested-user\"\npassword = \"nested-secret\"\n"
        ),
    )
    .unwrap();
    for strict in [false, true] {
        if strict {
            let err = format!(
                "{}",
                load_server_config(path.to_str().unwrap(), true).unwrap_err()
            );
            assert!(
                err.contains("unknown field \"web_server.tls."),
                "strict names one of the nested keys: got {err}"
            );
        } else {
            let cfg = load_server_config(path.to_str().unwrap(), false).unwrap();
            assert_eq!(cfg.web_server.user, "parent-user");
            assert_eq!(cfg.web_server.password, "parent-pw");
        }
    }

    // Client admin section: same walker, same guarantee.
    let cdir = tempfile::tempdir().unwrap();
    let cpath = cdir.path().join("frpc.toml");
    std::fs::write(
        &cpath,
        "server_addr = \"127.0.0.1\"\nserver_port = 7000\ntoken = \"t\"\n\
         [web_server]\nport = 7400\nuser = \"parent-user\"\n\
         [web_server.tls]\nuser = \"nested-user\"\npassword = \"nested-secret\"\n",
    )
    .unwrap();
    let cfg = load_client_config(cpath.to_str().unwrap(), false).unwrap();
    assert_eq!(cfg.web_server.user, "parent-user");
    assert_eq!(cfg.web_server.password, "");
    let cerr = format!(
        "{}",
        load_client_config(cpath.to_str().unwrap(), true).unwrap_err()
    );
    assert!(
        cerr.contains("unknown field \"web_server.tls."),
        "client strict: got {cerr}"
    );
}

/// A **parent-level** serde alias beside the nested spelling of the same value
/// must still load, with the nested value winning.
///
/// `WebServerConfig::tls_cert_file` (and the other three) carry
/// `#[serde(alias = "certFile")]`, so `[web_server] certFile = "…"` and a hoisted
/// `web_server.tls_cert_file` are the *same field* to serde. The hoist's
/// `insert` used to leave the parent alias in place, and the pair then failed to
/// deserialize in **both** loader modes:
///
/// ```text
/// config validation error: duplicate field `tls_cert_file`
/// ```
///
/// The base tree loaded exactly this shape under `strict = false` (the reload
/// path's mode) with the **flat** value, so that was a new refused start, not a
/// pre-existing defect — for all four destinations, TOML and YAML, server and
/// client (probe kept at `/tmp/wstls-f1/`, `s01`–`s05`, `s07`, `s12`, `s13`,
/// `c01`–`c02`; before/after in `/tmp/wstls-report.md`). Base *did* already fail
/// the `[web_server] certFile` + `[web_server.tls] certFile` shape with the same
/// duplicate (probe `s07`, both modes); the fix closes that too.
///
/// The hoist now removes the parent-level **alias** spelling before inserting,
/// which is what these rows pin. The parent-level *snake* spelling is a
/// different case and is deliberately left alone — see
/// `parent_level_snake_spelling_is_still_reported_in_strict_mode`.
///
/// **What this models.** The five F1 shapes (each destination alone, then all
/// four together), the both-spellings-nested and alias-plus-nested-camel
/// pre-existing duplicates, a YAML alias+nested pair, and a **control** with the
/// parent alias and no nested table — in both loader modes, server and client.
///
/// **What it does not cover.** Go, which has no snake_case spelling to confuse
/// this with (its own `certFile` alias does not exist; the key *is*
/// `certFile`); and the mixed `[webServer]` / `[web_server]` section pair, which
/// now **merges per key** instead of discarding the camelCase table whole — see
/// `both_web_server_sections_merge_per_key_in_both_modes`.
#[test]
fn parent_level_alias_beside_nested_spelling_still_loads() {
    const HEADER: &str = "bind_port = 7000\ntoken = \"t\"\n";
    const WS: &str = "[web_server]\naddr = \"127.0.0.1\"\nport = 7500\n";

    // (name, parent-level alias line(s), nested table, expected cert/key/ca/sn)
    type Case<'a> = (
        &'a str,
        &'a str,
        &'a str,
        (&'a str, &'a str, &'a str, &'a str),
    );
    let nested_all = "[web_server.tls]\ncert_file = \"/nested/cert.pem\"\n\
                      key_file = \"/nested/key.pem\"\ntrusted_ca_file = \"/nested/ca.pem\"\n\
                      server_name = \"nested.example.com\"\n";
    let cases: [Case; 7] = [
        (
            "parent certFile",
            "certFile = \"/parent/cert.pem\"\n",
            "[web_server.tls]\ncert_file = \"/nested/cert.pem\"\n",
            ("/nested/cert.pem", "", "", ""),
        ),
        (
            "parent keyFile",
            "keyFile = \"/parent/key.pem\"\n",
            "[web_server.tls]\nkey_file = \"/nested/key.pem\"\n",
            ("", "/nested/key.pem", "", ""),
        ),
        (
            "parent trustedCaFile",
            "trustedCaFile = \"/parent/ca.pem\"\n",
            "[web_server.tls]\ntrusted_ca_file = \"/nested/ca.pem\"\n",
            ("", "", "/nested/ca.pem", ""),
        ),
        (
            "parent serverName",
            "serverName = \"parent.example.com\"\n",
            "[web_server.tls]\nserver_name = \"nested.example.com\"\n",
            ("", "", "", "nested.example.com"),
        ),
        (
            "all four parent aliases",
            "certFile = \"/parent/cert.pem\"\nkeyFile = \"/parent/key.pem\"\n\
             trustedCaFile = \"/parent/ca.pem\"\nserverName = \"parent.example.com\"\n",
            nested_all,
            (
                "/nested/cert.pem",
                "/nested/key.pem",
                "/nested/ca.pem",
                "nested.example.com",
            ),
        ),
        (
            // The pre-existing duplicate: base failed this in both modes.
            "parent certFile + nested certFile",
            "certFile = \"/parent/cert.pem\"\n",
            "[web_server.tls]\ncertFile = \"/nested/cert.pem\"\n",
            ("/nested/cert.pem", "", "", ""),
        ),
        (
            // The both-spellings-nested shape from the previous round, now with
            // a parent alias on top.
            "parent certFile + both nested spellings",
            "certFile = \"/parent/cert.pem\"\n",
            "[web_server.tls]\ncert_file = \"/snake/cert.pem\"\ncertFile = \"/camel/cert.pem\"\n",
            ("/snake/cert.pem", "", "", ""),
        ),
    ];

    for (name, parent, nested, want) in cases {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("frps.toml");
        std::fs::write(&path, format!("{HEADER}{WS}{parent}{nested}")).unwrap();
        let p = path.to_str().unwrap();
        for strict in [false, true] {
            let cfg = load_server_config(p, strict).unwrap_or_else(|e| {
                panic!(
                    "{name}, strict={strict}: must load (the base tree loaded it non-strict):\n{e}"
                )
            });
            let ws = &cfg.web_server;
            assert_eq!(
                (
                    ws.tls_cert(),
                    ws.tls_key(),
                    ws.tls_ca_file.as_str(),
                    ws.tls_server_name.as_str()
                ),
                want,
                "{name}, strict={strict}: the nested value wins over the parent alias",
            );
        }
    }

    // Control: the parent alias with **no** nested table keeps working.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("frps.toml");
    std::fs::write(
        &path,
        format!("{HEADER}{WS}certFile = \"/flat/cert.pem\"\nkeyFile = \"/flat/key.pem\"\n"),
    )
    .unwrap();
    for strict in [false, true] {
        let cfg = load_server_config(path.to_str().unwrap(), strict).unwrap();
        assert_eq!(
            cfg.web_server.tls_cert(),
            "/flat/cert.pem",
            "strict={strict}"
        );
        assert_eq!(cfg.web_server.tls_key(), "/flat/key.pem", "strict={strict}");
    }

    // YAML: the same shape under Go's section name.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("frps.yaml");
    std::fs::write(
        &path,
        "bind_port: 7000\ntoken: \"t\"\nwebServer:\n  addr: \"127.0.0.1\"\n  port: 7500\n\
         \x20 certFile: \"/parent/cert.pem\"\n  tls:\n    cert_file: \"/nested/cert.pem\"\n",
    )
    .unwrap();
    for strict in [false, true] {
        let cfg = load_server_config(path.to_str().unwrap(), strict).unwrap();
        assert_eq!(
            cfg.web_server.tls_cert(),
            "/nested/cert.pem",
            "strict={strict}"
        );
    }

    // Client: same normalizer, same shape (frpc's admin TLS).
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("frpc.toml");
    std::fs::write(
        &path,
        "server_addr = \"127.0.0.1\"\nserver_port = 7000\ntoken = \"t\"\n\
         [web_server]\naddr = \"127.0.0.1\"\nport = 7400\ncertFile = \"/parent/cert.pem\"\n\
         keyFile = \"/parent/key.pem\"\n\
         [web_server.tls]\ncert_file = \"/nested/cert.pem\"\nkey_file = \"/nested/key.pem\"\n",
    )
    .unwrap();
    for strict in [false, true] {
        let cfg = load_client_config(path.to_str().unwrap(), strict).unwrap();
        assert_eq!(
            cfg.web_server.tls_cert(),
            "/nested/cert.pem",
            "strict={strict}"
        );
        assert_eq!(
            cfg.web_server.tls_key(),
            "/nested/key.pem",
            "strict={strict}"
        );
    }
}

/// A parent-level **snake** spelling (`[web_server] cert_file`) is not a field
/// and must keep being reported as an unknown key by strict mode — the hoist
/// removes only the parent-level `alias`, not every spelling of the group.
///
/// This is the narrower half of the F1 fix, and it is deliberate: removing
/// `cert_file` from the parent as well would silence a legitimate diagnostic for
/// a user who wrote the snake spelling where only `certFile`/`tls_cert_file`
/// exist, and it would also remove a *pre-existing* strict-mode report that the
/// mapping fix has no business touching.
///
/// **Two halves, two different powers** (measured against base `5717fa2`, see
/// `/tmp/wstls-falsify-final.txt`): the strict-mode half has **no
/// discriminating power** — base reports the same `unknown field
/// "web_server.cert_file"` path, because the nested snake spelling was dropped
/// rather than mapped — while the non-strict half **does** fail on base for the
/// `parent snake + nested snake` shape (`tls_cert() == ""` there, because the
/// nested value was dropped; `"/nested/cert.pem"` after the mapping).
///
/// **What this models.** Three shapes in both modes: parent snake + nested Go
/// camelCase, parent snake + nested snake, and parent snake alone.
///
/// **What it does not cover.** The message wording for a *typo* of a mapped
/// spelling (the `did you mean` list is parent-level, so it can suggest
/// `certFile` but never `cert_file`), and the same shape in YAML/JSON/INI.
#[test]
fn parent_level_snake_spelling_is_still_reported_in_strict_mode() {
    const HEADER: &str = "bind_port = 7000\ntoken = \"t\"\n";
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("frps.toml");
    let p = path.to_str().unwrap();

    let shapes = [
        (
            "parent snake + nested camel",
            "[web_server.tls]\ncertFile = \"/nested/cert.pem\"\n",
        ),
        (
            "parent snake + nested snake",
            "[web_server.tls]\ncert_file = \"/nested/cert.pem\"\n",
        ),
        ("parent snake only", ""),
    ];
    for (name, nested) in shapes {
        std::fs::write(
            &path,
            format!(
                "{HEADER}[web_server]\naddr = \"127.0.0.1\"\nport = 7500\n\
                 cert_file = \"/parent/cert.pem\"\n{nested}"
            ),
        )
        .unwrap();
        let err = format!("{}", load_server_config(p, true).unwrap_err());
        assert!(
            err.contains("unknown field \"web_server.cert_file\""),
            "{name}: the parent-level snake spelling is still an unknown key: {err}"
        );
        // Non-strict keeps the old drop, and the nested value (when there is
        // one) still reaches the accessor.
        let cfg = load_server_config(p, false).unwrap_or_else(|e| panic!("{name}: {e}"));
        let want = if nested.is_empty() {
            ""
        } else {
            "/nested/cert.pem"
        };
        assert_eq!(cfg.web_server.tls_cert(), want, "{name}");
    }
}

/// Load a Go legacy INI config through the real INI parser + normalize
/// pipeline (ini_to_toml rejects nothing, so [range:x] headers are legal).
fn load_client_ini(content: &str) -> Result<ClientConfig, Box<dyn std::error::Error>> {
    let mut value = super::format::parse_to_toml_value(content, super::format::ConfigFormat::Ini)?;
    if let Some(table) = value.as_table_mut() {
        super::normalize::canonicalize_legacy_ini_bools(table);
    }
    super::normalize::normalize_client_config(&mut value, super::format::ConfigFormat::Ini)?;
    // `.ini` inputs read values by target type, exactly as
    // `load_config_from_file` does (Go's legacy INI model) — not the strict
    // serde path TOML/JSON/YAML use.
    let mut cfg: ClientConfig =
        super::ini_lenient::deserialize_ini(&super::normalize::toml_to_json(value))
            .map_err(|e| format!("config validation error: {e}"))?;
    super::validate_client_config(&mut cfg)?;
    Ok(cfg)
}

/// Same for server configs.
fn load_server_ini(content: &str) -> Result<ServerConfig, Box<dyn std::error::Error>> {
    let mut value = super::format::parse_to_toml_value(content, super::format::ConfigFormat::Ini)?;
    if let Some(table) = value.as_table_mut() {
        super::normalize::canonicalize_legacy_ini_bools(table);
    }
    super::normalize::normalize_server_config(&mut value, super::format::ConfigFormat::Ini)?;
    let mut cfg: ServerConfig =
        super::ini_lenient::deserialize_ini(&super::normalize::toml_to_json(value))
            .map_err(|e| format!("config validation error: {e}"))?;
    super::validate_server_config(&mut cfg)?;
    Ok(cfg)
}

/// Go legacy INI proxy sections: [web]/[ssh] become [proxies] entries,
/// [range:xxx] expands to per-port proxies, [plugin:xxx] keeps its prefix,
/// and role=visitor sections land in [visitors].
#[test]
fn test_legacy_ini_proxy_sections() {
    let cfg: ClientConfig = load_client_ini(
        r#"server_addr = "127.0.0.1"
server_port = 7000
token = "t"

[web]
type = "http"
local_port = 80
custom_domains = "web.example.com"

[ssh]
type = "tcp"
local_port = 22
remote_port = 6000

[range:test_tcp]
type = "tcp"
local_port = "6000-6002"
remote_port = "16000-16002"

[plugin:http2https]
type = "https"
remote_port = 443
custom_domains = "plugin.example.com"
plugin = "http2https"
plugin_local_addr = "127.0.0.1:80"

[xtcp_visitor]
type = "xtcp"
role = "visitor"
server_name = "xtcp_proxy"
sk = "abc123"
bind_addr = "127.0.0.1"
bind_port = 9000
"#,
    )
    .unwrap();

    let proxies = &cfg.proxies;
    let names: Vec<&str> = proxies.iter().map(|p| p.name.as_str()).collect();
    assert!(names.contains(&"web"), "proxies: {names:?}");
    assert!(names.contains(&"ssh"), "proxies: {names:?}");

    // range:test_tcp expands to test_tcp_0/1/2 with individual ports.
    let range_names: Vec<&str> = names
        .iter()
        .filter(|n| n.starts_with("test_tcp_"))
        .copied()
        .collect();
    assert_eq!(range_names, vec!["test_tcp_0", "test_tcp_1", "test_tcp_2"]);
    let p0 = proxies.iter().find(|p| p.name == "test_tcp_0").unwrap();
    assert_eq!(p0.local_port, 6000);
    assert_eq!(p0.remote_port, 16000);

    // plugin: prefix is kept (Go parity); plugin_* keys nested into plugin.
    let ph = proxies
        .iter()
        .find(|p| p.name == "plugin:http2https")
        .unwrap();
    assert_eq!(ph.proxy_type, "https");
    let plugin = ph.plugin.as_ref().expect("plugin config");
    assert_eq!(plugin.plugin_type, "http2https");
    assert_eq!(plugin.local_addr, "127.0.0.1:80");

    // role=visitor lands in visitors with sk preserved.
    let visitors = &cfg.visitors;
    assert_eq!(visitors.len(), 1, "visitors: {visitors:?}");
    assert_eq!(visitors[0].name, "xtcp_visitor");
    assert_eq!(visitors[0].secret_key, "abc123");
    assert_eq!(visitors[0].bind_port, 9000);
}

/// A Go legacy INI config's flat health-check spellings
/// (`health_check_interval_s` / `health_check_timeout_s`) survive strict mode
/// **and are honoured**. They are valid Go legacy keys — `pkg/config/legacy`
/// declares them (`proxy.go:130,136`) and its conversion maps them onto
/// `HealthCheck.IntervalSeconds` / `.TimeoutSeconds`
/// (`pkg/config/legacy/conversion.go:204-206`) — so a config that loads on Go
/// must load here. Before `check_strict` walked the arrays they were silently
/// dropped; without the rename in `collect_legacy_ini_proxy_sections` the new
/// element walk would refuse the whole file (measured: `frpc verify` rc 1 with
/// `unknown field "proxies[0].health_check_interval_s"` against the version of
/// this branch without the rename).
#[test]
fn test_legacy_ini_health_check_s_spellings_survive_strict_mode() {
    let mut f = tempfile::Builder::new().suffix(".ini").tempfile().unwrap();
    f.write_all(
        b"[common]\nserver_addr = 127.0.0.1\nserver_port = 7000\n\n[tcp]\ntype = tcp\nlocal_port = 8080\nremote_port = 7001\nhealth_check_type = tcp\nhealth_check_interval_s = 7\nhealth_check_timeout_s = 2\n",
    )
    .unwrap();
    let cfg = load_client_config(f.path().to_str().unwrap(), true)
        .expect("a Go legacy INI health-check spelling must load in strict mode");
    assert_eq!(cfg.proxies.len(), 1);
    assert_eq!(cfg.proxies[0].health_check_interval_seconds, 7);
    assert_eq!(cfg.proxies[0].health_check_timeout_seconds, 2);

    // Contrast: the same spelling in a TOML `[[proxies]]` element is not a Go
    // v1 key (v1 has only `healthCheck.intervalSeconds`), so strict mode
    // refuses it there — the rename is scoped to the legacy INI collector.
    let mut t = tempfile::NamedTempFile::new().unwrap();
    t.write_all(
        b"serverAddr = \"127.0.0.1\"\nserverPort = 7000\n[[proxies]]\nname = \"p\"\ntype = \"tcp\"\nlocalPort = 80\nremotePort = 7001\nhealth_check_interval_s = 7\n",
    )
    .unwrap();
    let err = load_client_config(t.path().to_str().unwrap(), true)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("unknown field \"proxies[0].health_check_interval_s\""),
        "got: {err}"
    );
}
/// Go frp v0.71.0's own `conf/legacy/frpc_legacy_full.ini`, copied
/// byte-identically to `frp-core/src/config/fixtures/frpc_legacy_full.ini`
/// (`frp-core/src/config/fixtures/README.md` records the origin and licence).
/// It exercises every legacy INI prefix mechanism Go consumes — `[common]` and
/// `[ssh]` `meta_*`, `[web01] header_*`, and `plugin_header_*` on the three
/// plugin types that read it (`http2https`, `https2http`, `https2https`) — which
/// is exactly the class the strict-mode array walk must not refuse: Go's INI
/// path ignores an INI key its typed struct does not name instead of erroring,
/// so the whole file loads on Go (`frpc verify -c` exits 0).
///
/// The assertion is made at the **strict-check layer** on purpose: what this
/// test's item (#384) changed is the strict check, so the check is what it
/// pins, on the shipped file itself. When it was written the file also carried
/// bare numeric values for string fields (`token = 12345678`,
/// `meta_var1 = 123`) that frp-rs's INI number inference turned into TOML
/// integers serde then rejected — a pre-existing legacy-INI gap unrelated to
/// strict mode. That gap is fixed (`TODO.md:2609`) and the full load is pinned
/// by `legacy_ini_go_shipped_frpc_fixture_loads_end_to_end` below; this test
/// stays as the narrower strict-check pin.
#[test]
fn legacy_ini_go_shipped_fixture_passes_strict_mode() {
    let mut value = super::format::parse_to_toml_value(
        include_str!("fixtures/frpc_legacy_full.ini"),
        super::format::ConfigFormat::Ini,
    )
    .unwrap();
    super::normalize::normalize_client_config(&mut value, super::format::ConfigFormat::Ini)
        .unwrap();
    super::strict::run_strict_check(
        &value,
        &super::strict::known_client_keys(),
        "frpc_legacy_full.ini",
    )
    .expect("Go's shipped legacy INI fixture must not draw a strict-mode refusal");

    // …and the three honoured prefix families must have survived as the keys
    // their Go counterparts fill. A bare "no error" assertion would also pass if
    // the strip pass had dropped them.
    let proxies = value
        .get("proxies")
        .and_then(toml::Value::as_array)
        .expect("proxies array");
    let named = |name: &str| {
        proxies
            .iter()
            .find(|p| p.get("name").and_then(toml::Value::as_str) == Some(name))
            .unwrap_or_else(|| panic!("proxy `{name}` not collected"))
    };
    assert_eq!(
        named("ssh")
            .get("metadatas")
            .and_then(|m| m.get("var1"))
            .and_then(toml::Value::as_integer),
        Some(123),
        "`meta_var1` in a proxy section must be folded into `metadatas`"
    );
    assert_eq!(
        named("web01")
            .get("headers")
            .and_then(|h| h.get("X-From-Where"))
            .and_then(toml::Value::as_str),
        Some("frp"),
        "`header_*` in an http proxy section must be folded into `headers`"
    );
    for name in [
        "plugin_https2http",
        "plugin_https2https",
        "plugin_http2https",
    ] {
        assert_eq!(
            named(name)
                .get("plugin")
                .and_then(|p| p.get("request_headers"))
                .and_then(|h| h.get("X-From-Where"))
                .and_then(toml::Value::as_str),
            Some("frp"),
            "`plugin_header_*` on `{name}` must be folded into the plugin's \
             `request_headers`"
        );
    }
}

/// Go frp v0.71.0's own `conf/legacy/frpc_legacy_full.ini` (vendored
/// byte-identically), loaded **end to end** through the real client config
/// path with strict mode on — the assertion `legacy_ini_go_shipped_fixture_passes_strict_mode`
/// deliberately could not make before `TODO.md:2609` was closed.
///
/// Every expected name and count here is Go's own, measured on the real
/// v0.71.0 binary: Go frpc + Go frps with the same file (only
/// `server_addr`/`server_port`/`admin_port` swapped for free ports — every
/// other byte unchanged) logs
/// `proxy added: [dns p2p_tcp plugin_http2https … web01 web02]` (43 names) and
/// `visitor added: [p2p_tcp_visitor secret_tcp_visitor]`.
///
/// `[range:tcp_port]`'s `local_port = 6010-6020,6022,6024-6028` is 17 numbers
/// (Go `pkg/util/util/util.go:71` splits on `,`;
/// `pkg/config/legacy/client.go:314-336` renders one proxy per number).
#[test]
fn legacy_ini_go_shipped_frpc_fixture_loads_end_to_end() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/config/fixtures/frpc_legacy_full.ini"
    );
    let cfg = load_client_config(path, true)
        .expect("Go's shipped legacy frpc INI fixture must load end to end in strict mode");

    let mut names: Vec<&str> = cfg.proxies.iter().map(|p| p.name.as_str()).collect();
    names.sort_unstable();
    let expected: &[&str] = &[
        "dns",
        "p2p_tcp",
        "plugin_http2https",
        "plugin_http_proxy",
        "plugin_https2http",
        "plugin_https2https",
        "plugin_socks5",
        "plugin_static_file",
        "plugin_unix_domain_socket",
        "secret_tcp",
        "ssh",
        "ssh_random",
        "tcp_port_0",
        "tcp_port_1",
        "tcp_port_10",
        "tcp_port_11",
        "tcp_port_12",
        "tcp_port_13",
        "tcp_port_14",
        "tcp_port_15",
        "tcp_port_16",
        "tcp_port_2",
        "tcp_port_3",
        "tcp_port_4",
        "tcp_port_5",
        "tcp_port_6",
        "tcp_port_7",
        "tcp_port_8",
        "tcp_port_9",
        "tcpmuxhttpconnect",
        "udp_port_0",
        "udp_port_1",
        "udp_port_10",
        "udp_port_2",
        "udp_port_3",
        "udp_port_4",
        "udp_port_5",
        "udp_port_6",
        "udp_port_7",
        "udp_port_8",
        "udp_port_9",
        "web01",
        "web02",
    ];
    assert_eq!(names, expected, "proxy name set");
    assert_eq!(cfg.proxies.len(), 43);

    let mut visitors: Vec<&str> = cfg.visitors.iter().map(|v| v.name.as_str()).collect();
    visitors.sort_unstable();
    assert_eq!(visitors, ["p2p_tcp_visitor", "secret_tcp_visitor"]);
    let stcp_visitor = cfg
        .visitors
        .iter()
        .find(|v| v.name == "secret_tcp_visitor")
        .expect("secret_tcp_visitor");
    assert_eq!(stcp_visitor.visitor_type, "stcp");
    assert_eq!(stcp_visitor.server_name, "secret_tcp");
    assert_eq!(stcp_visitor.secret_key, "abcdefg");
    assert_eq!(stcp_visitor.bind_addr, "127.0.0.1");
    assert_eq!(stcp_visitor.bind_port, 9000, "visitor-only key survives");
    let xtcp_visitor = cfg
        .visitors
        .iter()
        .find(|v| v.name == "p2p_tcp_visitor")
        .expect("p2p_tcp_visitor");
    assert_eq!(xtcp_visitor.bind_port, 9001, "visitor-only key survives");
    assert_eq!(xtcp_visitor.server_user, "user1");
    assert!(!xtcp_visitor.keep_tunnel_open);
    assert_eq!(xtcp_visitor.max_retries_an_hour, 8);
    assert_eq!(xtcp_visitor.min_retry_interval, 90);

    // Value inference (TODO.md:2609 class 1): a bare numeric `token` and a bare
    // numeric `meta_*` are text on Go, not integers — Go's `frpc verify -c`
    // exits 0 and the token is the string `12345678`.
    assert_eq!(cfg.token, "12345678");
    assert_eq!(cfg.metas.get("var1").map(String::as_str), Some("123"));
    assert_eq!(cfg.metas.get("var2").map(String::as_str), Some("234"));

    let named = |name: &str| {
        cfg.proxies
            .iter()
            .find(|p| p.name == name)
            .unwrap_or_else(|| panic!("proxy `{name}`"))
    };
    let ssh = named("ssh");
    assert_eq!(ssh.group_key, "123456", "a numeric string field");
    assert_eq!(
        ssh.metas.get("var1").map(String::as_str),
        Some("123"),
        "`meta_*` folded into the proxy map as text"
    );
    assert_eq!(ssh.bandwidth_limit, "1MB");
    assert_eq!(ssh.health_check_interval_seconds, 10);

    // Class 2: the comma list expands to Go's per-port proxies.
    let tcp_ports: Vec<u16> = (0..17)
        .map(|i| named(&format!("tcp_port_{i}")).local_port)
        .collect();
    let mut expected_ports: Vec<u16> = (6010..=6020).collect();
    expected_ports.push(6022);
    expected_ports.extend(6024..=6028);
    assert_eq!(tcp_ports, expected_ports);
    assert_eq!(named("tcp_port_16").remote_port, 6028);
    let udp_ports: Vec<u16> = (0..11)
        .map(|i| named(&format!("udp_port_{i}")).local_port)
        .collect();
    assert_eq!(udp_ports, (6010..=6020).collect::<Vec<u16>>());
}

/// The same for Go's `conf/legacy/frps_legacy_full.ini` (vendored
/// byte-identically): Go `frps verify -c` exits 0 with
/// `allow_ports = 2000-3000,3001,3003,4000-50000` read as the *string*
/// (`pkg/config/legacy/server.go:243-247`), and `token = 12345678` as the
/// string `12345678`.
///
/// `frps` had no `verify` subcommand in frp-rs when this pin was written (the
/// `TODO.md` item "Go has `frps verify`, frp-rs has no `frps verify` at all",
/// since closed), so it loads through the same `load_server_config` the daemon
/// calls. That entry point is still the one `frps verify` uses — the subcommand
/// adds Go's line and stream around it, not a second loader — so this pin
/// describes both surfaces.
#[test]
fn legacy_ini_go_shipped_frps_fixture_loads_end_to_end() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/config/fixtures/frps_legacy_full.ini"
    );
    let cfg = load_server_config(path, true)
        .expect("Go's shipped legacy frps INI fixture must load end to end in strict mode");

    assert_eq!(cfg.auth.token, "12345678", "numeric `token` read as text");
    assert_eq!(cfg.auth.method, "token");
    assert_eq!(cfg.allow_ports, "2000-3000,3001,3003,4000-50000");
    assert_eq!(cfg.bind_port, 7000);
    assert_eq!(cfg.log.max_days, 3, "numeric INI field still parses");
    assert_eq!(cfg.sub_domain_host, "frps.com");
    assert_eq!(cfg.nat_hole_analysis_data_reserve_hours, 168);
    assert_eq!(cfg.transport.max_pool_count, 5);

    let mut plugins: Vec<&str> = cfg.http_plugins.iter().map(|p| p.name.as_str()).collect();
    plugins.sort_unstable();
    assert_eq!(plugins, ["port-manager", "user-manager"]);
    let user_manager = cfg
        .http_plugins
        .iter()
        .find(|p| p.name == "user-manager")
        .expect("user-manager");
    assert_eq!(user_manager.ops, ["Login"]);
    assert_eq!(user_manager.addr, "127.0.0.1:9000");
}

/// `TODO.md:2609` class 2, on a constructed case: the trigger for the dropped
/// section is the **comma list**, not the range.
///
/// Measured on Go v0.71.0 (Go frps + Go frpc, `GET /api/proxy/tcp`):
/// `local_port = 6010-6012` registers `x_0`…`x_2` (3);
/// `local_port = 6010-6012,6020` registers `x_0`…`x_3` (4). frp-rs used to
/// report `Proxies: 0` plus
/// `WARN … legacy INI [range:...] section: missing or invalid local_port; skipped`
/// for the second, because `ini_to_toml` split the list into a TOML array that
/// `ini_port_numbers` did not accept.
#[test]
fn test_legacy_ini_range_comma_list_expands_to_go_count() {
    let simple = load_client_ini(
        "[common]\n\
         server_addr = 127.0.0.1\n\
         server_port = 7000\n\
         [range:x]\n\
         type = tcp\n\
         local_port = 6010-6012\n\
         remote_port = 7010-7012\n",
    )
    .unwrap();
    let mut names: Vec<&str> = simple.proxies.iter().map(|p| p.name.as_str()).collect();
    names.sort_unstable();
    assert_eq!(names, ["x_0", "x_1", "x_2"]);

    let comma = load_client_ini(
        "[common]\n\
         server_addr = 127.0.0.1\n\
         server_port = 7000\n\
         [range:x]\n\
         type = tcp\n\
         local_port = 6010-6012,6020\n\
         remote_port = 7010-7012,7020\n",
    )
    .unwrap();
    let mut names: Vec<&str> = comma.proxies.iter().map(|p| p.name.as_str()).collect();
    names.sort_unstable();
    assert_eq!(names, ["x_0", "x_1", "x_2", "x_3"]);
    assert_eq!(
        comma.proxies[3].local_port, 6020,
        "the element after a range is expanded, not dropped"
    );
    assert_eq!(comma.proxies[3].remote_port, 7020);
}

/// `TODO.md:2609` class 3: Go dispatches a `[range:...]` template on `role`
/// **after** expanding it (`pkg/config/legacy/client.go:252-285`), so
/// `role = visitor` builds visitors. Measured on Go v0.71.0: a `6010-6012`
/// range with `role = visitor` logs `visitor added: [rv_0 rv_1 rv_2]`; frp-rs
/// used to report `Proxies: 3 Visitors: 0` and strip `bind_addr`/`bind_port`/
/// `server_name` with them (the elements were stripped against the *proxy*
/// key set).
#[test]
fn test_legacy_ini_range_role_visitor_builds_visitors() {
    let cfg = load_client_ini(
        "[common]\n\
         server_addr = 127.0.0.1\n\
         server_port = 7000\n\
         [range:rv]\n\
         type = stcp\n\
         role = visitor\n\
         server_name = missing_proxy\n\
         sk = abc\n\
         bind_addr = 127.0.0.1\n\
         bind_port = 6000\n\
         local_port = 6010-6012\n\
         remote_port = 7010-7012\n",
    )
    .unwrap();
    assert!(cfg.proxies.is_empty(), "a visitor template is not a proxy");
    let mut names: Vec<&str> = cfg.visitors.iter().map(|v| v.name.as_str()).collect();
    names.sort_unstable();
    assert_eq!(names, ["rv_0", "rv_1", "rv_2"]);
    for visitor in &cfg.visitors {
        assert_eq!(visitor.visitor_type, "stcp");
        assert_eq!(visitor.server_name, "missing_proxy");
        assert_eq!(visitor.secret_key, "abc");
        assert_eq!(visitor.bind_addr, "127.0.0.1");
        assert_eq!(
            visitor.bind_port, 6000,
            "the template's visitor-only keys must survive the strip pass"
        );
    }
}

/// `TODO.md:2609` class 1, the smallest form: an INI value that the lossless
/// reader infers as a non-string is read back **as text** by a string-typed
/// field, and the same value is still read as a number/boolean by a
/// numeric/boolean field (the trap: a blanket "keep every INI value as a
/// string" would break `bind_port = 7000` and `log_max_days = 3`).
#[test]
fn test_legacy_ini_values_are_read_by_target_type() {
    let cfg = load_client_ini(
        "[common]\n\
         server_addr = 127.0.0.1\n\
         server_port = 7000\n\
         token = 12345678\n\
         meta_var1 = 123\n\
         log_max_days = 3\n\
         tcp_mux = no\n\
         pool_count = 5\n\
         [tcp]\n\
         type = tcp\n\
         local_port = 8080\n\
         remote_port = 7001\n\
         group_key = 123456\n\
         bandwidth_limit = 1MB\n",
    )
    .unwrap();
    assert_eq!(cfg.token, "12345678");
    assert_eq!(cfg.metas.get("var1").map(String::as_str), Some("123"));
    assert_eq!(cfg.server_port, 7000, "numeric field still numeric");
    assert_eq!(cfg.log.max_days, 3, "numeric field still numeric");
    assert_eq!(cfg.pool_count, 5, "numeric field still numeric");
    assert!(!cfg.tcp_mux, "`no` still reads as a false boolean");
    assert_eq!(cfg.proxies[0].local_port, 8080);
    assert_eq!(cfg.proxies[0].remote_port, 7001);
    assert_eq!(cfg.proxies[0].group_key, "123456");
    assert_eq!(cfg.proxies[0].bandwidth_limit, "1MB");

    // The spellings Go's `ini.v1.parseBool` accepts (`key.go:194`) but the
    // inference no longer rewrites.
    let cfg = load_client_ini("[common]\nserver_addr = 127.0.0.1\ntcp_mux = OFF\n").unwrap();
    assert!(!cfg.tcp_mux);
    let cfg = load_client_ini("[common]\nserver_addr = 127.0.0.1\ntcp_mux = yes\n").unwrap();
    assert!(cfg.tcp_mux);
    // `1`/`0` are Go's `parseBool` spellings too, and reach the field as the
    // inferred integer rather than as text.
    let cfg = load_client_ini("[common]\nserver_addr = 127.0.0.1\ntcp_mux = 1\n").unwrap();
    assert!(cfg.tcp_mux);
    let cfg = load_client_ini("[common]\nserver_addr = 127.0.0.1\ntcp_mux = 0\n").unwrap();
    assert!(!cfg.tcp_mux);
    // The legacy `authenticate_heartbeats` -> additional_auth_scopes pass has
    // the same spelling set (it is a Go bool field).
    let cfg = load_client_ini("[common]\nserver_addr = 127.0.0.1\nauthenticate_heartbeats = 1\n")
        .unwrap();
    assert_eq!(
        cfg.auth
            .as_ref()
            .map(|a| a.additional_auth_scopes.clone())
            .unwrap_or_default(),
        ["HeartBeats"]
    );
    // …and a string-typed field keeps the spelling the file wrote.
    let cfg = load_client_ini("[common]\nserver_addr = 127.0.0.1\ntoken = YES\n").unwrap();
    assert_eq!(cfg.token, "YES");

    // Extreme magnitudes: serde_json's `ryu` rendering is exponential where
    // Rust's `f64` Display is not (`1e+19` / `1e-7`), so the reader keeps these
    // as text and a string field gets the file's text, not a re-rendering.
    // Measured on Go v0.71.0: the token `10000000000000000000` logs in against
    // a Go frps whose `auth.token` is that string.
    let cfg = load_client_ini(
        "[common]\nserver_addr = 127.0.0.1\nserver_port = 7000\n\
         token = 10000000000000000000\nmeta_id = 0.0000001\n",
    )
    .unwrap();
    assert_eq!(cfg.token, "10000000000000000000");
    assert_eq!(cfg.metas.get("id").map(String::as_str), Some("0.0000001"));

    // An INI value that is not a number at all still fails a numeric field.
    let err = load_client_ini("[common]\nserver_addr = 127.0.0.1\nserver_port = abc\n")
        .unwrap_err()
        .to_string();
    assert!(err.contains("config validation error"), "got: {err}");
}

/// Go splits a slice field with `Key.Strings(",")` (`key.go:492`): trim each
/// element, `\,` is a literal comma, and a trailing empty element is dropped.
/// Measured on Go v0.71.0 (`custom_domains`, `GET /api/proxy/http`): `a\,b` →
/// `["a,b"]`, `x\,y,z` → `["x,y", "z"]`, `a.example.com,` → `["a.example.com"]`.
/// Base and the first cut of this fix split naively, giving
/// `["a\\", "b"]` and `["a.example.com", ""]`.
#[test]
fn test_legacy_ini_slice_values_use_go_strings_semantics() {
    for (value, expected) in [
        (r"a\,b", vec!["a,b"]),
        (r"x\,y,z", vec!["x,y", "z"]),
        ("a.example.com,", vec!["a.example.com"]),
        (
            "a.example.com, b.example.com",
            vec!["a.example.com", "b.example.com"],
        ),
        ("a,b", vec!["a", "b"]),
    ] {
        let cfg = load_client_ini(&format!(
            "[common]\nserver_addr = 127.0.0.1\n[web]\ntype = http\nlocal_port = 8080\n\
             custom_domains = {value}\n"
        ))
        .unwrap();
        assert_eq!(cfg.proxies[0].custom_domains, expected, "value `{value}`");
        // A *string* field reading the same value gets the file's text.
        let cfg = load_client_ini(&format!(
            "[common]\nserver_addr = 127.0.0.1\ntoken = {value}\n"
        ))
        .unwrap();
        assert_eq!(cfg.token, value, "string field for `{value}`");
    }
}

/// The legacy-INI boolean conversion (`authenticate_heartbeats` /
/// `authenticate_new_work_conns` → `[auth] additional_auth_scopes`, Go
/// `pkg/config/legacy/conversion.go:31-36,92-97`; the fields are
/// `pkg/auth/legacy/legacy.go:25,28` bools read with `Key.Bool()`) accepts Go's
/// wider `parseBool` spelling set for **`.ini` only**.
///
/// The server enforces these scopes (`frp-server/src/control/proxy.rs:418-425`),
/// so applying the wider set in every format — as the first cut of this fix did
/// through a format-agnostic `ini_truthy` — silently changed the meaning of a
/// TOML/JSON/YAML config that base ignored. These rows go through the **real
/// file loader** (`load_client_config`, which detects the format from the
/// extension), not a test helper, so the format gate itself is pinned: with the
/// gate removed the TOML/JSON/YAML rows flip to `["HeartBeats"]` and fail.
#[test]
fn test_legacy_ini_bool_scopes_are_ini_only() {
    fn scopes(cfg: &ClientConfig) -> Vec<String> {
        cfg.auth
            .as_ref()
            .map(|a| a.additional_auth_scopes.clone())
            .unwrap_or_default()
    }
    fn load(suffix: &str, body: &str) -> ClientConfig {
        let mut f = tempfile::Builder::new().suffix(suffix).tempfile().unwrap();
        f.write_all(body.as_bytes()).unwrap();
        f.flush().unwrap();
        load_client_config(f.path().to_str().unwrap(), true).unwrap()
    }

    // `.ini`: Go's spellings apply.
    let ini = load(
        ".ini",
        "[common]\nserver_addr = 127.0.0.1\n\
         authenticate_heartbeats = 1\nauthenticate_new_work_conns = yes\n",
    );
    assert_eq!(scopes(&ini), ["HeartBeats", "NewWorkConns"]);

    // The other formats: the same spellings stay ignored, exactly as at base.
    let toml = load(
        ".toml",
        "server_addr = \"127.0.0.1\"\nauthenticate_heartbeats = 1\n\
         authenticate_new_work_conns = \"yes\"\n",
    );
    assert!(
        scopes(&toml).is_empty(),
        "a non-boolean spelling in TOML must stay ignored (base behaviour)"
    );
    let json = load(
        ".json",
        r#"{"serverAddr": "127.0.0.1", "authenticate_heartbeats": 1}"#,
    );
    assert!(scopes(&json).is_empty(), "JSON");
    let yaml = load(
        ".yaml",
        "server_addr: 127.0.0.1\nauthenticate_new_work_conns: \"yes\"\n",
    );
    assert!(scopes(&yaml).is_empty(), "YAML");

    // The pre-existing *boolean* spelling maps in every format (an frp-rs
    // extension; Go's v1 decoder refuses the key outside `.ini`).
    let toml = load(
        ".toml",
        "server_addr = \"127.0.0.1\"\nauthenticate_heartbeats = true\n",
    );
    assert_eq!(scopes(&toml), ["HeartBeats"]);
    let ini = load(
        ".ini",
        "[common]\nserver_addr = 127.0.0.1\nauthenticate_heartbeats = false\n",
    );
    assert!(scopes(&ini).is_empty());
}

/// The array spelling of the same port list — a TOML/JSON config may write the
/// legacy-shaped section with a real array, and `[range:...]`'s
/// `local/remote_port` must accept it just like the comma list
/// (`TODO.md:2609`'s "let `ini_port_numbers` accept the split array").
#[test]
fn test_legacy_ini_range_port_list_accepts_an_array() {
    let cfg = load_client_config_from_json(
        r#"{
          "serverAddr": "127.0.0.1",
          "serverPort": 7000,
          "range:x": {
            "type": "tcp",
            "local_port": [6010, "6011-6012"],
            "remote_port": [7010, 7011, 7012]
          }
        }"#,
    )
    .unwrap();
    let mut names: Vec<&str> = cfg.proxies.iter().map(|p| p.name.as_str()).collect();
    names.sort_unstable();
    assert_eq!(names, ["x_0", "x_1", "x_2"]);
    assert_eq!(cfg.proxies[0].local_port, 6010);
    assert_eq!(cfg.proxies[1].local_port, 6011);
    assert_eq!(cfg.proxies[2].local_port, 6012);
}

/// Every legacy INI prefix mechanism Go reads, loaded end to end through strict
/// mode (the values here were once quoted so they survived the INI reader's
/// number inference; since the reader became lossless and `.ini` values are
/// read by the target field's type, quoting is no longer needed — the
/// unquoted spellings are covered by
/// `test_legacy_ini_values_are_read_by_target_type`):
///
/// * `meta_*` → `metadatas` (`pkg/config/legacy/proxy.go:198`);
/// * `header_*` → HTTP request headers, for `type = "http"` only
///   (`proxy.go:244`; the HTTPS/TCP structs have no `Headers` field);
/// * `plugin_header_*` → the plugin's `request_headers` for the three plugin
///   types whose conversion calls `transformHeadersFromPluginParams`
///   (`conversion.go:171-181,217,228,236`);
/// * the flat `health_check_*_s` spellings (see the dedicated test below).
#[test]
fn legacy_ini_prefix_mechanisms_load_through_strict_mode() {
    let mut f = tempfile::Builder::new().suffix(".ini").tempfile().unwrap();
    f.write_all(
        br#"[common]
server_addr = 127.0.0.1
server_port = 7000

[web]
type = http
local_port = 8080
custom_domains = a.example.com
header_X-Foo = bar

[gh]
type = tcp
local_port = 8080
remote_port = 7001
meta_env = prod

[pl]
type = tcp
remote_port = 7002
plugin = https2http
plugin_local_addr = 127.0.0.1:80
plugin_crt_path = a.crt
plugin_key_path = a.key
plugin_header_X-Plugin = bar
"#,
    )
    .unwrap();
    let cfg = load_client_config(f.path().to_str().unwrap(), true)
        .expect("every Go legacy prefix mechanism must load in strict mode");
    let named = |name: &str| cfg.proxies.iter().find(|p| p.name == name).unwrap();
    assert_eq!(
        named("web").headers.get("X-Foo").map(String::as_str),
        Some("bar"),
        "header_* -> headers"
    );
    assert_eq!(
        named("gh").metas.get("env").map(String::as_str),
        Some("prod"),
        "meta_* -> metadatas"
    );
    assert_eq!(
        named("pl")
            .plugin
            .as_ref()
            .unwrap()
            .request_headers
            .get("X-Plugin")
            .map(String::as_str),
        Some("bar"),
        "plugin_header_* -> plugin request_headers"
    );
}

/// The keys Go's legacy layer **ignores** (its typed structs never name them,
/// and `gopkg.in/ini`'s `MapTo` skips what it cannot map) must not be refused
/// either — Go loads every config below with exit 0. The legacy collector drops
/// them before the strict walk, so the v1 `[[proxies]]` check stays strict while
/// the legacy INI surface keeps Go's accept-and-ignore semantics.
#[test]
fn legacy_ini_ignores_keys_go_ignores() {
    let mut f = tempfile::Builder::new().suffix(".ini").tempfile().unwrap();
    f.write_all(
        br#"[common]
server_addr = 127.0.0.1
server_port = 7000

[p]
type = tcp
local_port = 8080
remote_port = 7001
log_level = debug
privilege_mode = true
pool_count = 5
plugin = http_proxy
plugin_unknown_param = 1
plugin_enable_http2 = true

[v]
type = stcp
role = visitor
server_name = p
sk = abc
bind_port = 6000
meta_foo = bar
header_X-Foo = bar
"#,
    )
    .unwrap();
    let cfg = load_client_config(f.path().to_str().unwrap(), true)
        .expect("keys Go's legacy layer ignores must not be refused");
    assert_eq!(cfg.proxies.len(), 1);
    assert_eq!(cfg.proxies[0].name, "p");
    // The ignored keys must be *gone*, not silently honoured: `log_level` etc.
    // are client-level keys, and `plugin_enable_http2` is not a Go or frp-rs
    // plugin parameter (the v1 spelling is `enable_http2`).
    let plugin = cfg.proxies[0].plugin.as_ref().expect("plugin parsed");
    assert_eq!(plugin.plugin_type, "http_proxy");
    assert_eq!(plugin.enable_http2, None);
    assert_eq!(cfg.visitors.len(), 1);
    assert_eq!(cfg.visitors[0].name, "v");
}

/// Go's legacy INI struct declares only the `_s` health-check spellings
/// (`pkg/config/legacy/proxy.go:130,136`), so `health_check_interval_seconds` is
/// an unknown INI key there and is ignored. Measured on Go v0.71.0 with a real
/// frps+frpc pair and a dead local port (health-check log gaps): `_s = 2` alone
/// → a check every 2.0 s; `_seconds = 2` alone → one check and then the 10 s
/// default; `_s = 2` + `_seconds = 99` → every 2.0 s; `_s = 99` + `_seconds = 2`
/// → one check. The `_s` value therefore wins in both orders, which is what the
/// rewrite in `collect_legacy_ini_proxy_sections` implements (`insert`, not
/// `or_insert`).
#[test]
fn legacy_ini_health_check_s_wins_over_seconds() {
    let mut f = tempfile::Builder::new().suffix(".ini").tempfile().unwrap();
    f.write_all(
        br#"[common]
server_addr = 127.0.0.1
server_port = 7000

[tcp]
type = tcp
local_port = 8080
remote_port = 7001
health_check_type = tcp
health_check_interval_s = 7
health_check_interval_seconds = 99
health_check_timeout_s = 2
health_check_timeout_seconds = 88
"#,
    )
    .unwrap();
    let cfg = load_client_config(f.path().to_str().unwrap(), true).unwrap();
    assert_eq!(
        cfg.proxies[0].health_check_interval_seconds, 7,
        "the Go-honoured `_s` spelling wins over the frp-rs-only `_seconds` one"
    );
    assert_eq!(
        cfg.proxies[0].health_check_timeout_seconds, 2,
        "same for the timeout pair"
    );
}

/// Strict mode walks a proxy's health-check header array under **both** serde
/// spellings. `healthCheckHttpHeaders` is an alias not renamed by
/// `normalize_proxies`, so it reaches the check as its own key; without the
/// alias arm here the unknown key was accepted under the alias while the
/// canonical `health_check_http_headers` spelling refused it.
#[test]
fn strict_mode_rejects_unknown_health_check_header_via_both_spellings() {
    for spelling in ["health_check_http_headers", "healthCheckHttpHeaders"] {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(
            format!(
                "serverAddr = \"127.0.0.1\"\nserverPort = 7000\n[[proxies]]\nname = \"p\"\ntype = \"tcp\"\nlocalPort = 80\nremotePort = 7001\n\
                 [[proxies.healthCheck]]\ntype = \"tcp\"\nintervalSeconds = 10\n\
                 [[proxies.{spelling}]]\nname = \"X-Test\"\nvalue = \"1\"\nnotAKnownHeaderKey = 1\n"
            )
            .as_bytes(),
        )
        .unwrap();
        let err = load_client_config(f.path().to_str().unwrap(), true)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains(&format!(
                "unknown field \"proxies[0].{spelling}[0].notAKnownHeaderKey\""
            )),
            "[{spelling}] got: {err}"
        );
    }
}

/// The legacy `plugin_header_*` fold is gated on elements the **legacy
/// collector** created, so it cannot widen the v1 surface. On a TOML
/// `[[proxies]]` element the flat plugin spelling is an frp-rs extension Go
/// rejects outright (v1's `plugin` is an object: `json: cannot unmarshal string
/// into … plugin`), and the header key itself was dropped at the base commit and
/// refused at the round-1 head — folding it there would silently start honouring
/// a key that is not a v1 name. Measured three ways at the round-3 head:
/// Go rc 1 (`cannot unmarshal string into … plugin`), frp-rs before
/// `Config file … is valid` (key dropped), frp-rs now
/// `unknown field "proxies[0].plugin.plugin_header_X-Foo"`. The legacy-shaped
/// section form is covered (and its value asserted) by
/// `legacy_ini_prefix_mechanisms_load_through_strict_mode`.
#[test]
fn toml_proxy_element_does_not_inherit_the_legacy_plugin_header_fold() {
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(
        b"serverAddr = \"127.0.0.1\"\nserverPort = 7000\n[[proxies]]\nname = \"p\"\ntype = \"tcp\"\nremotePort = 7001\n\
          plugin = \"https2http\"\nplugin_local_addr = \"127.0.0.1:80\"\nplugin_crt_path = \"a.crt\"\nplugin_key_path = \"a.key\"\nplugin_header_X-Foo = \"y\"\n",
    )
    .unwrap();
    let err = load_client_config(f.path().to_str().unwrap(), true)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("unknown field \"proxies[0].plugin.plugin_header_X-Foo\""),
        "the v1 element must not fold the legacy plugin header spelling; got: {err}"
    );
}

/// Legacy INI range template with mismatched port counts is skipped (warn),
/// not fatal, and does not corrupt the remaining proxies.
#[test]
fn test_legacy_ini_range_mismatch_skipped() {
    let cfg: ClientConfig = load_client_ini(
        r#"server_addr = "127.0.0.1"
server_port = 7000

[good]
type = "tcp"
local_port = 8080
remote_port = 8081

[range:bad]
type = "tcp"
local_port = "6000-6002"
remote_port = "16000"
"#,
    )
    .unwrap();
    let names: Vec<&str> = cfg.proxies.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(names, vec!["good"]);
}

/// Legacy INI range template whose port expression would expand beyond the
/// per-call cap (L12: "0-65535" → 65536 numbers) is skipped, not fatal —
/// same as any other invalid local_port.
#[test]
fn test_legacy_ini_range_huge_expansion_skipped() {
    let cfg: ClientConfig = load_client_ini(
        r#"server_addr = "127.0.0.1"
server_port = 7000

[good]
type = "tcp"
local_port = 8080
remote_port = 8081

[range:huge]
type = "tcp"
local_port = "0-65535"
remote_port = "0-65535"
"#,
    )
    .unwrap();
    let names: Vec<&str> = cfg.proxies.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(names, vec!["good"]);
}

/// A known top-level section carrying a `type` key is NOT collected as a
/// legacy INI proxy (KNOWN_SECTIONS guard).
#[test]
fn test_legacy_ini_known_section_with_type_not_collected() {
    let cfg: ClientConfig = load_client_ini(
        r#"server_addr = "127.0.0.1"
server_port = 7000

[log]
type = "custom"
disable_print_color = true

[real_proxy]
type = "tcp"
local_port = 8080
remote_port = 8081
"#,
    )
    .unwrap();
    // [log] with a type key stays a log section (not a proxy);
    // [real_proxy] is collected normally.
    assert_eq!(cfg.proxies.len(), 1, "proxies: {:?}", cfg.proxies);
    assert_eq!(cfg.proxies[0].name, "real_proxy");
    assert!(cfg.log.disable_print_color);
}

/// httpHeaders in legacy map form ({X = "y"}) is converted to the canonical
/// [{name,value}] array (Vec<HealthCheckHttpHeader>).
#[test]
fn test_health_headers_map_form_converted() {
    let cfg: ClientConfig = load_client_config_from_str(
        r#"server_addr = "127.0.0.1"
server_port = 7000

[[proxies]]
name = "web"
type = "http"
local_port = 8080
custom_domains = ["web.example.com"]

[proxies.healthCheck]
type = "http"
url = "http://127.0.0.1/"
httpHeaders = { X-Token = "abc", X-Other = "def" }
"#,
    )
    .unwrap();
    let hdrs = &cfg.proxies[0].health_check_http_headers;
    let mut pairs: Vec<(String, String)> = hdrs
        .iter()
        .map(|h| (h.name.clone(), h.value.clone()))
        .collect();
    pairs.sort();
    assert_eq!(
        pairs,
        vec![
            ("X-Other".to_string(), "def".to_string()),
            ("X-Token".to_string(), "abc".to_string()),
        ]
    );
}

/// [range:...] with an unquoted single port (Integer) expands like Go
/// ParseRangeNumbers, instead of being skipped.
#[test]
fn test_legacy_ini_range_unquoted_single_port() {
    let cfg: ClientConfig = load_client_ini(
        r#"server_addr = "127.0.0.1"
server_port = 7000

[range:single]
type = "tcp"
local_port = 6000
remote_port = 16000
"#,
    )
    .unwrap();
    assert_eq!(cfg.proxies.len(), 1);
    assert_eq!(cfg.proxies[0].name, "single_0");
    assert_eq!(cfg.proxies[0].local_port, 6000);
    assert_eq!(cfg.proxies[0].remote_port, 16000);
}

/// Go legacy INI server keys: authentication_method -> [auth].method (the
/// BLOCKER from the audit — OIDC silently fell back to token), server-side
/// authenticate_* -> additional_auth_scopes, top-level tcp_keepalive and
/// quic_* -> [transport], and [plugin.xxx] sections -> http_plugins.
#[test]
fn test_legacy_ini_server_gaps_round2() {
    let cfg: ServerConfig = load_server_ini(
        r#"bind_port = 7000
authentication_method = oidc
authenticate_heartbeats = true
authenticate_new_work_conns = true
tcp_keepalive = 7200
quic_keepalive_period = 15
quic_max_idle_timeout = 45
quic_max_incoming_streams = 200

[plugin.http_proxy]
addr = "127.0.0.1:8888"
path = "/handler"
ops = ["login"]

[plugin.static_file]
addr = "http://127.0.0.1:9999"
"#,
    )
    .unwrap();
    assert_eq!(cfg.auth.method, "oidc");
    let scopes = cfg.auth.additional_auth_scopes;
    assert!(
        scopes.contains(&"HeartBeats".to_string()),
        "scopes: {scopes:?}"
    );
    assert!(
        scopes.contains(&"NewWorkConns".to_string()),
        "scopes: {scopes:?}"
    );
    assert_eq!(cfg.transport.tcp_keepalive, 7200);
    let quic = cfg.transport.quic_options.as_ref().expect("quic options");
    assert_eq!(quic.keepalive_period, 15);
    assert_eq!(quic.max_idle_timeout, 45);
    assert_eq!(quic.max_incoming_streams, 200);
    assert_eq!(cfg.http_plugins.len(), 2);
    let hp = cfg
        .http_plugins
        .iter()
        .find(|p| p.name == "http_proxy")
        .unwrap();
    assert_eq!(hp.addr, "127.0.0.1:8888");
    assert_eq!(hp.path, "/handler");
    assert_eq!(hp.ops, vec!["login"]);
    let sf = cfg
        .http_plugins
        .iter()
        .find(|p| p.name == "static_file")
        .unwrap();
    assert_eq!(sf.addr, "http://127.0.0.1:9999");
}

/// The `authentication_method` serde alias also works on the canonical
/// [auth] section (defense in depth beyond the normalize mapping).
#[test]
fn test_auth_method_alias_authentication_method() {
    let cfg: ServerConfig = load_server_config_from_str(
        r#"bind_port = 7000
[auth]
authentication_method = "oidc"
"#,
    )
    .unwrap();
    assert_eq!(cfg.auth.method, "oidc");
}

/// Client-side legacy INI authentication_method (mirror of the server fix):
/// frpc.ini [common] authentication_method = oidc must not silently fall
/// back to token.
#[test]
fn test_legacy_ini_client_authentication_method() {
    let cfg: ClientConfig = load_client_ini(
        r#"server_addr = "127.0.0.1"
server_port = 7000
authentication_method = oidc
oidc_client_id = "frpc-test"
oidc_issuer = "https://idp.example"
oidc_token_endpoint_url = "https://idp.example/token"
"#,
    )
    .unwrap();
    assert_eq!(
        cfg.auth.as_ref().map(|a| a.method.as_str()).unwrap_or(""),
        "oidc"
    );

    // Canonical [auth] section alias too.
    let cfg2: ClientConfig = load_client_config_from_str(
        r#"server_addr = "127.0.0.1"
server_port = 7000
[auth]
authentication_method = "oidc"
[auth.oidc]
clientID = "frpc-test"
issuer = "https://idp.example"
tokenEndpointUrl = "https://idp.example/token"
"#,
    )
    .unwrap();
    assert_eq!(
        cfg2.auth.as_ref().map(|a| a.method.as_str()).unwrap_or(""),
        "oidc"
    );
}

/// ini_to_toml empty array literal: ops = [] -> [] (not [""]).
#[test]
fn test_ini_empty_array_literal() {
    let cfg: ServerConfig = load_server_ini(
        r#"bind_port = 7000
[plugin.empty]
addr = "127.0.0.1:9000"
ops = []
"#,
    )
    .unwrap();
    let p = cfg.http_plugins.iter().find(|p| p.name == "empty").unwrap();
    assert!(p.ops.is_empty(), "ops: {:?}", p.ops);
}

/// Strict mode accepts the audit-added legacy keys inside [auth]
/// (authentication_method, oidc_skip_*_check snake_case, camelCase
/// oidcSkip*Check) — exercised through the REAL strict path (file load with
/// strict_config=true -> run_strict_check), plus a negative assertion that an
/// unknown [auth] key is still rejected.
#[test]
fn test_strict_auth_accepts_legacy_keys() {
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(
        br#"bind_port = 7000
[auth]
authentication_method = "oidc"
oidc_skip_expiry_check = true
oidc_skip_issuer_check = true
"#,
    )
    .unwrap();
    let cfg: ServerConfig =
        super::file::load_server_config(f.path().to_str().unwrap(), true).unwrap();
    assert_eq!(cfg.auth.method, "oidc");
    assert!(cfg.auth.oidc_skip_expiry);
    assert!(cfg.auth.oidc_skip_issuer);

    // camelCase variants are whitelisted too (serde aliases oidcSkip*Check).
    let mut cc = tempfile::NamedTempFile::new().unwrap();
    cc.write_all(
        br#"bind_port = 7000
[auth]
oidcSkipExpiryCheck = true
oidcSkipIssuerCheck = true
"#,
    )
    .unwrap();
    let cfg_cc: ServerConfig =
        super::file::load_server_config(cc.path().to_str().unwrap(), true).unwrap();
    assert!(cfg_cc.auth.oidc_skip_expiry);
    assert!(cfg_cc.auth.oidc_skip_issuer);

    // Negative: an unknown [auth] key still fails strict.
    let mut bad = tempfile::NamedTempFile::new().unwrap();
    bad.write_all(
        br#"bind_port = 7000
[auth]
method = "token"
not_a_real_auth_key = 1
"#,
    )
    .unwrap();
    let err = super::file::load_server_config(bad.path().to_str().unwrap(), true).unwrap_err();
    assert!(
        format!("{err}").contains("not_a_real_auth_key"),
        "err: {err}"
    );
}

/// Go legacy INI top-level oidc_skip_expiry_check / oidc_skip_issuer_check
/// fold into [auth] (the serde alias only covers the [auth] section form).
#[test]
fn test_legacy_ini_top_level_oidc_skip_check_keys() {
    let cfg: ServerConfig = load_server_ini(
        r#"bind_port = 7000
oidc_skip_expiry_check = true
oidc_skip_issuer_check = true
"#,
    )
    .unwrap();
    assert!(cfg.auth.oidc_skip_expiry);
    assert!(cfg.auth.oidc_skip_issuer);
}

/// [auth] token_source (frp-rs native snake_case) is whitelisted in strict
/// mode alongside the Go camelCase tokenSource.
#[test]
fn test_strict_auth_accepts_token_source_snake_case() {
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(
        br#"bind_port = 7000
[auth]
method = "token"
[auth.token_source]
type = "file"
file.path = "/tmp/frp-token"
"#,
    )
    .unwrap();
    let cfg: ServerConfig =
        super::file::load_server_config(f.path().to_str().unwrap(), true).unwrap();
    assert!(cfg.auth.token_source.is_some());
}

/// ini_to_toml: a bare "[::1]" (IPv6 literal) is NOT treated as an array —
/// it must parse as a plain string.
#[test]
fn test_ini_ipv6_literal_not_array() {
    let cfg: ServerConfig = load_server_ini(
        r#"bind_port = 7000
[plugin.ipv6]
addr = "http://[::1]:9000"
"#,
    )
    .unwrap();
    let p = cfg.http_plugins.iter().find(|p| p.name == "ipv6").unwrap();
    assert_eq!(p.addr, "http://[::1]:9000");
}

/// ini_to_toml: an array literal with quoted elements still parses as an
/// array (regression guard for the looks-like-list heuristic).
#[test]
fn test_ini_quoted_array_literal_still_array() {
    let cfg: ServerConfig = load_server_ini(
        r#"bind_port = 7000
[plugin.arr]
addr = "127.0.0.1:9000"
ops = ["login", "new_proxy"]
"#,
    )
    .unwrap();
    let p = cfg.http_plugins.iter().find(|p| p.name == "arr").unwrap();
    assert_eq!(p.ops, vec!["login", "new_proxy"]);
}

/// infer_ini_value: a lone quote character as the whole value must not
/// panic. `token = "` and `token = '` used to hit `s[1..s.len() - 1]` →
/// `s[1..0]` ("slice index starts at 1 but ends at 0"), which aborts in
/// release builds (panic = "abort") and is reachable at startup AND on
/// runtime reload (frpc SIGUSR1 / admin API). Go ini.v1 keeps a lone quote
/// as a one-character literal string, so it must parse to `"` / `'`.
#[test]
fn test_ini_lone_quote_char_no_panic() {
    for (raw_value, expected) in [
        ("\"", "\""),
        ("'", "'"),
        ("\"abc\"", "abc"),
        ("\"\"", ""),
        ("\"abc", "\"abc"),
        ("abc\"", "abc\""),
    ] {
        // Each value on its own line so a lone quote is the complete value.
        let content = format!("token = {raw_value}\nserver_port = 7000\n");
        let value =
            super::format::parse_to_toml_value(&content, super::format::ConfigFormat::Ini).unwrap();
        let table = value.as_table().unwrap();
        assert_eq!(
            table.get("token"),
            Some(&toml::Value::String(expected.to_string())),
            "INI value {raw_value:?} should parse to {expected:?}"
        );
    }
}

/// infer_ini_value: deeply nested array-literal brackets must not overflow
/// the stack. `[`×k + `"x"` + `]`×k recurses once per bracket pair (each
/// frame trims, lowercases, and re-checks the value), so a multi-MB config
/// value SIGSEGVs the process — reachable at startup AND on runtime reload
/// (frpc SIGUSR1 / admin API) — under panic="abort" nothing catches it.
/// Legitimate nesting is at most 2 levels; the depth cap returns the
/// remaining value as a string literal instead of recursing.
#[test]
fn test_ini_nested_bracket_recursion_depth_capped() {
    let k = 30_000; // ~150+ B/frame → well past the 2 MiB test-thread stack
    let mut raw = String::with_capacity(2 * k + 3);
    raw.push_str("token = ");
    for _ in 0..k {
        raw.push('[');
    }
    raw.push_str("\"x\"");
    for _ in 0..k {
        raw.push(']');
    }
    raw.push_str("\nserver_port = 7000\n");

    let value = super::format::parse_to_toml_value(&raw, super::format::ConfigFormat::Ini).unwrap();
    let table = value.as_table().unwrap();
    let token = table.get("token").unwrap();

    // The recursion must stop at the cap: nested Arrays <= MAX_INI_NESTING
    // deep, innermost element a String holding the unparsed bracket
    // remainder. Pre-fix this value overflowed the stack (SIGABRT).
    let mut depth = 0usize;
    let mut cur = token;
    loop {
        match cur {
            toml::Value::Array(items) => {
                depth += 1;
                assert_eq!(items.len(), 1, "single-element chain");
                cur = &items[0];
            }
            toml::Value::String(s) => {
                assert!(s.starts_with('['), "string remainder keeps brackets");
                break;
            }
            other => panic!("unexpected nested value {other:?}"),
        }
    }
    assert!(
        depth <= 16,
        "nesting depth {depth} must be capped at 16 (no stack overflow)"
    );
}

/// bind_port: an EXPLICIT 0 maps to the default 7000 in complete(), exactly
/// like an absent key. Go frp `v1/server.go:111` `BindPort =
/// util.EmptyOr(BindPort, 7000)`; serde's default fn fires only on absent,
/// so complete() closes the present-but-zero gap — `bindPort = 0` must bind
/// 7000, not an OS-chosen ephemeral port (TcpListener::bind("0.0.0.0:0")).
#[test]
fn test_server_bind_port_zero_maps_to_default_in_complete() {
    let mut cfg: ServerConfig =
        serde_json::from_value(serde_json::json!({ "bindPort": 0 })).unwrap();
    assert_eq!(cfg.bind_port, 0, "deserialization alone must not default");
    cfg.complete();
    assert_eq!(cfg.bind_port, 7000);
}

/// `bind_addr`: an explicit empty string is filled to `0.0.0.0`, matching Go's
/// `c.BindAddr = util.EmptyOr(c.BindAddr, "0.0.0.0")`
/// (`pkg/config/v1/server.go:110`, which runs before the `ProxyBindAddr`
/// inheritance at `:112-114` and before `BindPort` at `:111`).
///
/// Measured on Go v0.71.0 and frp-rs (base `80199f4`) with `bindAddr: ""` +
/// `bindPort: 19815`, credentials set, `-c <file>`: Go stdout
/// `frps tcp listen on 0.0.0.0:19815`, `lsof -nP -iTCP:19815 -sTCP:LISTEN`
/// → `TCP *:19815 (LISTEN)`; frp-rs (before) logged `frps starting on :19815`
/// then `frps error: failed to lookup address information...` and exited 1 with
/// nothing listening. The bound address is pinned end-to-end by the spawn test
/// `cli_empty_bind_addr_binds_wildcard` in `frps/tests/cli_completion.rs`.
#[test]
fn server_bind_addr_empty_is_completed_to_wildcard() {
    let mut cfg: ServerConfig =
        serde_json::from_value(serde_json::json!({ "bindPort": 19815 })).unwrap();
    assert_eq!(cfg.bind_addr, "0.0.0.0", "serde default for an ABSENT key");
    cfg.bind_addr = String::new();
    cfg.complete();
    assert_eq!(cfg.bind_addr, "0.0.0.0");

    // The completion does not look at the port (Go fills it unconditionally at
    // `:110`, before `BindPort`'s own EmptyOr), so an empty address with an
    // explicitly zero port is filled the same way.
    let mut cfg: ServerConfig =
        serde_json::from_value(serde_json::json!({ "bindPort": 0 })).unwrap();
    cfg.bind_addr = String::new();
    assert_eq!(cfg.bind_port, 0);
    cfg.complete();
    assert_eq!(cfg.bind_addr, "0.0.0.0");
    assert_eq!(cfg.bind_port, 7000);

    // Every explicit non-empty address passes through verbatim.
    for addr in ["127.0.0.1", "::", "10.1.2.3"] {
        let mut cfg: ServerConfig =
            serde_json::from_value(serde_json::json!({ "bindAddr": addr, "bindPort": 19815 }))
                .unwrap();
        assert_eq!(cfg.bind_addr, addr, "deserialization must not rewrite it");
        cfg.complete();
        assert_eq!(cfg.bind_addr, addr, "bindAddr = {addr:?} must pass through");
    }

    // Go order: the `ProxyBindAddr` inheritance sees the filled address, so an
    // empty `proxyBindAddr` inherits `0.0.0.0`, not `""`.
    let mut cfg: ServerConfig =
        serde_json::from_value(serde_json::json!({ "bindPort": 19815 })).unwrap();
    cfg.bind_addr = String::new();
    cfg.proxy_bind_addr = String::new();
    cfg.complete();
    assert_eq!(cfg.bind_addr, "0.0.0.0");
    assert_eq!(cfg.proxy_bind_addr, "0.0.0.0");
}

/// **Call-order pin for the CLI override path.** `frps` overlays CLI flag values
/// onto the file config and must complete the *merged* result, as Go does
/// (`cmd/frps/root.go:78-81`: flags are bound onto the struct and
/// `ServerConfig.Complete()` runs afterwards). Completing the file first and
/// overlaying the flags afterwards loses the completion for any flag whose
/// value is empty — the shape this test pins, since that ordering is what made
/// an empty `--dashboard-addr ""` reach the dashboard as `:<port>` (measured:
/// `Dashboard web UI starting on :<port>` + `failed to lookup address
/// information`, no listener on the dashboard port).
#[test]
fn server_completion_must_run_on_the_merged_cli_config() {
    // What the file holds: an empty addr in each of the two completion inputs
    // and no bindAddr, then the flags that reach the same values.
    let mut cfg: ServerConfig =
        serde_json::from_value(serde_json::json!({ "bindPort": 19817 })).unwrap();
    cfg.bind_addr = String::new();
    cfg.web_server.addr = String::new();
    cfg.web_server.port = 19818;

    // The buggy order: complete, then write the flag values (all empty).
    let mut completed_first = cfg.clone();
    completed_first.complete();
    completed_first.bind_addr = String::new();
    completed_first.web_server.addr = String::new();
    assert_eq!(
        completed_first.web_server.addr, "",
        "completing before the override leaves the override value uncompleted"
    );

    // The Go order: overlay, then complete.
    cfg.complete();
    assert_eq!(cfg.bind_addr, "0.0.0.0");
    assert_eq!(cfg.web_server.addr, "127.0.0.1");
}

/// The **server** side of the empty `webServer.addr` story, now Go parity. Go's
/// `ServerConfig.Complete()` (`pkg/config/v1/server.go:101-126`) runs
/// `WebServer.Complete()` → `Addr = util.EmptyOr(Addr, "127.0.0.1")`
/// (`pkg/config/v1/common.go:71-72`) at `:107` and only then the
/// `if Port > 0 { Addr = util.EmptyOr(Addr, "0.0.0.0") }` at `:116-117`, so that
/// second branch is **dead** and an empty `addr` stays loopback. frp-core's
/// `ServerConfig::complete` used to implement only the second half (an empty
/// `addr` with a set port bound `*:<port>`); it now fills the empty string with
/// `127.0.0.1` first and no longer has the `0.0.0.0` branch at all. Measured on
/// Go v0.71.0 and frp-rs with `[webServer] addr = "" port = 7597` plus
/// credentials: Go logs `dashboard listen on 127.0.0.1:7597`, frp-rs (before)
/// logged `Dashboard listening on 0.0.0.0:7597`. The *bound address* is pinned
/// by the spawn test `dashboard_explicit_empty_addr_binds_loopback_only` in
/// `frp-server/tests/dashboard_integration.rs`; this test pins the completion
/// that feeds it, and the passthrough of every non-empty value.
#[test]
fn server_web_server_addr_empty_is_completed_to_localhost() {
    // Explicit empty string, as `[webServer] addr = ""` deserializes, with a
    // set port: the pre-fix code made this the wildcard.
    let mut cfg: ServerConfig =
        serde_json::from_value(serde_json::json!({ "bindPort": 7000 })).unwrap();
    cfg.web_server.addr = String::new();
    cfg.web_server.port = 7597;
    cfg.complete();
    assert_eq!(
        cfg.web_server.addr, "127.0.0.1",
        "Go's WebServer.Complete() fills the empty string unconditionally, \
         so the Port > 0 -> 0.0.0.0 branch it precedes is dead"
    );

    // Go's `WebServer.Complete()` does not look at the port, so an empty addr
    // is filled the same way when the dashboard is disabled.
    let mut cfg: ServerConfig =
        serde_json::from_value(serde_json::json!({ "bindPort": 7000 })).unwrap();
    cfg.web_server.addr = String::new();
    assert_eq!(cfg.web_server.port, 0);
    cfg.complete();
    assert_eq!(cfg.web_server.addr, "127.0.0.1");

    // Every explicit non-empty address is used verbatim — including the
    // wildcard, which the deleted branch used to be able to overwrite.
    for addr in ["0.0.0.0", "::1", "10.1.2.3"] {
        let mut cfg: ServerConfig = serde_json::from_value(
            serde_json::json!({ "bindPort": 7000, "webServer": { "addr": addr, "port": 7597 } }),
        )
        .unwrap();
        assert_eq!(
            cfg.web_server.addr, addr,
            "deserialization must not rewrite it"
        );
        cfg.complete();
        assert_eq!(
            cfg.web_server.addr, addr,
            "addr = {addr:?} must pass through"
        );
    }

    // An ABSENT `addr` key: the serde default already supplies 127.0.0.1, so
    // the completion never sees an empty string (parity before and after).
    let mut cfg: ServerConfig = serde_json::from_value(
        serde_json::json!({ "bindPort": 7000, "webServer": { "port": 7597 } }),
    )
    .unwrap();
    assert_eq!(cfg.web_server.addr, "127.0.0.1", "serde default");
    cfg.complete();
    assert_eq!(cfg.web_server.addr, "127.0.0.1");
}

/// server_port: same EmptyOr mapping on the client (Go v1/client.go:87).
/// `server_port = 0` used to dial port 0 (connect refused) instead of the
/// default listener.
#[test]
fn test_client_server_port_zero_maps_to_default_in_complete() {
    let mut cfg: ClientConfig =
        serde_json::from_value(serde_json::json!({ "server_port": 0 })).unwrap();
    assert_eq!(cfg.server_port, 0, "deserialization alone must not default");
    cfg.complete();
    assert_eq!(cfg.server_port, 7000);
}

/// The lone-quote token through the FULL client pipeline (parse → normalize
/// → validate → deserialize), proving the panic fix survives reload paths.
#[test]
fn test_ini_lone_quote_token_through_pipeline() {
    let cfg: ClientConfig =
        load_client_ini("server_addr = \"127.0.0.1\"\nserver_port = 7000\ntoken = \"\n").unwrap();
    assert_eq!(cfg.token, "\"", "lone quote token survives the pipeline");
}

// ─── Pre-release hardening round 8: config coverage gaps ──────────────
//
// Before this round, `type = "udp"` appeared ZERO times in workspace tests;
// udp/sudp/stcp/xtcp/https had no coverage at all. The blocks below add
// full-sample + minimal-defaults tests for every proxy type, plus the other
// verified gaps: malformed formats, negative poolCount/maxPoolCount,
// strict-mode section recursion, include variants, exec token-source
// validation, client heartbeat preservation (no clamp — Go parity), full
// Client/Server config samples, and a proxy/visitor sub-table proptest (in
// mod proptest_tests).

#[test]
fn test_proxy_minimal_defaults_for_every_type() {
    // serde defaults on ProxyConfig (client.rs): local_ip "127.0.0.1",
    // bandwidth_limit_mode "client", health_check_interval_seconds 10,
    // health_check_timeout_seconds 3, health_check_max_failed 1, enabled
    // true, proxy_protocol_version "".
    for proxy_type in [
        "tcp", "udp", "http", "sudp", "stcp", "xtcp", "https", "tcpmux",
    ] {
        // http/https/tcpmux require a domain (Go validateDomainConfigForClient:
        // "subdomain and custom domains should not be both empty"); the other
        // five types have no required fields.
        let extra = if matches!(proxy_type, "http" | "https" | "tcpmux") {
            "\ncustom_domains = [\"example.com\"]"
        } else {
            ""
        };
        let toml = format!(
            "server_addr = \"127.0.0.1\"\n[[proxies]]\nname = \"p\"\ntype = \"{proxy_type}\"{extra}\n"
        );
        let cfg: ClientConfig = load_client_config_from_str(&toml).unwrap();
        let p = &cfg.proxies[0];
        assert_eq!(p.proxy_type, proxy_type);
        assert_eq!(p.local_ip, "127.0.0.1", "{proxy_type}: local_ip default");
        assert_eq!(
            p.bandwidth_limit_mode, "client",
            "{proxy_type}: bandwidth_limit_mode default"
        );
        assert_eq!(
            p.health_check_interval_seconds, 10,
            "{proxy_type}: health_check_interval_seconds default"
        );
        assert_eq!(
            p.health_check_timeout_seconds, 3,
            "{proxy_type}: health_check_timeout_seconds default"
        );
        assert_eq!(
            p.health_check_max_failed, 1,
            "{proxy_type}: health_check_max_failed default"
        );
        assert!(p.enabled, "{proxy_type}: enabled default true");
        assert_eq!(
            p.proxy_protocol_version, "",
            "{proxy_type}: proxy_protocol_version default"
        );
        assert_eq!(p.local_port, 0, "{proxy_type}: local_port default");
        assert_eq!(p.remote_port, 0, "{proxy_type}: remote_port default");
        assert!(!p.use_encryption, "{proxy_type}: use_encryption default");
        assert!(!p.use_compression, "{proxy_type}: use_compression default");
    }
}

#[test]
fn test_udp_proxy_full_sample() {
    let toml = r#"
serverAddr = "127.0.0.1"
serverPort = 7000

[[proxies]]
name = "udp-echo"
type = "udp"
localIp = "10.0.0.5"
localPort = 5353
remotePort = 5353
useEncryption = true
useCompression = true
bandwidthLimit = "1MB"
bandwidthLimitMode = "server"
"#;
    let cfg: ClientConfig = load_client_config_from_str(toml).unwrap();
    let p = &cfg.proxies[0];
    assert_eq!(p.name, "udp-echo");
    assert_eq!(p.proxy_type, "udp");
    assert_eq!(p.local_ip, "10.0.0.5");
    assert_eq!(p.local_port, 5353);
    assert_eq!(p.remote_port, 5353);
    assert!(p.use_encryption);
    assert!(p.use_compression);
    assert_eq!(p.bandwidth_limit, "1MB");
    assert_eq!(p.bandwidth_limit_mode, "server");
}

#[test]
fn test_sudp_proxy_full_sample() {
    // SUDP shares the ProxyBackend/Transport/BandwidthLimit shape of UDP
    // (Go SUDPServerProxyConfig).
    let toml = r#"
serverAddr = "127.0.0.1"
serverPort = 7000

[[proxies]]
name = "sudp-syslog"
type = "sudp"
local_ip = "10.0.0.9"
local_port = 514
remote_port = 5514
use_encryption = true
use_compression = true
bandwidth_limit = "512KB"
"#;
    let cfg: ClientConfig = load_client_config_from_str(toml).unwrap();
    let p = &cfg.proxies[0];
    assert_eq!(p.proxy_type, "sudp");
    assert_eq!(p.local_ip, "10.0.0.9");
    assert_eq!(p.local_port, 514);
    assert_eq!(p.remote_port, 5514);
    assert!(p.use_encryption);
    assert!(p.use_compression);
    assert_eq!(p.bandwidth_limit, "512KB");
}

#[test]
fn test_stcp_proxy_full_sample() {
    let toml = r#"
serverAddr = "127.0.0.1"
serverPort = 7000

[[proxies]]
name = "stcp-db"
type = "stcp"
local_ip = "10.0.0.6"
local_port = 5432
sk = "stcp-secret"
virtual_net = "prod"
disable_assisted_addrs = true
use_encryption = true
allow_users = ["alice", "bob"]
"#;
    let cfg: ClientConfig = load_client_config_from_str(toml).unwrap();
    let p = &cfg.proxies[0];
    assert_eq!(p.proxy_type, "stcp");
    assert_eq!(p.local_ip, "10.0.0.6");
    assert_eq!(p.local_port, 5432);
    assert_eq!(p.sk, "stcp-secret");
    assert_eq!(p.virtual_net, "prod");
    assert!(p.disable_assisted_addrs);
    assert!(p.use_encryption);
    assert_eq!(p.allow_users, vec!["alice".to_string(), "bob".to_string()]);
}

#[test]
fn test_xtcp_proxy_full_sample() {
    // CamelCase aliases (secretKey/allowUsers/disableAssistedAddrs) exercise
    // the Go field names on the wire.
    let toml = r#"
serverAddr = "127.0.0.1"
serverPort = 7000

[[proxies]]
name = "xtcp-game"
type = "xtcp"
local_ip = "10.0.0.7"
local_port = 7777
secretKey = "xtcp-key"
virtual_net = "game"
disableAssistedAddrs = true
useEncryption = true
useCompression = true
allowUsers = ["carol"]
"#;
    let cfg: ClientConfig = load_client_config_from_str(toml).unwrap();
    let p = &cfg.proxies[0];
    assert_eq!(p.proxy_type, "xtcp");
    assert_eq!(p.local_ip, "10.0.0.7");
    assert_eq!(p.local_port, 7777);
    assert_eq!(p.sk, "xtcp-key");
    assert_eq!(p.virtual_net, "game");
    assert!(p.disable_assisted_addrs);
    assert!(p.use_encryption);
    assert!(p.use_compression);
    assert_eq!(p.allow_users, vec!["carol".to_string()]);
}

#[test]
fn test_https_proxy_full_sample() {
    // https2http/https2https plugins with crt/key/enableHTTP2 land on
    // PluginConfig.crt_file/key_file/enable_http2 (serde aliases crtPath,
    // keyPath, enableHTTP2).
    let toml = r#"
serverAddr = "127.0.0.1"
serverPort = 7000

[[proxies]]
name = "web-https"
type = "https"
custom_domains = ["secure.example.com", "api.example.com"]
use_encryption = true
use_compression = true

[proxies.plugin]
type = "https2http"
crtPath = "/etc/frp/https.crt"
keyPath = "/etc/frp/https.key"
enableHTTP2 = false

[[proxies]]
name = "web-https2https"
type = "https"
custom_domains = ["tls.example.com"]
useEncryption = true

[proxies.plugin]
type = "https2https"
crtPath = "/etc/frp/tls.crt"
keyPath = "/etc/frp/tls.key"
enableHTTP2 = true
"#;
    let cfg: ClientConfig = load_client_config_from_str(toml).unwrap();
    assert_eq!(cfg.proxies.len(), 2);
    let p = &cfg.proxies[0];
    assert_eq!(p.proxy_type, "https");
    assert_eq!(
        p.custom_domains,
        vec![
            "secure.example.com".to_string(),
            "api.example.com".to_string()
        ]
    );
    assert!(p.use_encryption);
    assert!(p.use_compression);
    let plugin = p.plugin.as_ref().expect("https2http plugin");
    assert_eq!(plugin.plugin_type, "https2http");
    assert_eq!(plugin.crt_file, "/etc/frp/https.crt");
    assert_eq!(plugin.key_file, "/etc/frp/https.key");
    assert_eq!(plugin.enable_http2, Some(false));

    let p2 = &cfg.proxies[1];
    let plugin2 = p2.plugin.as_ref().expect("https2https plugin");
    assert_eq!(plugin2.plugin_type, "https2https");
    assert_eq!(plugin2.crt_file, "/etc/frp/tls.crt");
    assert_eq!(plugin2.key_file, "/etc/frp/tls.key");
    assert_eq!(plugin2.enable_http2, Some(true));
}

#[test]
fn test_http_proxy_full_sample_extended() {
    // Extends the http coverage with http_user/http_pwd/host_header_rewrite/
    // locations/route_by_http_user/subdomain (Go HTTPProxyConfig fields).
    let toml = r#"
serverAddr = "127.0.0.1"
serverPort = 7000

[[proxies]]
name = "web-http"
type = "http"
local_ip = "10.0.0.8"
local_port = 8080
custom_domains = ["web.example.com"]
subdomain = "web"
http_user = "admin"
http_pwd = "s3cret"
host_header_rewrite = "internal.example.com"
locations = ["/", "/api"]
route_by_http_user = "alice"
use_encryption = true
bandwidth_limit = "2MB"
"#;
    let cfg: ClientConfig = load_client_config_from_str(toml).unwrap();
    let p = &cfg.proxies[0];
    assert_eq!(p.proxy_type, "http");
    assert_eq!(p.local_ip, "10.0.0.8");
    assert_eq!(p.local_port, 8080);
    assert_eq!(p.custom_domains, vec!["web.example.com".to_string()]);
    assert_eq!(p.subdomain, "web");
    assert_eq!(p.http_user, "admin");
    assert_eq!(p.http_pwd, "s3cret");
    assert_eq!(p.host_header_rewrite, "internal.example.com");
    assert_eq!(p.locations, vec!["/".to_string(), "/api".to_string()]);
    assert_eq!(p.route_by_http_user, "alice");
    assert!(p.use_encryption);
    assert_eq!(p.bandwidth_limit, "2MB");
}

#[test]
fn test_tcpmux_proxy_full_sample() {
    let toml = r#"
serverAddr = "127.0.0.1"
serverPort = 7000

[[proxies]]
name = "mux-ssh"
type = "tcpmux"
multiplexer = "httpconnect"
custom_domains = ["mux.example.com"]
subdomain = "mux"
http_user = "mux-user"
http_pwd = "mux-pass"
route_by_http_user = "bob"
proxy_protocol_version = "v2"
use_encryption = true
"#;
    let cfg: ClientConfig = load_client_config_from_str(toml).unwrap();
    let p = &cfg.proxies[0];
    assert_eq!(p.proxy_type, "tcpmux");
    assert_eq!(p.multiplexer, "httpconnect");
    assert_eq!(p.custom_domains, vec!["mux.example.com".to_string()]);
    assert_eq!(p.subdomain, "mux");
    assert_eq!(p.http_user, "mux-user");
    assert_eq!(p.http_pwd, "mux-pass");
    assert_eq!(p.route_by_http_user, "bob");
    assert_eq!(p.proxy_protocol_version, "v2");
    assert!(p.use_encryption);
}

// ─── Malformed formats → Err, never panic ─────────────────────────────

#[test]
fn test_malformed_toml_returns_err() {
    // Malformed TOML surfaces as an Err from parse and from the full
    // pipeline (before round 8 only malformed JSON was tested).
    assert!(
        super::format::parse_to_toml_value("bind_port = ]", super::format::ConfigFormat::Toml)
            .is_err()
    );
    let err = load_server_config_from_str("bind_port = ]\n");
    assert!(err.is_err(), "malformed TOML must not panic: {err:?}");
    let err = load_client_config_from_str("server_addr = [\n");
    assert!(err.is_err(), "malformed TOML must not panic: {err:?}");
}

#[test]
fn test_malformed_yaml_returns_err() {
    // Malformed YAML (unclosed flow sequence) surfaces as an Err, never a
    // panic.
    assert!(super::format::parse_to_toml_value("a: [", super::format::ConfigFormat::Yaml).is_err());
    let err = load_client_config_from_yaml("server_addr: [\n");
    assert!(err.is_err(), "malformed YAML must not panic: {err:?}");
}

#[test]
fn test_malformed_ini_value_through_pipeline_returns_err() {
    // INI parsing is deliberately lenient (Go Viper parity) and never fails
    // at parse time; a value the schema cannot accept (string where an
    // integer is required) surfaces as a config validation error from the
    // pipeline — never a panic.
    let err = load_server_ini("bind_port = not-a-number\n")
        .unwrap_err()
        .to_string();
    assert!(err.contains("config validation error"), "got: {err}");
    // Lenient parse: an unclosed section header is skipped, not an error.
    let value = super::format::parse_to_toml_value(
        "[broken\ntoken = x\n",
        super::format::ConfigFormat::Ini,
    )
    .unwrap();
    assert!(value.as_table().unwrap().contains_key("token"));
}

// ─── Negative pool counts ─────────────────────────────────────────────

#[test]
fn test_client_negative_pool_count_rejected() {
    // Fail-fast divergence, NOT Go client parity: Go frp v0.71.0 has no
    // client-side poolCount check (Go frpc loads the config; the SERVER
    // rejects the negative at login — control.go:438, mirrored in frp-rs
    // control/login.rs). frp-rs frpc now refuses the misconfig at load
    // instead of dialing first (round-9 addition in loader.rs
    // validate_client_config).
    // 0 keeps the use-the-default semantics (util.EmptyOr → 1), pinned by
    // test_explicit_zero_client_pool_count_and_keepalive_use_go_defaults.
    let err = load_client_config_from_str("server_addr = '127.0.0.1'\npool_count = -1\n")
        .unwrap_err()
        .to_string();
    assert!(err.contains("invalid poolCount"), "got: {err}");

    let err =
        load_client_config_from_str("serverAddr = '127.0.0.1'\n[transport]\npoolCount = -1\n")
            .unwrap_err()
            .to_string();
    assert!(err.contains("invalid poolCount"), "got: {err}");

    let cfg = load_client_config_from_str("serverAddr = '127.0.0.1'\n[transport]\npoolCount = 0\n")
        .unwrap();
    assert_eq!(cfg.pool_count, 1, "explicit 0 still means the default (1)");
}

#[test]
fn test_server_negative_max_pool_count_rejected() {
    // loader.rs validate_server_config already rejects a negative
    // transport.maxPoolCount (Go v0.71.0); this pins the config-layer
    // rejection, which had no test.
    let err = load_server_config_from_str("bindPort = 7000\n[transport]\nmaxPoolCount = -1\n")
        .unwrap_err()
        .to_string();
    assert!(err.contains("invalid transport.maxPoolCount"), "got: {err}");

    // 0 and positive values are accepted.
    load_server_config_from_str("bindPort = 7000\n[transport]\nmaxPoolCount = 0\n").unwrap();
    load_server_config_from_str("bindPort = 7000\n[transport]\nmaxPoolCount = 10\n").unwrap();
}

// ─── Strict mode: section recursion ───────────────────────────────────

#[test]
fn test_strict_rejects_unknown_proxy_field() {
    // Go frp v0.71.0 with strict mode on (its default) refuses this config:
    // `decode proxy at index 0: unmarshal ProxyConfig error: json: unknown
    // field "totally_unknown_proxy_field"` (measured on the v0.71.0
    // darwin/arm64 binary; `frpc verify -c` exits 1). `check_strict` recurses
    // into the `proxies` array with `PROXY_KNOWN_KEYS` (`strict.rs`), so the
    // same key is refused here with the element index in the path.
    //
    // The match is exact, so Go's case-insensitive field lookup is *not*
    // mirrored: Go accepts `RemotePort` here (measured), frp-rs refused it
    // before this recursion only by silently dropping the value — see
    // `case_insensitive_proxy_array_key_is_dropped_in_strict_mode`.
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(
        br#"serverAddr = "127.0.0.1"
serverPort = 7000
[[proxies]]
name = "p"
type = "tcp"
local_port = 80
remote_port = 7001
totally_unknown_proxy_field = 1
"#,
    )
    .unwrap();
    let err = load_client_config(f.path().to_str().unwrap(), true)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("unknown field \"proxies[0].totally_unknown_proxy_field\""),
        "got: {err}"
    );

    // Non-strict mode still accepts the file and drops the unknown key — the
    // direction Go takes with `--strict-config=false` (measured: rc 0).
    let cfg = load_client_config(f.path().to_str().unwrap(), false).unwrap();
    assert_eq!(cfg.proxies.len(), 1);
    assert_eq!(cfg.proxies[0].remote_port, 7001);
    assert_eq!(cfg.proxies[0].name, "p");
}

#[test]
fn test_strict_rejects_unknown_web_server_key() {
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(
        br#"bindPort = 7000
[web_server]
addr = "0.0.0.0"
port = 7500
unknown_web_server_key = 1
"#,
    )
    .unwrap();
    let err = load_server_config(f.path().to_str().unwrap(), true)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("unknown field \"web_server.unknown_web_server_key\""),
        "got: {err}"
    );
}

/// The array-element arm of the case-insensitive-keys divergence. Go v0.71.0
/// accepts the file (`frpc verify -c` exits 0, measured) because its
/// `encoding/json` decoder matches object keys case-insensitively, so
/// `RemotePort` reaches the same field as `remotePort`; frp-rs's serde field
/// matching is exact, so the key is unknown to the frp-rs config surface and
/// its value is dropped. Strict mode now **refuses** that key instead of
/// dropping it silently (`check_strict` recurses into the array with its exact
/// key set), which is stricter than Go but louder than the previous silent
/// loss; non-strict mode keeps the drop, which is what the old pin asserted.
///
/// This is not a new class of divergence: the same config with a mis-cased
/// **top-level** key (`SERVERADDR`) is refused by frp-rs strict mode today and
/// accepted by Go (both measured).
#[test]
fn case_insensitive_proxy_array_key_is_refused_in_strict_mode() {
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(
        b"serverAddr = \"127.0.0.1\"\nserverPort = 7000\n[[proxies]]\nname = \"p\"\ntype = \"tcp\"\nlocalPort = 80\nRemotePort = 7198\n",
    )
    .unwrap();
    let err = load_client_config(f.path().to_str().unwrap(), true)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("unknown field \"proxies[0].RemotePort\""),
        "the mis-cased key must be refused in strict mode; got: {err}"
    );

    // Non-strict mode still drops the value: `remote_port` stays 0 while the
    // camelCase alias `localPort` (which serde does know) is honoured. A
    // future `#[serde(alias = "RemotePort")]` would break this arm, so the
    // drop cannot be silently upgraded into an honoured key.
    let cfg = load_client_config(f.path().to_str().unwrap(), false).unwrap();
    assert_eq!(cfg.proxies.len(), 1);
    assert_eq!(
        cfg.proxies[0].remote_port, 0,
        "non-strict keeps Go's `--strict-config=false` shape: the mis-cased key \
         is dropped, not read (Go would use 7198); a serde alias would make \
         this 7198 and would be a behaviour change, not a test tweak"
    );
    assert_eq!(cfg.proxies[0].local_port, 80);
}

/// The third non-walked shape: a **nested table inside a walked section**. The
/// key-list lookup happens for the table being visited, so nothing below it is
/// visited either — `[auth.tokenSource]` is walked (its own keys are checked)
/// but `[auth.tokenSource.exec]` has no list and is skipped.
///
/// Measured against Go v0.71.0 with `[auth.tokenSource] type = "exec"` and
/// `[auth.tokenSource.exec] command = "echo tok"`:
///
/// * Go refuses **both** spellings — `unsafe feature "TokenSourceExec" is not
///   enabled …` — because it reads the key either way and then hits its gate.
/// * frp-rs strict `verify` now exits 1 for **both** too: `TokenSourceExec` is
///   defined at `frp-core/src/unsafe_features.rs:10` and enforced by
///   `validate_token_source_unsafe` (`frp-core/src/auth.rs`), and since `3798a727`
///   the shared load path runs it (`frp-core/src/config/file.rs`), so verify
///   refuses the config after the walk and the spelling no longer changes its
///   verdict; `--allow-unsafe TokenSourceExec` restores `is valid`/rc 0 for both.
///   Measured: `frpc -c <this config>` is rc 3 with
///   `auth.tokenSource exec blocked: TokenSourceExec not in UnsafeFeatures
///   allowlist. …`, identical for `Env` and `env`. The drop is therefore visible
///   only at the parsed-value level, which is what this pin asserts: `env` is
///   read into the token source, `Env` leaves it empty.
///
/// Already documented in `docs/deployment.md:900`
/// (`auth.tokenSource.exec.env` has no key set at `tokenSource`).
#[test]
fn case_insensitive_key_in_a_nested_table_is_dropped_in_strict_mode() {
    let base = "serverAddr = \"127.0.0.1\"\nserverPort = 7000\n[auth]\nmethod = \"token\"\n\
                [auth.tokenSource]\ntype = \"exec\"\n[auth.tokenSource.exec]\n\
                command = \"echo tok\"\n";

    let mut cap = tempfile::NamedTempFile::new().unwrap();
    cap.write_all(format!("{base}Env = [{{ name = \"A\", value = \"B\" }}]\n").as_bytes())
        .unwrap();
    let cfg = load_client_config(cap.path().to_str().unwrap(), true)
        .expect("strict mode accepts the mis-cased nested key");
    let exec = cfg
        .auth
        .as_ref()
        .and_then(|a| a.token_source.as_ref())
        .and_then(|ts| ts.exec.as_ref())
        .expect("exec source parsed");
    assert!(
        exec.env.is_empty(),
        "the mis-cased `Env` must be dropped (Go would read it and refuse at its \
         TokenSourceExec gate); got {:?}",
        exec.env
    );

    // The correctly spelled key is read — the same frp-rs `verify` rc, a
    // different parsed value. That difference is the whole claim.
    let mut lower = tempfile::NamedTempFile::new().unwrap();
    lower
        .write_all(format!("{base}env = [{{ name = \"A\", value = \"B\" }}]\n").as_bytes())
        .unwrap();
    let cfg = load_client_config(lower.path().to_str().unwrap(), true).unwrap();
    let exec = cfg
        .auth
        .as_ref()
        .and_then(|a| a.token_source.as_ref())
        .and_then(|ts| ts.exec.as_ref())
        .expect("exec source parsed");
    assert_eq!(exec.env.len(), 1, "the correct spelling IS read");
    assert_eq!(exec.env[0].name, "A");
    assert_eq!(exec.env[0].value, "B");
}

/// The second non-walked shape for a mis-cased key, and the reason the
/// case-insensitive-keys record cannot say "the walked sections refuse, arrays
/// are dropped": a **table alias the normalizer leaves alone**. `[virtualNet]`
/// is a documented camelCase alias for `virtual_net`, but
/// `normalize_client_config` canonicalises only some spellings (`webServer`,
/// `featureGates`, …), so this alias survives to `check_strict`, which has no
/// key list for it and therefore does not descend. A capitalised nested key is
/// then dropped silently in strict mode.
///
/// Measured against Go v0.71.0: Go's `verify -c` on the `Address` spelling fails
/// with `VirtualNet feature is not enabled; enable it by setting the appropriate
/// feature gate flag`, while frp-rs's `verify` exits 0 and prints `syntax is ok`, and
/// the strict load returns `Ok` with `virtual_net.address == ""`. The dropped key
/// also *hides* the feature-gate refusal, because an empty address means no vnet
/// config is seen at all. `[virtual_net] Address` and `[virtualNet] address`
/// both behave differently, so this is specifically the alias arm.
#[test]
fn case_insensitive_key_in_a_table_alias_is_dropped_in_strict_mode() {
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(
        b"serverAddr = \"127.0.0.1\"\nserverPort = 7000\n[virtualNet]\nAddress = \"10.1.0.0/24\"\n",
    )
    .unwrap();
    let cfg = load_client_config(f.path().to_str().unwrap(), true)
        .expect("strict mode accepts the alias with a mis-cased nested key");
    assert_eq!(
        cfg.virtual_net.address, "",
        "the mis-cased key is dropped, not read (Go would use 10.1.0.0/24)"
    );

    // The correctly spelled alias key IS read, and then the feature-gate check
    // fires — which is what the dropped key above hides.
    let mut ok = tempfile::NamedTempFile::new().unwrap();
    ok.write_all(
        b"serverAddr = \"127.0.0.1\"\nserverPort = 7000\n[virtualNet]\naddress = \"10.1.0.0/24\"\n",
    )
    .unwrap();
    let err = load_client_config(ok.path().to_str().unwrap(), true)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("VirtualNet feature is not enabled"),
        "the correctly spelled alias key reaches the feature gate: {err}"
    );

    // Contrast: the canonical snake_case section DOES have a key list, so the
    // same mis-cased nested key is refused there.
    let mut snake = tempfile::NamedTempFile::new().unwrap();
    snake
        .write_all(
            b"serverAddr = \"127.0.0.1\"\nserverPort = 7000\n[virtual_net]\nAddress = \"10.1.0.0/24\"\n",
        )
        .unwrap();
    let err = load_client_config(snake.path().to_str().unwrap(), true)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("unknown field \"virtual_net.Address\""),
        "got: {err}"
    );
}

#[test]
fn test_strict_rejects_unknown_quic_key() {
    // Client-side top-level [quic] (normalize flattens [transport.quic] to
    // the top-level `quic` table) and server-side [transport.quic].
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(
        br#"serverAddr = "127.0.0.1"
[quic]
keepalive_period = 10
unknown_quic_key = 1
"#,
    )
    .unwrap();
    let err = load_client_config(f.path().to_str().unwrap(), true)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("unknown field \"quic.unknown_quic_key\""),
        "got: {err}"
    );

    let mut sf = tempfile::NamedTempFile::new().unwrap();
    sf.write_all(
        br#"bindPort = 7000
[transport]
[transport.quic]
keepalive_period = 10
unknown_quic_key = 1
"#,
    )
    .unwrap();
    let err = load_server_config(sf.path().to_str().unwrap(), true)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("unknown field \"transport.quic.unknown_quic_key\""),
        "got: {err}"
    );
}

#[test]
fn test_strict_rejects_unknown_ssh_tunnel_gateway_key() {
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(
        br#"bindPort = 7000
[ssh_tunnel_gateway]
bind_port = 2200
unknown_ssh_key = 1
"#,
    )
    .unwrap();
    let err = load_server_config(f.path().to_str().unwrap(), true)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("unknown field \"ssh_tunnel_gateway.unknown_ssh_key\""),
        "got: {err}"
    );
}

#[test]
fn test_strict_rejects_unknown_observability_key() {
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(
        br#"bindPort = 7000
[observability]
otlp_endpoint = "http://otel.example.com:4317"
unknown_obs_key = 1
"#,
    )
    .unwrap();
    let err = load_server_config(f.path().to_str().unwrap(), true)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("unknown field \"observability.unknown_obs_key\""),
        "got: {err}"
    );
}

#[test]
fn test_strict_rejects_unknown_virtual_net_key() {
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(
        br#"serverAddr = "127.0.0.1"
[virtual_net]
address = "10.0.0.1"
unknown_vnet_key = 1
"#,
    )
    .unwrap();
    let err = load_client_config(f.path().to_str().unwrap(), true)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("unknown field \"virtual_net.unknown_vnet_key\""),
        "got: {err}"
    );
}

#[test]
fn test_strict_rejects_unknown_store_key() {
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(
        br#"serverAddr = "127.0.0.1"
[store]
path = "./frpc_store.json"
unknown_store_key = 1
"#,
    )
    .unwrap();
    let err = load_client_config(f.path().to_str().unwrap(), true)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("unknown field \"store.unknown_store_key\""),
        "got: {err}"
    );
}

// ─── ClientConfig / ServerConfig full samples ─────────────────────────

#[test]
fn test_client_config_full_sample() {
    let toml = r#"
server_addr = "10.1.2.3"
server_port = 7001
user = "bob"
clientID = "client-42"
start = ["web", "ssh"]
connectServerLocalIP = "192.168.1.10"
natHoleStunServer = "stun.example.com:3478"
loginFailExit = true
metas = { env = "prod", region = "eu" }
udpPacketSize = 2048
"#;
    let cfg: ClientConfig = load_client_config_from_str(toml).unwrap();
    assert_eq!(cfg.server_addr, "10.1.2.3");
    assert_eq!(cfg.server_port, 7001);
    assert_eq!(cfg.user, "bob");
    assert_eq!(cfg.client_id, "client-42");
    assert_eq!(cfg.start, vec!["web".to_string(), "ssh".to_string()]);
    assert_eq!(cfg.connect_server_local_ip, "192.168.1.10");
    assert_eq!(cfg.nat_hole_stun_server, "stun.example.com:3478");
    assert!(cfg.login_fail_exit);
    assert_eq!(cfg.metas.get("env").map(String::as_str), Some("prod"));
    assert_eq!(cfg.metas.get("region").map(String::as_str), Some("eu"));
    assert_eq!(cfg.udp_packet_size, 2048);
}

#[test]
fn test_client_config_defaults_pinned() {
    // login_fail_exit's TRUE default is deliberate (CLAUDE.md: the code
    // default differs from the README example); udp_packet_size defaults to
    // 1500 and nat_hole_stun_server to stun.easyvoip.com:3478.
    let cfg: ClientConfig = load_client_config_from_str("server_addr = '127.0.0.1'\n").unwrap();
    assert!(cfg.login_fail_exit, "login_fail_exit defaults to TRUE");
    assert_eq!(cfg.udp_packet_size, 1500);
    assert_eq!(cfg.nat_hole_stun_server, "stun.easyvoip.com:3478");
    assert!(cfg.start.is_empty());
    assert!(cfg.user.is_empty());
    assert!(cfg.client_id.is_empty());
    assert!(cfg.connect_server_local_ip.is_empty());
}

#[test]
fn test_server_config_full_sample() {
    let toml = r#"
bind_port = 7000
maxConnsPerProxy = 1000
graceful_shutdown_timeout = 60
natholeAnalysisDataReserveHours = 336
maxAcceptRate = 500

[observability]
otlp_endpoint = "http://otel.example.com:4317"
service_name = "frps-prod"
"#;
    let cfg: ServerConfig = load_server_config_from_str(toml).unwrap();
    assert_eq!(cfg.max_conns_per_proxy, 1000);
    assert_eq!(cfg.graceful_shutdown_timeout, 60);
    assert_eq!(cfg.nat_hole_analysis_data_reserve_hours, 336);
    assert_eq!(cfg.max_accept_rate, Some(500));
    assert_eq!(
        cfg.observability.otlp_endpoint,
        "http://otel.example.com:4317"
    );
    assert_eq!(cfg.observability.service_name, "frps-prod");
}

#[test]
fn test_server_config_defaults_pinned() {
    let cfg: ServerConfig = load_server_config_from_str("bind_port = 7000\n").unwrap();
    assert_eq!(cfg.allow_port_start, 1);
    assert_eq!(cfg.allow_port_end, 65535);
    assert_eq!(cfg.graceful_shutdown_timeout, 30);
    assert_eq!(cfg.nat_hole_analysis_data_reserve_hours, 168);
    assert_eq!(cfg.max_accept_rate, None);
    assert_eq!(cfg.max_conns_per_proxy, 0);
}

#[test]
fn test_max_conns_per_proxy_snapshot_clamped_to_2pow20() {
    // server.rs:233: ServerConfigSnapshot clamps max_conns_per_proxy to
    // 2^20 — a u64::MAX value would overflow the i64 normalized field
    // (u64::MAX -> -1) and truncate on 32-bit usize.
    let cfg = ServerConfig {
        max_conns_per_proxy: u64::MAX,
        ..Default::default()
    };
    let snap = ServerConfigSnapshot::from_config(&cfg);
    assert_eq!(snap.max_conns_per_proxy, 1_048_576);

    let cfg = ServerConfig {
        max_conns_per_proxy: 1000,
        ..Default::default()
    };
    let snap = ServerConfigSnapshot::from_config(&cfg);
    assert_eq!(snap.max_conns_per_proxy, 1000);
}

#[test]
fn test_max_custom_domains_per_proxy_parse_and_snapshot_clamp() {
    // Snake + camelCase parse; default 0 = unlimited; snapshot clamps to
    // 2^20 like its siblings (u64::MAX would overflow the i64 field).
    let toml = r#"
bind_port = 7000
max_custom_domains_per_proxy = 128
"#;
    let cfg: ServerConfig = load_server_config_from_str(toml).unwrap();
    assert_eq!(cfg.max_custom_domains_per_proxy, 128);

    let cfg: ServerConfig =
        load_server_config_from_str("bind_port = 7000\nmaxCustomDomainsPerProxy = 64\n").unwrap();
    assert_eq!(cfg.max_custom_domains_per_proxy, 64);

    let cfg: ServerConfig = load_server_config_from_str("bind_port = 7000\n").unwrap();
    assert_eq!(cfg.max_custom_domains_per_proxy, 0);

    let cfg = ServerConfig {
        max_custom_domains_per_proxy: u64::MAX,
        ..Default::default()
    };
    let snap = ServerConfigSnapshot::from_config(&cfg);
    assert_eq!(snap.max_custom_domains_per_proxy, 1_048_576);
}

// ─── Exec token-source validation branches ────────────────────────────

#[test]
fn test_exec_token_source_validation_errors() {
    // server.rs ValueSource::validate error branches: empty command, empty
    // env name, env name containing '='. (File-source errors were already
    // covered; exec had none.)
    let err = load_server_config_from_str(
        r#"
bind_port = 7000
[auth.tokenSource]
type = "exec"
exec = {}
"#,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("exec command cannot be empty"), "got: {err}");

    let err = load_server_config_from_str(
        r#"
bind_port = 7000
[auth.tokenSource]
type = "exec"
exec.command = "/bin/sh"
exec.env = [{ name = "", value = "x" }]
"#,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("exec env name cannot be empty"), "got: {err}");

    let err = load_server_config_from_str(
        r#"
bind_port = 7000
[auth.tokenSource]
type = "exec"
exec.command = "/bin/sh"
exec.env = [{ name = "A=B", value = "x" }]
"#,
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("exec env name cannot contain '='"),
        "got: {err}"
    );

    // A valid exec source still parses.
    let cfg = load_server_config_from_str(
        r#"
bind_port = 7000
[auth.tokenSource]
type = "exec"
exec.command = "/bin/sh"
exec.args = ["-c", "echo secret"]
exec.env = [{ name = "TOKEN", value = "abc" }]
"#,
    )
    .unwrap();
    let exec = cfg.auth.token_source.unwrap().exec.unwrap();
    assert_eq!(exec.command, "/bin/sh");
    assert_eq!(exec.args, vec!["-c".to_string(), "echo secret".to_string()]);
    assert_eq!(exec.env[0].name, "TOKEN");
    assert_eq!(exec.env[0].value, "abc");
}

// ─── Client heartbeat: no clamp (round-8: Go has none) ────────────────

#[test]
fn test_client_heartbeat_huge_values_preserved() {
    // Round-8 blocker: the old 3600 clamp disconnected Go frpc
    // (interval=7200) ↔ Rust frps in a reconnect loop. Go has no clamp, so
    // huge explicit heartbeat values must pass through untouched —
    // overflow protection lives in the watchdog arithmetic
    // (`Duration::from_secs` never panics; tokio sleep/interval saturate),
    // not in config.
    let cfg = load_client_config_from_str(
        r#"
serverAddr = "127.0.0.1"
[transport]
heartbeatInterval = 9999999999
heartbeatTimeout = 9999999999
"#,
    )
    .unwrap();
    assert_eq!(cfg.heartbeat_interval, 9999999999);
    assert_eq!(cfg.heartbeat_timeout, 9999999999);
}

#[test]
fn test_client_heartbeat_preserves_disable_and_go_style_values() {
    // -1 (explicit disable) and normal / Go-default-scale values (90, 3600,
    // 7200) are untouched: no clamp rewrites them.
    let cfg = load_client_config_from_str(
        r#"
serverAddr = "127.0.0.1"
[transport]
heartbeatInterval = -1
heartbeatTimeout = 90
"#,
    )
    .unwrap();
    assert_eq!(cfg.heartbeat_interval, -1);
    assert_eq!(cfg.heartbeat_timeout, 90);

    let cfg = load_client_config_from_str(
        r#"
serverAddr = "127.0.0.1"
[transport]
heartbeatInterval = 7200
heartbeatTimeout = 7200
"#,
    )
    .unwrap();
    assert_eq!(cfg.heartbeat_interval, 7200);
    assert_eq!(cfg.heartbeat_timeout, 7200);
}

// ─── include / includes variants (file.rs) ────────────────────────────

#[test]
fn test_include_singular_alias() {
    // file.rs process_includes: the singular `include` key (string form) is
    // an alias for `includes = ["..."]`.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("frpc.toml"),
        "server_addr = \"127.0.0.1\"\ninclude = \"extra.toml\"\n",
    )
    .unwrap();
    std::fs::write(
        dir.path().join("extra.toml"),
        "server_port = 7001\ntoken = \"inc\"\n",
    )
    .unwrap();
    let cfg = load_client_config(dir.path().join("frpc.toml").to_str().unwrap(), true).unwrap();
    assert_eq!(cfg.server_port, 7001, "include file merged");
    assert_eq!(cfg.token, "inc");
}

#[test]
fn test_includes_glob_pattern_merged() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("frps.toml"),
        "bind_port = 7000\nincludes = [\"conf.d/*.toml\"]\n",
    )
    .unwrap();
    std::fs::create_dir(dir.path().join("conf.d")).unwrap();
    std::fs::write(
        dir.path().join("conf.d").join("a.toml"),
        "vhost_http_port = 8080\n",
    )
    .unwrap();
    std::fs::write(
        dir.path().join("conf.d").join("b.toml"),
        "vhost_https_port = 8443\n",
    )
    .unwrap();
    // Non-matching extension must not be picked up by the glob.
    std::fs::write(dir.path().join("conf.d").join("ignore.txt"), "garbage").unwrap();
    let cfg = load_server_config(dir.path().join("frps.toml").to_str().unwrap(), false).unwrap();
    assert_eq!(cfg.vhost_http_port, 8080);
    assert_eq!(cfg.vhost_https_port, 8443);
}

#[test]
fn test_include_glob_entries_are_processed_in_sorted_order() {
    // glob_in_dir ends with `results.sort()` to mirror `os.ReadDir`, whose
    // contract is "sorted by filename" (`pkg/config/legacy/parse.go:78`,
    // repeated at `pkg/config/load.go:513`). `deep_merge_toml` CONCATENATES
    // arrays (base + overlay), so the merged `[[proxies]]` order *is* the
    // include processing order. Six files, each contributing one proxy, make a
    // filesystem readdir order fail loudly: this APFS returns the six
    // `incN.toml` names in an order like inc2,inc3,inc4,inc5,inc6,inc1, which
    // is not sorted, so deleting `results.sort()` reorders the merged array and
    // reddens this test. The teeth are host-filesystem-conditional, though:
    // they hold only while readdir returns those six names out of sorted order.
    // On a filesystem whose readdir is already name-ordered the same mutant
    // would stay green, so this is a strong check on the hosts we run, not a
    // portable one.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("frpc.toml"),
        "server_addr = \"127.0.0.1\"\nincludes = [\"inc*.toml\"]\n",
    )
    .unwrap();
    for i in 1..=6 {
        std::fs::write(
            dir.path().join(format!("inc{i}.toml")),
            format!(
                "[[proxies]]\nname = \"p{i}\"\ntype = \"tcp\"\nlocal_port = {}\nremote_port = {}\n",
                1000 + i,
                2000 + i
            ),
        )
        .unwrap();
    }
    let cfg = load_client_config(dir.path().join("frpc.toml").to_str().unwrap(), false).unwrap();
    let names: Vec<&str> = cfg.proxies.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(
        names,
        vec!["p1", "p2", "p3", "p4", "p5", "p6"],
        "include glob results must be processed in os.ReadDir (name-sorted) order"
    );
    assert_eq!(cfg.proxies[5].remote_port, 2006);
}

#[test]
fn test_include_array_concatenation_deep_merge() {
    // file.rs deep_merge_toml: arrays CONCATENATE (base + overlay) — the
    // include file's [[proxies]] entries append to the main config's.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("frpc.toml"),
        r#"server_addr = "127.0.0.1"
includes = ["extra.toml"]
[[proxies]]
name = "p1"
type = "tcp"
local_port = 1000
remote_port = 2000
"#,
    )
    .unwrap();
    std::fs::write(
        dir.path().join("extra.toml"),
        r#"[[proxies]]
name = "p2"
type = "tcp"
local_port = 1001
remote_port = 2001
"#,
    )
    .unwrap();
    let cfg = load_client_config(dir.path().join("frpc.toml").to_str().unwrap(), false).unwrap();
    let names: Vec<&str> = cfg.proxies.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(
        names,
        vec!["p1", "p2"],
        "arrays concatenated by deep_merge_toml"
    );
    assert_eq!(cfg.proxies[0].local_port, 1000);
    assert_eq!(cfg.proxies[1].local_port, 1001);
    assert_eq!(cfg.proxies[1].remote_port, 2001);
}

#[test]
fn test_include_missing_directory_is_fatal() {
    // file.rs process_includes: Go frp fails when the include's directory is
    // missing (load.go LoadAdditionalClientConfigs os.Stat error;
    // legacy/client.go:393 "include: directory of %s not exist"). A typo'd
    // glob path must not silently merge nothing — that drops proxy configs
    // without a word.
    let dir = tempfile::tempdir().unwrap();
    let main_path = dir.path().join("frpc.toml");
    std::fs::write(
        &main_path,
        "server_addr = \"127.0.0.1\"\nincludes = [\"nope.d/*.toml\"]\n",
    )
    .unwrap();
    let err = load_client_config(main_path.to_str().unwrap(), false)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("directory of") && err.contains("not exist"),
        "missing include dir must be fatal, got: {err}"
    );
}

#[test]
fn test_include_unparseable_file_is_fatal() {
    // A matched include file that fails to parse aborts loading (Go "load
    // additional config from %s error") instead of warn-and-skip.
    let dir = tempfile::tempdir().unwrap();
    let main_path = dir.path().join("frpc.toml");
    std::fs::write(
        &main_path,
        "server_addr = \"127.0.0.1\"\nincludes = [\"conf.d/*.toml\"]\n",
    )
    .unwrap();
    std::fs::create_dir(dir.path().join("conf.d")).unwrap();
    std::fs::write(dir.path().join("conf.d").join("bad.toml"), "not [[[ toml").unwrap();
    let err = load_client_config(main_path.to_str().unwrap(), false)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("include") && err.contains("bad.toml"),
        "unparseable include file must be fatal, got: {err}"
    );
}

#[test]
fn test_include_zero_match_glob_is_silent() {
    // Go parity: a glob that matches nothing in an EXISTING directory is not
    // an error (the loop just appends nothing). Only the missing-directory
    // and per-file failure cases are fatal.
    let dir = tempfile::tempdir().unwrap();
    let main_path = dir.path().join("frpc.toml");
    std::fs::write(
        &main_path,
        "server_addr = \"127.0.0.1\"\nincludes = [\"conf.d/*.toml\"]\n",
    )
    .unwrap();
    std::fs::create_dir(dir.path().join("conf.d")).unwrap();
    let cfg = load_client_config(main_path.to_str().unwrap(), false).unwrap();
    assert_eq!(cfg.server_addr, "127.0.0.1");
}

// ─── Type-mismatch values ─────────────────────────────────────────────

#[test]
fn test_type_mismatch_toml_values_rejected() {
    // A string where a bool is required (tcp_mux) and a string where an
    // integer is required (bind_port) fail deserialization in the pipeline
    // instead of being silently coerced.
    let err = load_client_config_from_str("server_addr = '127.0.0.1'\ntcp_mux = \"true\"\n")
        .unwrap_err()
        .to_string();
    assert!(err.contains("config validation error"), "got: {err}");

    let err = load_server_config_from_str("bind_port = \"7000\"\n")
        .unwrap_err()
        .to_string();
    assert!(err.contains("config validation error"), "got: {err}");
}

#[test]
fn test_ini_yes_no_bool_inference() {
    // format.rs infer_ini_value is lossless: `yes`/`no` are NOT the canonical
    // rendering of a boolean, so they stay text here and the *target field*
    // decides. A string field receives `yes` verbatim — what Go's legacy INI
    // loader gives it (`ini.v1` `Key.String()`, struct.go:164) — where the old
    // inference rewrote it to `true` before serde ever saw the field.
    let value =
        super::format::parse_to_toml_value("a = yes\nb = no\n", super::format::ConfigFormat::Ini)
            .unwrap();
    let table = value.as_table().unwrap();
    assert_eq!(table.get("a"), Some(&toml::Value::String("yes".into())));
    assert_eq!(table.get("b"), Some(&toml::Value::String("no".into())));
    // The canonical spellings are still inferred.
    let value = super::format::parse_to_toml_value(
        "a = true\nb = false\n",
        super::format::ConfigFormat::Ini,
    )
    .unwrap();
    let table = value.as_table().unwrap();
    assert_eq!(table.get("a"), Some(&toml::Value::Boolean(true)));
    assert_eq!(table.get("b"), Some(&toml::Value::Boolean(false)));

    // Through the full pipeline: login_fail_exit = yes → true, tcp_mux = no
    // → false.
    let cfg = load_client_ini("server_addr = \"127.0.0.1\"\nlogin_fail_exit = yes\ntcp_mux = no\n")
        .unwrap();
    assert!(cfg.login_fail_exit);
    assert!(!cfg.tcp_mux);
}

/// The load-path `--allow-unsafe` gate is fail-closed over **both** client
/// fields the daemon can gate at construction: `auth.tokenSource` and
/// `auth.oidc.tokenSource`. Go's verdict for the OIDC spelling is measured on
/// v0.71.0: a minimal `[auth] method = "token"` config carrying
/// `[auth.oidc.tokenSource] type = "exec"` makes `frpc verify` rc 1 with
/// `unsafe feature "TokenSourceExec" is not enabled. …` and rc 0 once
/// `--allow-unsafe TokenSourceExec` is passed (so that refusal *is* the gate);
/// the `auth.tokenSource` spelling behaves the same (frps/frpc `verify` → rc 1,
/// see `frps/tests/cli_exit_codes.rs` and `frpc/tests/cli_exit_codes.rs`).
///
/// The field *set* is the daemon's, but the *condition* is not: this gate
/// refuses either spelling on `verify` regardless of `auth_method`, while the
/// daemon gates `auth.tokenSource` unconditionally and `auth.oidc_token_source`
/// only under `auth_method == AuthMethod::Oidc` (`frp-client/src/service.rs:661-664`)
/// — measured, `frpc -c` on the `method = "token"` OIDC config above starts and
/// logs its connection attempts where Go's `frpc -c` exits 1 on the gate line.
/// The third loop arm pins the fail-closed condition.
///
/// The configs are parsed with `toml::from_str` rather than through
/// `load_client_config_with_presence*`, so the test pins the *gate's* field set
/// independently of loader validation and of the normalizer that rewrites
/// `[auth.oidc] tokenSource` into `oidc_token_source`.
///
/// Teeth: deleting `oidc_token_source` from `check_client_unsafe_features` makes
/// the second and third loop arms fail (their `expect_err` returns `Ok(())`);
/// narrowing that arm to `auth.method == "oidc"` fails only the third.
#[test]
fn check_client_unsafe_features_gates_both_token_source_spellings() {
    use crate::unsafe_features::{UnsafeFeatures, TOKEN_SOURCE_EXEC};

    let token_source: ClientConfig = toml::from_str(
        r#"
server_addr = "127.0.0.1"
server_port = 7000

[auth]
method = "token"

[auth.tokenSource]
type = "exec"

[auth.tokenSource.exec]
command = "/bin/echo"
"#,
    )
    .expect("parse the auth.tokenSource config");
    let oidc_source: ClientConfig = toml::from_str(
        r#"
server_addr = "127.0.0.1"
server_port = 7000

[auth]
method = "oidc"

[auth.oidc_token_source]
type = "exec"

[auth.oidc_token_source.exec]
command = "/bin/echo"
"#,
    )
    .expect("parse the auth.oidc tokenSource config");
    // The same OIDC spelling under `method = "token"`: the daemon skips it
    // (its `auth_method == AuthMethod::Oidc` branch), this gate must not.
    let oidc_source_token_method: ClientConfig = toml::from_str(
        r#"
server_addr = "127.0.0.1"
server_port = 7000

[auth]
method = "token"

[auth.oidc_token_source]
type = "exec"

[auth.oidc_token_source.exec]
command = "/bin/echo"
"#,
    )
    .expect("parse the method=token auth.oidc tokenSource config");

    let blocked = UnsafeFeatures::new(&[]);
    let allowed = UnsafeFeatures::new(&[TOKEN_SOURCE_EXEC]);
    for (label, cfg) in [
        ("auth.tokenSource", &token_source),
        ("auth.oidc.tokenSource", &oidc_source),
        (
            "auth.oidc.tokenSource under method = \"token\"",
            &oidc_source_token_method,
        ),
    ] {
        let err = super::check_client_unsafe_features(cfg, &blocked)
            .expect_err(&format!("{label} exec must be refused without the feature"));
        assert!(err.contains("TokenSourceExec"), "{label}: {err}");
        assert!(
            super::check_client_unsafe_features(cfg, &allowed).is_ok(),
            "{label} exec must be accepted with --allow-unsafe TokenSourceExec"
        );
    }

    // A `file` source is not an unsafe feature and is never gated.
    let file_source: ClientConfig = toml::from_str(
        r#"
server_addr = "127.0.0.1"
server_port = 7000

[auth.tokenSource]
type = "file"

[auth.tokenSource.file]
path = "/tmp/does-not-matter"
"#,
    )
    .expect("parse the auth.tokenSource=file config");
    assert!(
        super::check_client_unsafe_features(&file_source, &blocked).is_ok(),
        "file sources are not unsafe features"
    );
}

/// **A verbatim `[name]` section wins a collision with a top-level scalar.**
///
/// Go keeps the two namespaces apart: `includes = 1` (a default-section key) and
/// an `[includes]` *section* are independent in `gopkg.in/ini.v1`, and the legacy
/// reader ignores every default-section key (`LoadAllProxyConfsFromIni` skips
/// `ini.DefaultSection`, `pkg/config/legacy/client.go:255-257`) — the sections
/// are what it parses. `insert_ini_section` (`frp-core/src/config/format.rs:376`)
/// used to keep the scalar and drop the section's keys, which hid a real
/// `[includes]` section from the typeless-visitor guard and the collector, and
/// then the `.ini`-only scalar scrub
/// (`frp-core/src/config/file.rs:521`) deleted the scalar too. Measured on Go
/// v0.71.0, the three shapes below are rc 1 in **both** loader modes with Go's
/// own message, and the typed port-carrying one is rc 0 with one `tcp` proxy
/// *named* `includes`.
#[test]
fn legacy_ini_scalar_and_section_collision_keeps_the_section_like_go() {
    let head = "[common]\nserver_addr = 127.0.0.1\nserver_port = 7000\n";
    for (body, expected) in [
        (
            "includes = 1\n[includes]\nrole = \"visitor\"\nserver_name = s\n",
            "failed to parse visitor includes, err: type shouldn't be empty",
        ),
        (
            "includes = 1\n[includes]\ntype = \"custom\"\nlocal_port = 8080\nremote_port = 18080\n",
            "proxy 'includes': invalid proxy_type 'custom'",
        ),
        (
            "include = 1\n[include]\nrole = \"visitor\"\nserver_name = s\n",
            "failed to parse visitor include, err: type shouldn't be empty",
        ),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("frpc.ini");
        std::fs::write(&path, format!("{body}{head}")).unwrap();
        for strict in [false, true] {
            let err = format!(
                "{}",
                load_client_config(path.to_str().unwrap(), strict)
                    .expect_err("the section Go parses refuses the file")
            );
            assert!(
                err.contains(expected),
                "strict={strict}, body {body:?}: expected {expected:?}, got {err}"
            );
            assert!(
                !err.contains("invalid type: integer"),
                "the scalar must not reach the v1 decoder: {err}"
            );
        }
    }

    // A typed, port-carrying collision is a proxy in Go, not a settings table:
    // rc 0 in both modes with exactly one `tcp` proxy named `includes`.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("frpc.ini");
    std::fs::write(
        &path,
        format!("includes = 1\n[includes]\nlocal_port = 8080\nremote_port = 18080\n{head}"),
    )
    .unwrap();
    for strict in [false, true] {
        let cfg = load_client_config(path.to_str().unwrap(), strict).unwrap();
        assert_eq!(cfg.proxies.len(), 1, "strict={strict}");
        assert_eq!(cfg.proxies[0].name, "includes", "strict={strict}");
        assert_eq!(cfg.proxies[0].local_port, 8080, "strict={strict}");
    }

    // The server has no legacy proxy dispatch, so every collision there is
    // inert: Go is rc 0 in both modes for all four shapes (measured).
    let server_head = "[common]\nbind_port = 7000\ntoken = t\n";
    for body in [
        "includes = 1\n[includes]\nrole = \"visitor\"\nserver_name = s\n",
        "includes = 1\n[includes]\ntype = \"custom\"\nlocal_port = 8080\nremote_port = 18080\n",
        "includes = 1\n[includes]\nlocal_port = 8080\nremote_port = 18080\n",
        "include = 1\n[include]\nrole = \"visitor\"\n",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("frps.ini");
        std::fs::write(&path, format!("{body}{server_head}")).unwrap();
        for strict in [false, true] {
            load_server_config(path.to_str().unwrap(), strict)
                .unwrap_or_else(|e| panic!("server {body:?}, strict={strict}: {e}"));
        }
    }
}

/// **Go's `[common] start` filter runs before role dispatch and collection.**
///
/// `LoadAllProxyConfsFromIni` builds `startProxy` from the list and skips every
/// named section that is not in it (`pkg/config/legacy/client.go:227-262`), and
/// the generated `{prefix}_{i}` range sections are filtered by their *generated*
/// names. The role refusal (`frp-core/src/config/normalize.rs:2185`) and the
/// collector's candidate list (`frp-core/src/config/normalize.rs:2154`) both
/// apply it now; the `[common] start` list is read after the hoist
/// (`frp-core/src/config/normalize.rs:1183-1184`,
/// `ini_start_names` at `frp-core/src/config/normalize.rs:2484`, which trims each
/// element exactly like Go's `Key.Strings(",")`).
///
/// One half remains pre-existing: a *non-started* section that is not a
/// collector candidate stays a top-level table, so frp-rs's own strict checker
/// still reports it (`unknown field "p1"`) where Go's legacy reader ignores it —
/// the same residue as `[foo] role = "weird"` with no `[common]` and the `a12`/
/// `a13` rows of the round-5 matrix. Non-strict mode matches Go.
#[test]
fn legacy_ini_common_start_is_applied_before_role_and_collection() {
    let start = "[common]\nserver_addr = 127.0.0.1\nserver_port = 7000\nstart = ";
    let p2 = "[p2]\nlocal_port = 9090\nremote_port = 19090\n";
    let bad_p1 = "[p1]\nrole = \"weird\"\nlocal_port = 8080\nremote_port = 18080\n";

    // `start = p2` skips the bad-role section: rc 0 in both modes, one proxy.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("frpc.ini");
    std::fs::write(&path, format!("{start}p2\n{bad_p1}{p2}")).unwrap();
    for strict in [false, true] {
        let cfg = load_client_config(path.to_str().unwrap(), strict).unwrap();
        assert_eq!(cfg.proxies.len(), 1, "strict={strict}");
        assert_eq!(cfg.proxies[0].name, "p2", "strict={strict}");
    }

    // The same section started is refused with Go's message.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("frpc.ini");
    std::fs::write(&path, format!("{start}p1\n{bad_p1}{p2}")).unwrap();
    for strict in [false, true] {
        let err = format!(
            "{}",
            load_client_config(path.to_str().unwrap(), strict).unwrap_err()
        );
        assert!(
            err.contains("proxy p1 role should be 'server' or 'visitor'"),
            "strict={strict}: {err}"
        );
    }

    // A comma list is trimmed element by element: `p2, p1` starts `p1`, and the
    // refusal names `p1` without the leading space (measured on Go v0.71.0).
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("frpc.ini");
    std::fs::write(&path, format!("{start}p2, p1\n{bad_p1}{p2}")).unwrap();
    for strict in [false, true] {
        let err = format!(
            "{}",
            load_client_config(path.to_str().unwrap(), strict).unwrap_err()
        );
        assert!(
            err.contains("proxy p1 role should be 'server' or 'visitor'"),
            "strict={strict}: {err}"
        );
        assert!(!err.contains("proxy  p1"), "strict={strict}: {err}");
    }

    // A skipped section is not *type*-validated either: a bad proxy type in a
    // non-started section is rc 0 on Go (measured).
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("frpc.ini");
    std::fs::write(
        &path,
        format!("{start}p2\n[p1]\ntype = \"custom\"\nlocal_port = 8080\nremote_port = 18080\n{p2}"),
    )
    .unwrap();
    for strict in [false, true] {
        let cfg = load_client_config(path.to_str().unwrap(), strict).unwrap();
        assert_eq!(cfg.proxies.len(), 1, "strict={strict}");
        assert_eq!(cfg.proxies[0].name, "p2", "strict={strict}");
    }

    // The `range:` filter uses the generated names: `start = p2` skips the whole
    // template (Go rc 0), while `start = p_0` reaches the generated refusal.
    let range_bad = "[range:p]\nrole = \"weird\"\nlocal_port = 8080\nremote_port = 18080\n";
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("frpc.ini");
    std::fs::write(&path, format!("{start}p2\n{range_bad}{p2}")).unwrap();
    for strict in [false, true] {
        let cfg = load_client_config(path.to_str().unwrap(), strict).unwrap();
        assert_eq!(cfg.proxies.len(), 1, "strict={strict}");
        assert_eq!(cfg.proxies[0].name, "p2", "strict={strict}");
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("frpc.ini");
    std::fs::write(&path, format!("{start}p_0\n{range_bad}")).unwrap();
    for strict in [false, true] {
        let err = format!(
            "{}",
            load_client_config(path.to_str().unwrap(), strict).unwrap_err()
        );
        assert!(
            err.contains("proxy p_0 role should be 'server' or 'visitor'"),
            "strict={strict}: {err}"
        );
    }

    // The typeless-visitor guard is start-aware as well: with `start = p2` the
    // skipped section is not refused. Go is rc 0 in both modes; non-strict here
    // matches, while strict keeps frp-rs's own `unknown field` residue.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("frpc.ini");
    std::fs::write(&path, format!("{start}p2\n[p1]\nrole = \"visitor\"\n{p2}")).unwrap();
    let cfg = load_client_config(path.to_str().unwrap(), false).unwrap();
    assert_eq!(cfg.proxies.len(), 1, "non-strict");
    assert_eq!(cfg.proxies[0].name, "p2", "non-strict");
    let err = format!(
        "{}",
        load_client_config(path.to_str().unwrap(), true).unwrap_err()
    );
    assert!(err.contains("unknown field \"p1\""), "{err}");
    assert!(
        !err.contains("failed to parse visitor p1"),
        "the guard skips a section Go does not start: {err}"
    );

    // A non-candidate settings root is skipped too (`[includes] role = visitor`
    // with `start = p2` is rc 0 in both modes on Go, measured).
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("frpc.ini");
    std::fs::write(
        &path,
        format!("{start}p2\n[includes]\nrole = \"visitor\"\nserver_name = s\n{p2}"),
    )
    .unwrap();
    for strict in [false, true] {
        let cfg = load_client_config(path.to_str().unwrap(), strict).unwrap();
        assert_eq!(cfg.proxies.len(), 1, "strict={strict}");
        assert_eq!(cfg.proxies[0].name, "p2", "strict={strict}");
    }
}

/// **`start` is only a legacy-`.ini` filter.** A `[common]`-less `.ini` is Go's
/// v1 path (`DetectLegacyINIFormat`, `pkg/config/load.go:65`), where the role
/// switch does not exist: `[foo] role = "weird"` is rc 1 **strict** with
/// `json: unknown field "foo"` but **rc 0 non-strict** (measured on Go v0.71.0).
/// The role scan is therefore gated on the `[common]` presence captured before
/// the hoist (`frp-core/src/config/normalize.rs:1183-1184`) and must not refuse
/// the file where Go loads it.
#[test]
fn nocommon_ini_weird_role_is_not_a_role_refusal() {
    let body = "server_addr = \"127.0.0.1\"\nserver_port = 7000\n[foo]\nrole = \"weird\"\n";
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("frpc.ini");
    std::fs::write(&path, body).unwrap();
    let cfg = load_client_config(path.to_str().unwrap(), false)
        .expect("Go's v1 decoder loads this non-strict: rc 0");
    assert!(cfg.proxies.is_empty(), "the v1 path has no proxy sections");
    let err = format!(
        "{}",
        load_client_config(path.to_str().unwrap(), true).unwrap_err()
    );
    assert!(err.contains("unknown field \"foo\""), "{err}");
    assert!(
        !err.contains("role should be 'server' or 'visitor'"),
        "the legacy role refusal must not fire without [common]: {err}"
    );

    // A `[[proxies]]` array-of-tables header next to it keeps the same rc
    // parity (measured on Go v0.71.0: strict rc 1 `json: unknown field "foo"`,
    // non-strict rc 0). Only the load outcome is pinned: frp-rs's v1 `.ini`
    // reader spells that header as a section literally named `[proxies]`, so the
    // element is not addressed as `proxies[0]` (pre-existing, out of scope here).
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("frpc.ini");
    std::fs::write(
        &path,
        format!("{body}[[proxies]]\nname = \"p\"\ntype = \"tcp\"\nlocal_port = 8080\nremote_port = 18080\n"),
    )
    .unwrap();
    let cfg = load_client_config(path.to_str().unwrap(), false)
        .expect("Go's v1 decoder loads this non-strict: rc 0");
    assert!(!cfg.proxies.is_empty());
    let err = format!(
        "{}",
        load_client_config(path.to_str().unwrap(), true).unwrap_err()
    );
    assert!(err.contains("unknown field \"foo\""), "{err}");
    assert!(
        !err.contains("role should be 'server' or 'visitor'"),
        "the legacy role refusal must not fire without [common]: {err}"
    );
}

/// **A default-section string `includes` is still expanded.** Go's legacy reader
/// ignores default-section keys, so the expansion here is a pre-existing frp-rs
/// extension (the Go-measured shape is rc 0 with no proxies), but it must not be
/// *silently dropped*: the `.ini`-only scalar scrub
/// (`frp-core/src/config/file.rs:521`, `is_scalar` at
/// `frp-core/src/config/file.rs:523`) accepts Integer/Float/Boolean/Datetime and
/// must keep leaving a String alone. A mutant that also accepts `String` deletes
/// the include pattern and this file loads with zero proxies.
#[test]
fn legacy_ini_default_section_string_include_is_still_expanded() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("sub.ini"),
        "[p1]\nlocal_port = 8080\nremote_port = 18080\n",
    )
    .unwrap();
    let path = dir.path().join("frpc.ini");
    std::fs::write(
        &path,
        "includes = \"sub.ini\"\n[common]\nserver_addr = 127.0.0.1\nserver_port = 7000\n",
    )
    .unwrap();
    for strict in [false, true] {
        let cfg = load_client_config(path.to_str().unwrap(), strict)
            .unwrap_or_else(|e| panic!("strict={strict}: {e}"));
        assert_eq!(cfg.proxies.len(), 1, "strict={strict}");
        assert_eq!(cfg.proxies[0].name, "p1", "strict={strict}");
        assert_eq!(cfg.proxies[0].local_port, 8080, "strict={strict}");
    }

    // A scalar sibling stays scrubbed (Go ignores it in the default section too,
    // and frp-rs must not turn it into the v1 `includes` type error).
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("frpc.ini");
    std::fs::write(
        &path,
        "includes = 1\n[common]\nserver_addr = 127.0.0.1\nserver_port = 7000\n",
    )
    .unwrap();
    for strict in [false, true] {
        load_client_config(path.to_str().unwrap(), strict)
            .unwrap_or_else(|e| panic!("scalar includes, strict={strict}: {e}"));
    }
}

/// **Item 4: a DefaultSection `start = p2` beside a `[start]` section keeps the
/// section.**
///
/// This is the `w8_start_scalar_plus_start_section.ini` shape measured against
/// Go v0.71.0: a DefaultSection key is not part of the legacy common config
/// (`UnmarshalClientConfFromIni` reads `[common]` alone), so Go's `start` list
/// stays empty (`startAll`) and the `[start]` section runs as an ordinary typeless
/// legacy proxy — 1 proxy named `start` in a real frps+frpc run
/// (`[start] start proxy success`). Round 5 kept that section, round 6 deleted it
/// (0 proxies) with the unconditional `start` removal, and round 7 restored it;
/// this pin fixes the exact shape in both loader modes.
#[test]
fn legacy_ini_default_section_start_beside_start_section_both_modes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("frpc.ini");
    std::fs::write(
        &path,
        "start = p2\n[common]\nserver_addr = 127.0.0.1\nserver_port = 7000\n\
         [start]\nlocal_port = 18080\nremote_port = 19080\n",
    )
    .unwrap();
    for strict in [false, true] {
        let cfg = load_client_config(path.to_str().unwrap(), strict)
            .unwrap_or_else(|e| panic!("strict={strict}: {e}"));
        assert_eq!(cfg.proxies.len(), 1, "strict={strict}");
        assert_eq!(cfg.proxies[0].name, "start", "strict={strict}");
        assert!(
            cfg.start.is_empty(),
            "strict={strict}: Go's [common] list is empty, so every section starts"
        );
    }
}

/// **[common]-less `.ini` with a scalar `start` beside `[start]`: the v1 path.**
///
/// With no `[common]` section Go's `DetectLegacyINIFormat`
/// (`pkg/config/load.go:65`) is false, so the file is not read by the legacy
/// reader at all: the scalar `start = p2` reaches the v1 decode and Go is rc 1 in
/// both loader modes (`json: cannot unmarshal string into Go value of type
/// v1.rawClientConfig`). frp-rs keeps its v1 reading instead — rc 0, zero proxies
/// (the scalar wins the section-name collision, `insert_ini_section`,
/// `frp-core/src/config/format.rs:376`). This pin records the measured,
/// deliberate divergence so a later change cannot pick it up silently.
#[test]
fn legacy_ini_without_common_start_scalar_is_a_v1_shape() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("frpc.ini");
    std::fs::write(
        &path,
        "start = p2\n[start]\ntype = tcp\nlocal_port = 8080\nremote_port = 18080\n",
    )
    .unwrap();
    for strict in [false, true] {
        let cfg = load_client_config(path.to_str().unwrap(), strict)
            .unwrap_or_else(|e| panic!("strict={strict}: {e}"));
        assert_eq!(
            cfg.proxies.len(),
            0,
            "strict={strict}: frp-rs v1 reading keeps the scalar and drops the section"
        );
    }
}

/// **Item 5: an unknown key merged out of `[common]` is still refused in strict
/// mode (recorded divergence, `c1.ini`).**
///
/// Go v0.71.0 reads `[common]` into a typed struct that ignores a key it does not
/// name, so `c1.ini` (`[common] server_addr + zzz_unknown_common = 1`) is rc 0 in
/// both loader modes. frp-rs is rc 0 loose but rc 1 strict
/// (`unknown field "zzz_unknown_common"`), because the `[common]` hoist
/// (`frp-core/src/config/normalize.rs:1185`) moves the key to the top level before
/// the top-level strict walk and the `.ini` exemption does not reach it. The
/// item's Done-when allows the measurement instead of a fix — exempting the keys
/// the merge created would also blind the top-level check to a genuine v1 typo
/// spelled under `[common]`. The recommended `docs/config.md` wording is carried
/// in the batch report; this pin keeps the residual visible.
#[test]
fn legacy_ini_common_unknown_key_residual_both_modes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("c1.ini");
    std::fs::write(
        &path,
        "[common]\nserver_addr = 127.0.0.1\nserver_port = 7000\nzzz_unknown_common = 1\n",
    )
    .unwrap();
    assert!(
        load_client_config(path.to_str().unwrap(), false).is_ok(),
        "loose mode drops it, exactly like Go"
    );
    let err = format!(
        "{}",
        load_client_config(path.to_str().unwrap(), true).unwrap_err()
    );
    assert!(
        err.contains("unknown field \"zzz_unknown_common\""),
        "strict residual: Go is rc 0 here, frp-rs reports the merged top-level key: {err}"
    );
}

/// **Item 2: a `[common] includes` is expanded, exactly as Go's legacy reader
/// expands it.**
///
/// The legacy reader fills its include list from `[common]` alone
/// (`UnmarshalClientConfFromIni` reads only that section,
/// `pkg/config/legacy/client.go:172-200`; `ParseClientConfig` then renders
/// `cfg.IncludeConfigFiles`, `pkg/config/legacy/parse.go:50`), and the included
/// sections join the same parse buffer (`LoadAllProxyConfsFromIni`,
/// `pkg/config/legacy/parse.go:59`) — so an include named inside `[common]`
/// contributes proxies. frp-rs ran `process_includes` on the top level before
/// the `[common]` hoist and therefore never saw the nested key: `x12_main.ini`
/// was rc 0 with zero proxies against Go rc 1 (the include was never read).
/// Read it from `[common]` while the raw dialect is still visible
/// (`frp-core/src/config/file.rs:265`).
#[test]
fn legacy_ini_common_include_is_expanded_like_go() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("sub.ini"),
        "[p1]\ntype = tcp\nlocal_port = 8080\nremote_port = 18080\n",
    )
    .unwrap();
    let path = dir.path().join("frpc.ini");
    std::fs::write(
        &path,
        "[common]\nserver_addr = 127.0.0.1\nserver_port = 7000\nincludes = \"sub.ini\"\n",
    )
    .unwrap();
    for strict in [false, true] {
        let cfg = load_client_config(path.to_str().unwrap(), strict)
            .unwrap_or_else(|e| panic!("strict={strict}: {e}"));
        assert_eq!(cfg.proxies.len(), 1, "strict={strict}");
        assert_eq!(cfg.proxies[0].name, "p1", "strict={strict}");
        assert_eq!(cfg.proxies[0].local_port, 8080, "strict={strict}");
        assert_eq!(cfg.proxies[0].remote_port, 18080, "strict={strict}");
    }
}

/// **Item 2: a `[common]` include whose directory is missing aborts the load,
/// like Go.**
///
/// `x12_main.ini` (`[common] includes = <unreadable pattern>`) is rc 1 in both
/// Go loader modes (`getIncludeContents error: ...`; the pattern's directory is
/// checked in `ClientCommonConf.Validate`, `pkg/config/legacy/client.go:393`,
/// `include: directory of %s not exist`). frp-rs was rc 0 because the nested
/// include was never read; the wording of its own error is
/// `include: directory of <dir> not exist (included by pattern <p>)`
/// (`frp-core/src/config/file.rs:426`), but the load must fail. A mutant that
/// drops the `[common]` extraction reads zero patterns and returns `Ok`.
///
/// The `missing/` spelling is the trailing-separator case: Go's `Dir` drops the
/// trailing separator and checks `missing` (`filepath.Dir("missing/") ==
/// "missing"`), while the old `base_dir.join(pattern).parent()` rule took the
/// parent of the *join result* — a path that still ends in a separator, so the
/// parent was the (existing) config directory and the missing directory went
/// unnoticed. That spelling was rc 0 before round 5 in the relative and absolute
/// `-c` shapes; it must refuse now.
#[test]
fn legacy_ini_common_include_missing_dir_refuses_like_go() {
    let dir = tempfile::tempdir().unwrap();
    for pattern in ["no_such_dir/missing.ini", "missing/"] {
        let path = dir.path().join("frpc.ini");
        std::fs::write(
            &path,
            format!(
                "[common]\nserver_addr = 127.0.0.1\nserver_port = 7000\n\
                 includes = \"{pattern}\"\n"
            ),
        )
        .unwrap();
        for strict in [false, true] {
            let err = format!(
                "{}",
                load_client_config(path.to_str().unwrap(), strict).unwrap_err()
            );
            assert!(
                err.contains("include:"),
                "pattern={pattern} strict={strict}: a [common] include must be attempted: {err}"
            );
        }
    }
}

/// **Item 2 / F2: a `[common] includes` *glob* expands, exactly as Go's
/// `getIncludeContents` does.**
///
/// `getIncludeContents` (`pkg/config/legacy/parse.go:68-97`) resolves each
/// pattern with `filepath.Match` over the directory listing, so
/// `includes = "sub*.ini"` is a real glob: with `sub_bad.ini`
/// (`[p1] role = "visitor"`) beside the config, Go v0.71.0 is rc 1 in both
/// loader modes (`failed to parse visitor p1, err: type shouldn't be empty`).
/// frp-rs's [`process_includes`] uses the same single-`*`-per-component glob
/// (`glob_in_dir`, `frp-core/src/config/file.rs:869`), so the matched file must
/// be merged and refused the same way.
#[test]
fn legacy_ini_common_include_glob_is_expanded_like_go() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("sub_bad.ini"), "[p1]\nrole = \"visitor\"\n").unwrap();
    let path = dir.path().join("frpc.ini");
    std::fs::write(
        &path,
        "[common]\nserver_addr = 127.0.0.1\nserver_port = 7000\nincludes = \"sub*.ini\"\n",
    )
    .unwrap();
    for strict in [false, true] {
        let err = format!(
            "{}",
            load_client_config(path.to_str().unwrap(), strict).unwrap_err()
        );
        assert!(
            err.contains("failed to parse visitor p1") && err.contains("type shouldn't be empty"),
            "strict={strict}: the glob must expand and the included visitor be refused: {err}"
        );
    }
}

/// **Round-8 F2(a): the `*`-suffix half of the legacy glob is load-bearing.**
///
/// Go builds the match pattern as `filepath.Join(absDir, filepath.Base(path))`
/// and tests it with `filepath.Match` (`pkg/config/legacy/parse.go:87`), so
/// everything after the `*` is a literal suffix that must still match. A test
/// that only kept `name.starts_with(prefix)` (`frp-core/src/config/file.rs:918`)
/// survived the whole suite because the extension pre-filter
/// (`frp-core/src/config/file.rs:908-916`) already rejects the obvious cases
/// (e.g. `z*.ini` against `zebra.txt`, where the extensions differ). This pin
/// uses `z*ini`: the star is followed by no `.`, so `Path::extension()` is
/// `None` and the pre-filter is skipped — only the suffix test can reject
/// `zebra.txt`, whose detector body would otherwise merge and fail the load.
/// Measured: GO v0.71.0 rc 0 and HEAD r8 rc 0 for `z*ini` (and for `z*.ini`),
/// where `z*` and `*a.txt` are rc 1 in both (the `*.txt` pattern carries the
/// extension `txt`, so the pre-filter passes there).
#[test]
fn legacy_ini_common_include_glob_suffix_is_matched_like_go() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("zebra.txt"), "[p1]\nrole = \"visitor\"\n").unwrap();
    let path = dir.path().join("frpc.ini");
    std::fs::write(
        &path,
        "[common]\nserver_addr = 127.0.0.1\nserver_port = 7000\nincludes = \"z*ini\"\n",
    )
    .unwrap();
    for strict in [false, true] {
        let cfg = load_client_config(path.to_str().unwrap(), strict).unwrap_or_else(|e| {
            panic!("strict={strict}: `z*ini` matches nothing, so the load must succeed: {e}")
        });
        assert!(
            cfg.proxies.is_empty(),
            "strict={strict}: `z*ini` must not match `zebra.txt` — Go's Match requires \
             the `ini` suffix after the star"
        );
    }
}

/// **Round-7 F2: a `[common] includes` naming a symlink-to-directory refuses
/// like Go, because the directory filter uses each entry's *own* type.**
///
/// Go's `getIncludeContents` enumerates with `os.ReadDir` and skips only real
/// directory entries — `if fi.IsDir() { continue }`
/// (`pkg/config/legacy/parse.go:83`), where `DirEntry.IsDir()` is the directory
/// entry's own type and is **false for a symlink whatever it points at**. So a
/// symlink that resolves to a directory is matched, read, and fails the load.
/// Measured on Go v0.71.0, both loader modes and all three `-c` forms:
/// `includes = "lnk"` (with `lnk -> realdir`) is rc 1 `getIncludeContents
/// error: render extra config <abs>/lnk error: read <abs>/lnk: is a
/// directory`, where frp-rs's old `Path::is_file()` filter made it rc 0
/// (nothing matched at all). This pin fixes rc 1 in both loader modes.
#[cfg(unix)]
#[test]
fn legacy_ini_common_include_symlink_to_dir_refuses_like_go() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("realdir")).unwrap();
    std::fs::write(
        dir.path().join("realdir").join("x.ini"),
        "[p1]\ntype = tcp\nlocal_port = 8080\nremote_port = 18080\n",
    )
    .unwrap();
    std::os::unix::fs::symlink("realdir", dir.path().join("lnk")).unwrap();
    let path = dir.path().join("frpc.ini");
    std::fs::write(
        &path,
        "[common]\nserver_addr = 127.0.0.1\nserver_port = 7000\nincludes = \"lnk\"\n",
    )
    .unwrap();
    for strict in [false, true] {
        let err = format!(
            "{}",
            load_client_config(path.to_str().unwrap(), strict).unwrap_err()
        );
        assert!(
            err.contains("include: read included file") && err.contains("Is a directory"),
            "strict={strict}: a symlink to a directory must be matched and read, so the \
             read fails like Go's `read <abs>/lnk: is a directory`: {err}"
        );
    }
}

/// **Round-7 F2: a `[common] includes` naming a dangling symlink refuses like
/// Go, for the same reason.**
///
/// `DirEntry::is_dir()` is false for a symlink even when its target does not
/// exist, so Go matches `dangling.ini -> nowhere.ini` and fails when it reads
/// it. Measured on v0.71.0, both loader modes and all three `-c` forms: rc 1
/// `getIncludeContents error: render extra config <abs>/dangling.ini error:
/// open <abs>/dangling.ini: no such file or directory`; the old `is_file()`
/// filter made frp-rs rc 0.
#[cfg(unix)]
#[test]
fn legacy_ini_common_include_dangling_symlink_refuses_like_go() {
    let dir = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink("nowhere.ini", dir.path().join("dangling.ini")).unwrap();
    let path = dir.path().join("frpc.ini");
    std::fs::write(
        &path,
        "[common]\nserver_addr = 127.0.0.1\nserver_port = 7000\nincludes = \"dangling.ini\"\n",
    )
    .unwrap();
    for strict in [false, true] {
        let err = format!(
            "{}",
            load_client_config(path.to_str().unwrap(), strict).unwrap_err()
        );
        assert!(
            err.contains("include: read included file")
                && err.contains("No such file or directory"),
            "strict={strict}: a dangling symlink must be matched and read, so the read \
             fails like Go's `open <abs>/dangling.ini: no such file or directory`: {err}"
        );
    }
}

/// **Round-7 F2: the same entry-type filter under a glob, with the real
/// directory held out as the control.**
///
/// Both shapes above are reachable through `*` too, and the glob must not
/// start admitting real directories while it admits them. Measured on v0.71.0
/// in one directory holding `realdir/`, `lnk -> realdir` and
/// `dangling.ini -> nowhere.ini`, both loader modes and all three `-c` forms:
/// `l*` and `dang*.ini` are rc 1 (Go: `read <abs>/lnk: is a directory`,
/// `open <abs>/dangling.ini: no such file or directory`), while `reald*` — a
/// real directory entry, which both implementations skip with `fi.IsDir()` — is
/// rc 0 with zero proxies.
#[cfg(unix)]
#[test]
fn legacy_ini_common_include_symlink_globs_refuse_like_go() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("realdir")).unwrap();
    std::fs::write(
        dir.path().join("realdir").join("x.ini"),
        "[p1]\ntype = tcp\nlocal_port = 8080\nremote_port = 18080\n",
    )
    .unwrap();
    std::os::unix::fs::symlink("realdir", dir.path().join("lnk")).unwrap();
    std::os::unix::fs::symlink("nowhere.ini", dir.path().join("dangling.ini")).unwrap();
    let path = dir.path().join("frpc.ini");

    for (pattern, needle) in [
        ("l*", "Is a directory"),
        ("dang*.ini", "No such file or directory"),
    ] {
        std::fs::write(
            &path,
            format!(
                "[common]\nserver_addr = 127.0.0.1\nserver_port = 7000\nincludes = \"{pattern}\"\n"
            ),
        )
        .unwrap();
        for strict in [false, true] {
            let err = format!(
                "{}",
                load_client_config(path.to_str().unwrap(), strict).unwrap_err()
            );
            assert!(
                err.contains("include: read included file") && err.contains(needle),
                "pattern={pattern} strict={strict}: the glob must admit the symlink entry \
                 and fail on the read: {err}"
            );
        }
    }

    // Control: a *real* directory is skipped by the entry-type filter, exactly
    // as Go's `fi.IsDir()` skips it, so the load succeeds with zero proxies
    // (frp-rs does not recurse into it, and neither does Go).
    std::fs::write(
        &path,
        "[common]\nserver_addr = 127.0.0.1\nserver_port = 7000\nincludes = \"reald*\"\n",
    )
    .unwrap();
    for strict in [false, true] {
        let cfg = load_client_config(path.to_str().unwrap(), strict).unwrap_or_else(|e| {
            panic!("strict={strict}: a real directory entry must be skipped: {e}")
        });
        assert_eq!(cfg.proxies.len(), 0, "strict={strict}");
    }
}

/// **Item 2 / F2: only the string `includes` spelling is Go's.**
///
/// Go maps `IncludeConfigFiles []string \`ini:"includes"\``
/// (`pkg/config/legacy/client.go:166`) out of `[common]`. Measured on v0.71.0,
/// both loader modes: `[common] include = "<file>"` (the singular, a key Go
/// never reads) is rc 0 with zero proxies, and `[common] includes = ["<file>"]`
/// (an array, which `ini.MapTo` turns into the literal bracketed string) is
/// rc 0 with zero proxies for a *bare* relative name — the shape pinned here.
/// (The array's path shape is a pre-existing divergence: `["./bad.ini"]` and
/// absolute entries are Go rc 1 `parse config error: include: directory of
/// ["./bad.ini"] not exist`, frp-rs rc 0 for all shapes.) The string form loads
/// the file; frp-rs must ignore the two ignored spellings rather than expand
/// them.
#[test]
fn legacy_ini_common_include_ignored_spellings_both_modes() {
    for (label, line) in [
        ("singular include", "include = \"sub.ini\"".to_string()),
        ("array includes", "includes = [\"sub.ini\"]".to_string()),
    ] {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("sub.ini"),
            "[p1]\ntype = tcp\nlocal_port = 8080\nremote_port = 18080\n",
        )
        .unwrap();
        let path = dir.path().join("frpc.ini");
        std::fs::write(
            &path,
            format!("[common]\nserver_addr = 127.0.0.1\nserver_port = 7000\n{line}\n"),
        )
        .unwrap();
        for strict in [false, true] {
            let cfg = load_client_config(path.to_str().unwrap(), strict)
                .unwrap_or_else(|e| panic!("{label}, strict={strict}: {e}"));
            assert_eq!(
                cfg.proxies.len(),
                0,
                "{label}, strict={strict}: frp-rs must not expand it (Go yields zero proxies for this bare-relative form)"
            );
        }
    }
}

/// **Round-4 F1: an empty `[common] includes` means "no includes", not a
/// directory-less pattern.**
///
/// Go maps `includes = ""` onto `IncludeConfigFiles []string` as `[]string{""}`
/// (`pkg/config/legacy/client.go:166`); `getIncludeContents`
/// (`pkg/config/legacy/parse.go:68-97`) then stats `filepath.Dir("")` = `.`
/// (present), reads that directory, and matches every entry against
/// `filepath.Match(".", absFile)`, which never matches an absolute path — so Go
/// v0.71.0 is rc 0 with zero proxies in both loader modes. frp-rs instead joined
/// the empty pattern onto the config directory, and for the `./name` form
/// (`base_dir == "."`) `Path::new(".").join("")` has an empty parent, so the
/// missing-directory guard fired: rc 1
/// `include: directory of  not exist (included by pattern )`.
///
/// The pin drives [`super::file::process_includes`] with that exact base
/// directory, because a unit test's config path is absolute and the absolute
/// form never hit the empty-parent branch (the regression was `./`-form only).
/// The end-to-end half then asserts the recorded result, zero proxies in both
/// modes. A mutant that stops filtering empty patterns reds the first half.
#[test]
fn legacy_ini_common_include_empty_pattern_is_no_includes_both_modes() {
    // The raw dialect value the loader sees for `[common] includes = ""`, with
    // the base directory the `./name` CLI form produces.
    let mut value: toml::Value = toml::from_str("[common]\nincludes = \"\"\n").unwrap();
    super::file::process_includes(
        &mut value,
        std::path::Path::new("."),
        super::format::ConfigFormat::Ini,
        super::normalize::ConfigSide::Client,
    )
    .expect("an empty include pattern is no includes, exactly like Go");
    assert!(
        value["common"].get("includes").is_none(),
        "the empty pattern must be consumed, not left for a later pass"
    );

    // End to end: rc 0, zero proxies, both loader modes.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("frpc.ini");
    std::fs::write(
        &path,
        "[common]\nserver_addr = 127.0.0.1\nserver_port = 7000\nincludes = \"\"\n",
    )
    .unwrap();
    for strict in [false, true] {
        let cfg = load_client_config(path.to_str().unwrap(), strict)
            .unwrap_or_else(|e| panic!("strict={strict}: an empty include is not an error: {e}"));
        assert_eq!(cfg.proxies.len(), 0, "strict={strict}");
    }
}

/// **Round-5 blocker: `[common] includes = "."` (and `"./"`, `"././"`) is the
/// config's own directory, not a missing one.**
///
/// Go resolves the *pattern's* own directory — `absDir = filepath.Abs(
/// filepath.Dir(pattern))` (`pkg/config/legacy/parse.go:71`, repeated for the v1
/// path at `pkg/config/load.go:506`) — and `filepath.Dir` is `Clean` of the
/// prefix **through** the last separator, so `Dir(".") = Dir("./") =
/// Dir("././") = "."` (`internal/filepathlite/path.go`, `Dir`). The match name
/// is `filepath.Base(pattern) = "."`, which equals no directory entry, so Go
/// v0.71.0 is rc 0 with zero proxies in both loader modes and all three `-c`
/// forms.
///
/// frp-rs used `base_dir.join(pattern).parent()` instead. For `base_dir == "."`
/// (the `-c ./name` form, `frp-core/src/config/normalize.rs:633`) that is
/// `Path::new("./.")`, whose parent is `Some("")`, and `Path::new("").exists()`
/// is false — so the missing-directory guard fired: rc 1
/// `include: directory of  not exist (included by pattern .)`. The pin drives
/// [`super::file::process_includes`] with the base directory that CLI form
/// produces, because no hermetic in-process config path can make
/// `Path::parent()` return `"."` (a tempdir path is absolute); the `./`-form
/// end-to-end half is a real CLI pin in `frpc/tests/legacy_ini_fixture.rs`. A
/// mutant that goes back to `base_dir.join(pattern).parent()` reds this.
#[test]
fn legacy_ini_common_include_dot_spellings_both_modes() {
    for pattern in [".", "./", "././"] {
        let mut value: toml::Value =
            toml::from_str(&format!("[common]\nincludes = \"{pattern}\"\n")).unwrap();
        super::file::process_includes(
            &mut value,
            std::path::Path::new("."),
            super::format::ConfigFormat::Ini,
            super::normalize::ConfigSide::Client,
        )
        .unwrap_or_else(|e| {
            panic!("`includes = \"{pattern}\"` names the config's own directory, like Go: {e}")
        });
        assert!(
            value["common"].get("includes").is_none(),
            "`{pattern}` must be consumed, not left for a later pass"
        );
    }
}

/// **Round-5: a separator-less `[common] includes` resolves even when `base_dir`
/// is empty.**
///
/// `-c <bare relative name>` makes `Path::new(name).parent()` `Some("")`
/// (`frp-core/src/config/normalize.rs:633`) — an empty base directory, not the
/// current directory spelled as a path. `base_dir.join(pattern)` then has an
/// empty parent for *every* separator-less pattern, so each one failed the same
/// guard: rc 1 `include: directory of  not exist`. Go has no such shape: it
/// always starts from `filepath.Abs(filepath.Dir(pattern))`, and
/// `Dir(<bare name>)` is `"."`. Measured on v0.71.0, both loader modes, bare
/// `-c`: rc 0 with zero proxies for a name that matches no file, and rc 0 with
/// the included proxy for a name that does.
///
/// This is the same defect as the `"."` pin above — one rule, not a special
/// case — which is why the fix is `go_dir`/`go_base` rather than a guard on the
/// empty string. A mutant that goes back to `base_dir.join(pattern).parent()`
/// reds this too.
#[test]
fn legacy_ini_common_include_dot_spellings_bare_config_both_modes() {
    for pattern in ["", ".", "./", "nope.ini"] {
        let mut value: toml::Value =
            toml::from_str(&format!("[common]\nincludes = \"{pattern}\"\n")).unwrap();
        super::file::process_includes(
            &mut value,
            std::path::Path::new(""),
            super::format::ConfigFormat::Ini,
            super::normalize::ConfigSide::Client,
        )
        .unwrap_or_else(|e| {
            panic!(
                "`includes = \"{pattern}\"` under `-c <name>` resolves against the config's \
                 directory (`.`) in Go, never against a missing empty one: {e}"
            )
        });
    }
}

/// **Round-5: `[common] includes = ".."` matches nothing — it is not a glob
/// wildcard.**
///
/// Go matches each directory entry against `filepath.Match(filepath.Join(absDir,
/// filepath.Base(path)), absFile)` (`pkg/config/legacy/parse.go:87`). `Base("..")
/// = ".."`, so the matcher's pattern is the literal `<dir>/..`, which equals no
/// entry: Go v0.71.0 is rc 0 with zero proxies in both loader modes and all
/// three `-c` forms.
///
/// frp-rs took `Path::file_name()`, which is `None` for `".."`, and
/// `unwrap_or("*")` turned the pattern into a wildcard over the config's
/// directory (`frp-core/src/config/file.rs`, former `simple_glob`) — so rc 1.
/// Here the directory holds `decoy.ini`, a legacy visitor the collector refuses
/// (`failed to parse visitor bad`), which makes that merge visible. A mutant
/// that restores the `file_name().unwrap_or("*")` fallback reds this.
#[test]
fn legacy_ini_common_include_dotdot_is_not_a_wildcard_both_modes() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("decoy.ini"), "[bad]\nrole = \"visitor\"\n").unwrap();
    let mut value: toml::Value = toml::from_str("[common]\nincludes = \"..\"\n").unwrap();
    super::file::process_includes(
        &mut value,
        dir.path(),
        super::format::ConfigFormat::Ini,
        super::normalize::ConfigSide::Client,
    )
    .expect("`..` is a directory name, not a wildcard: Go's Match selects no entry");
    assert!(
        value["common"].get("includes").is_none(),
        "the pattern must be consumed, not left for a later pass"
    );
    assert!(
        value.get("bad").is_none(),
        "the decoy visitor beside the config must not be merged: `..` is not a wildcard"
    );

    // End to end: rc 0 and zero proxies, both loader modes. Before the fix the
    // absolute base directory made `..` glob its own directory and merge the
    // decoy.
    let path = dir.path().join("frpc.ini");
    std::fs::write(
        &path,
        "[common]\nserver_addr = 127.0.0.1\nserver_port = 7000\nincludes = \"..\"\n",
    )
    .unwrap();
    for strict in [false, true] {
        let cfg = load_client_config(path.to_str().unwrap(), strict)
            .unwrap_or_else(|e| panic!("strict={strict}: `..` must not glob a directory: {e}"));
        assert_eq!(cfg.proxies.len(), 0, "strict={strict}");
    }
}

/// **Round-5 F1: the include resolver folds an interior `..` with Go's
/// `filepath.Clean` rule — it does not merely spell the same directory.**
///
/// Go resolves the pattern's own directory with `filepath.Abs(filepath.Dir(p))`
/// (`pkg/config/legacy/parse.go:71`), and `Abs` Cleans, so
/// `Dir("a/../b") = Clean("a/../") = "."` even when `a` does not exist. frp-rs at
/// `c5b4f9ed` Cleaned without folding, leaving `"a/.."` — a path whose
/// `exists()` is false — so the missing-directory guard fired and the four
/// interior-`..` spellings were GO rc 0 / HEAD rc 1 (measured on v0.71.0, all
/// three `-c` forms, both loader modes):
/// `a/../b`, `./x/../y`, `x/../sub.ini`, `nonexistent/../sub.ini`. The fix is in
/// [`super::file::go_clean`]; this pin drives [`super::file::process_includes`]
/// with the same base directory the `./name` CLI form produces, so a mutant that
/// drops the `..` fold reds the `:410` guard here.
#[test]
fn legacy_ini_common_include_interior_dotdot_is_cleaned_like_go() {
    let dir = tempfile::tempdir().unwrap();
    // A decoy beside the config: a legacy visitor the collector would refuse.
    // It must not be merged — `a/../b` is not `*`, and after Clean it is `b` in
    // the config's own directory, which does not exist.
    std::fs::write(dir.path().join("bad.ini"), "[bad]\nrole = \"visitor\"\n").unwrap();
    for pattern in [
        "a/../b",
        "./x/../y",
        "x/../sub.ini",
        "nonexistent/../sub.ini",
    ] {
        let mut value: toml::Value =
            toml::from_str(&format!("[common]\nincludes = \"{pattern}\"\n")).unwrap();
        super::file::process_includes(
            &mut value,
            dir.path(),
            super::format::ConfigFormat::Ini,
            super::normalize::ConfigSide::Client,
        )
        .unwrap_or_else(|e| {
            panic!("`includes = \"{pattern}\"` must Clean to `.` and resolve, like Go: {e}")
        });
        assert!(
            value["common"].get("includes").is_none(),
            "`{pattern}` must be consumed, not left for a later pass"
        );
        assert!(
            value.get("bad").is_none(),
            "`{pattern}` must not merge the decoy beside the config"
        );
    }
}

/// **Round-5 F4: a separator-terminated pattern whose `Base` names a regular
/// entry is matched.**
///
/// `filepath.Base("sub/sub/") = "sub"` (Go's `Base` strips the trailing
/// separator) and `Dir("sub/sub/") = "sub/sub"`, so `includes = "sub/sub/"`
/// matches the file `sub/sub/sub` and merges it. frp-rs reproduced that via the
/// trailing-separator strip in [`super::file::go_base`]. Dropping that strip
/// makes `Base` the slash-only `"/"`, which matches nothing: silent rc 0 where
/// Go merges the file. Measured on v0.71.0 in both loader modes: GO rc 1
/// `failed to parse visitor pbad, err: type shouldn't be empty` with this
/// detector; the pre-`go_base` rule and the strip-removed mutant are rc 0. The
/// detector is a *visitor*, so Go's "no `[common]`/`[proxies]` wrapper needed"
/// reader and frp-rs both refuse it and the merge is observable as rc 1.
#[test]
fn legacy_ini_common_include_trailing_separator_base_names_a_file_like_go() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("sub/sub")).unwrap();
    // A regular file named `sub`, i.e. `Base("sub/sub/")`.
    std::fs::write(
        dir.path().join("sub/sub/sub"),
        "[pbad]\nrole = \"visitor\"\n",
    )
    .unwrap();
    let path = dir.path().join("frpc.ini");
    std::fs::write(
        &path,
        "[common]\nserver_addr = 127.0.0.1\nserver_port = 7000\nincludes = \"sub/sub/\"\n",
    )
    .unwrap();
    for strict in [false, true] {
        let err = format!(
            "{}",
            load_client_config(path.to_str().unwrap(), strict).unwrap_err()
        );
        assert!(
            err.contains("failed to parse visitor pbad") && err.contains("type shouldn't be empty"),
            "strict={strict}: `Base(\"sub/sub/\")` is `sub`, so the file `sub/sub/sub` merges: {err}"
        );
    }
}

/// **Go's `Clean`, spelled out: the `..` fold, the literal-`..` survival, and
/// the rooted clamp.**
///
/// Every case is a `filepath.Clean` measurement on Go v0.71.0, written as
/// `(input, expected)` so a reader can `go run` the same list. The interesting
/// families are the ones [`super::file::go_clean`] has to get right beyond
/// dropping `.`/empty elements:
/// * the fold over a *non-existent* element (`a/../b` → `b`), which is what
///   fixes the interior-`..` rc divergence;
/// * `..` surviving when it has nothing to cancel (`../x/../` → `..`,
///   `a/../../b` → `../b`, `x/../../..` → `../..`);
/// * the rooted clamp (`/..` → `/`, `//` → `/`), where Go never emits `..`;
/// * the *non-trivial* rooted results (`//x` → `/x`, `/a/b` → `/a/b`,
///   `/a/../b` → `/b`, `/a/b/..` → `/a`), which are what keep a mutant that
///   short-circuits every rooted input to `"/"` from passing: before round 7
///   every rooted row here expected exactly `"/"`, so that mutant was invisible
///   to the whole suite.
#[test]
fn go_clean_has_go_clean_semantics() {
    for (input, expected) in [
        ("", "."),
        (".", "."),
        ("./", "."),
        ("././", "."),
        ("///", "/"),
        ("//", "/"),
        ("/", "/"),
        ("/..", "/"),
        ("/../..", "/"),
        ("/a/../", "/"),
        ("//x", "/x"),
        ("/a/b", "/a/b"),
        ("/a/../b", "/b"),
        ("/a/b/..", "/a"),
        ("/..//x", "/x"),
        ("..", ".."),
        ("../", ".."),
        ("../x/../", ".."),
        ("a/..", "."),
        ("a/../", "."),
        ("a/../b", "b"),
        ("a/./../b", "b"),
        ("a/b/../../", "."),
        ("a/b/../../c", "c"),
        ("a/../../", ".."),
        ("a/../../b", "../b"),
        ("a//b/../", "a"),
        ("a/..//b", "b"),
        ("x/../../..", "../.."),
        ("sub/", "sub"),
        ("sub/./", "sub"),
        ("sub/../x", "x"),
        ("nonexistent/../sub.ini", "sub.ini"),
    ] {
        assert_eq!(
            super::file::go_clean(input),
            expected,
            "Go Clean({input:?}) is {expected:?}"
        );
    }
}

/// **Round-4 F6: the `format == ConfigFormat::Ini` half of the `[common]`
/// include guard is load-bearing.**
///
/// A TOML client config has a real `ClientConfig.includes: Vec<String>` field
/// (`frp-core/src/config/client.rs:256`), so a *string* `[common] includes` is a
/// type error that the v1 validator reports: both loader modes are rc 1
/// `config validation error: invalid type: string "sub.ini", expected a
/// sequence`. The legacy `.ini` extractor only exists to reproduce Go's legacy
/// reader, which no other dialect reaches; if it ran for TOML it would consume
/// the key as an include list and that error would disappear (and the merged
/// `[p1]` would appear as a proxy). The pin fixes the current verdict so a
/// mutant that drops `format == ConfigFormat::Ini` cannot pass.
#[test]
fn legacy_ini_common_include_does_not_apply_to_toml_both_modes() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("sub.ini"),
        "[p1]\ntype = tcp\nlocal_port = 8080\nremote_port = 18080\n",
    )
    .unwrap();
    let path = dir.path().join("frpc.toml");
    std::fs::write(
        &path,
        "[common]\nserver_addr = \"127.0.0.1\"\nserver_port = 7000\nincludes = \"sub.ini\"\n",
    )
    .unwrap();
    for strict in [false, true] {
        let err = format!(
            "{}",
            load_client_config(path.to_str().unwrap(), strict).unwrap_err()
        );
        assert!(
            err.contains("invalid type: string \"sub.ini\", expected a sequence"),
            "strict={strict}: a TOML includes string is a v1 type error, not a legacy include: {err}"
        );
    }
}

/// **Item 2 / F1: the frps load ignores `[common] includes` entirely, matching
/// Go.**
///
/// The legacy `.ini` `[common]` include list is read on the *client* load only.
/// `LoadServerConfig` (`pkg/config/load.go:295`) maps `[common]` onto
/// `legacy.ServerCommonConf` (`pkg/config/legacy/server.go:220`), which has no
/// `includes` field, and the only expansion (`LoadAdditionalClientConfigs`,
/// `pkg/config/load.go:381-382`) is inside `LoadClientConfigResult`
/// (`pkg/config/load.go:346`). (A *top-level* `includes` is a v1 `ServerConfig`
/// field and stays live on the server, at base and head alike.) Measured on
/// v0.71.0, both loader modes, all rc 0: an include holding `[p1]` (which the
/// client-side fix would merge and, under frps's strict default, refuse as
/// `unknown field "p1"`), an include holding a visitor the legacy collector
/// refuses, a missing include directory, and an include holding
/// `[common] log_level = "debug"` (a silent server-semantics change). The frps
/// load must stay rc 0 and keep its own log level.
#[test]
fn legacy_ini_server_ignores_common_includes_both_modes() {
    // Case 1: an include holding a proxy section — merging it would add an
    // unknown top-level `p1` under frps's strict default.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("srv_p1.ini"),
        "[p1]\ntype = tcp\nlocal_port = 8080\nremote_port = 18080\n",
    )
    .unwrap();
    let path = dir.path().join("frps.ini");
    std::fs::write(
        &path,
        "[common]\nbind_port = 17703\nincludes = \"srv_p1.ini\"\n",
    )
    .unwrap();
    for strict in [false, true] {
        load_server_config(path.to_str().unwrap(), strict)
            .unwrap_or_else(|e| panic!("include holding [p1], strict={strict}: {e}"));
    }

    // Case 2: an include the client-side collector would refuse.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("srv_bad.ini"), "[p1]\nrole = \"visitor\"\n").unwrap();
    let path = dir.path().join("frps.ini");
    std::fs::write(
        &path,
        "[common]\nbind_port = 17703\nincludes = \"srv_bad.ini\"\n",
    )
    .unwrap();
    for strict in [false, true] {
        load_server_config(path.to_str().unwrap(), strict)
            .unwrap_or_else(|e| panic!("include holding a bad visitor, strict={strict}: {e}"));
    }

    // Case 3: a missing include directory is not an error for frps.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("frps.ini");
    std::fs::write(
        &path,
        "[common]\nbind_port = 17703\nincludes = \"no_such_dir/missing.ini\"\n",
    )
    .unwrap();
    for strict in [false, true] {
        load_server_config(path.to_str().unwrap(), strict)
            .unwrap_or_else(|e| panic!("missing include dir, strict={strict}: {e}"));
    }

    // Case 4: the include cannot change server semantics silently — the
    // included `[common] log_level = "debug"` must not reach the merged config.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("srv_log.ini"),
        "[common]\nlog_level = \"debug\"\n",
    )
    .unwrap();
    let path = dir.path().join("frps.ini");
    std::fs::write(
        &path,
        "[common]\nbind_port = 17705\nincludes = \"srv_log.ini\"\n",
    )
    .unwrap();
    for strict in [false, true] {
        let cfg = load_server_config(path.to_str().unwrap(), strict)
            .unwrap_or_else(|e| panic!("log include, strict={strict}: {e}"));
        assert_eq!(
            cfg.log.level, "info",
            "strict={strict}: the server's own log level must not come from an ignored include"
        );
    }
}

/// **A DefaultSection `start` never filters; `[common] start` does.**
///
/// Go fills the legacy common config from `[common]` alone
/// (`UnmarshalClientConfFromIni`: `GetSection("common")` + `MapTo`,
/// `pkg/config/legacy/client.go:173-200`) and `start` is one of those keys
/// (`Start []string \`ini:"start"\``, `pkg/config/legacy/client.go:119`). The
/// hoist's `entry(k).or_insert(v)` (`frp-core/src/config/normalize.rs:1185-1189`)
/// would let a DefaultSection `start` win and mask Go's refusals (round-5
/// adversarial RF5-1), so the `[common]` value is captured before the hoist
/// (`legacy_common_start`, `frp-core/src/config/normalize.rs:2511`) and written
/// back after it (`legacy_start_override`,
/// `frp-core/src/config/normalize.rs:2530`). Measured on Go v0.71.0, both loader
/// modes: the four shapes below are rc 1 with the message asserted, a
/// DefaultSection-only `start` is rc 0 with both proxies (Go's list is empty,
/// i.e. `startAll`), `[common] start` beats a DefaultSection `start`, and
/// `[common] start = p2` still skips a bad `[p1]`.
#[test]
fn legacy_ini_start_comes_from_the_common_section_only() {
    let head = "[common]\nserver_addr = 127.0.0.1\nserver_port = 7000\n";
    let valid_p2 = "[p2]\nlocal_port = 8081\nremote_port = 18081\n";
    let bad_p1 = "[p1]\nrole = \"weird\"\nlocal_port = 8080\nremote_port = 18080\n";
    for (label, body, expected) in [
        (
            "a DefaultSection start cannot mask a bad role",
            format!("start = p2\n{head}{bad_p1}{valid_p2}"),
            "proxy p1 role should be 'server' or 'visitor'",
        ),
        (
            "a DefaultSection start cannot mask an invalid proxy type",
            format!(
                "start = p2\n{head}[p1]\ntype = \"custom\"\nlocal_port = 8080\nremote_port = 18080\n{valid_p2}"
            ),
            "invalid proxy_type 'custom'",
        ),
        (
            "a DefaultSection start cannot mask a typeless visitor",
            format!("start = p2\n{head}[p1]\nrole = \"visitor\"\nserver_name = s\n{valid_p2}"),
            "failed to parse visitor p1, err: type shouldn't be empty",
        ),
        (
            "a DefaultSection start cannot mask [common] start",
            format!(
                "start = p1\n{head}start = p2\n[p1]\nlocal_port = 8080\nremote_port = 18080\n[p2]\nrole = \"weird\"\nlocal_port = 8081\nremote_port = 18081\n"
            ),
            "proxy p2 role should be 'server' or 'visitor'",
        ),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("frpc.ini");
        std::fs::write(&path, body).unwrap();
        for strict in [false, true] {
            let err = format!(
                "{}",
                load_client_config(path.to_str().unwrap(), strict).expect_err(
                    "a DefaultSection start must not change Go's legacy dispatch"
                )
            );
            assert!(err.contains(expected), "{label}, strict={strict}: {err}");
        }
    }

    // A DefaultSection-only `start` is ignored, so Go's list is empty
    // (`startAll`) and both proxies load.
    let all = format!("start = p2\n{head}[p1]\nlocal_port = 8080\nremote_port = 18080\n{valid_p2}");
    // `[common] start = p2` wins over a DefaultSection `start = p1`.
    let common_wins = format!(
        "start = p1\n{head}start = p2\n[p1]\nlocal_port = 8080\nremote_port = 18080\n{valid_p2}"
    );
    // Control: `[common] start = p2` skips the bad `[p1]`.
    let control = format!("{head}start = p2\n{bad_p1}{valid_p2}");
    for (label, body, expected_len) in [
        ("DefaultSection start is ignored", all, 2usize),
        ("[common] start wins", common_wins, 1usize),
        ("[common] start skips p1", control, 1usize),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("frpc.ini");
        std::fs::write(&path, body).unwrap();
        for strict in [false, true] {
            let cfg = load_client_config(path.to_str().unwrap(), strict)
                .unwrap_or_else(|e| panic!("{label}, strict={strict}: {e}"));
            assert_eq!(cfg.proxies.len(), expected_len, "{label}, strict={strict}");
            if !label.starts_with("DefaultSection") {
                assert_eq!(cfg.proxies[0].name, "p2", "{label}, strict={strict}");
            }
        }
    }
}

/// **The section-wins collision rule is legacy-`.ini` only.**
///
/// Go's detector is the `[common]` section (`DetectLegacyINIFormat`,
/// `pkg/config/load.go:65`), so a `.ini` without it is decoded by the v1
/// decoder, where a DefaultSection scalar colliding with a same-named section is
/// a type error — measured on Go v0.71.0, both loader modes: `webServer = 1` +
/// `[webServer]` is rc 1 (`json: cannot unmarshal string into Go value of type
/// v1.rawClientConfig`), and `log`, two collisions, and the server twins
/// `webServer` / `log` / `transport` likewise. The replacement at
/// `frp-core/src/config/format.rs:389` is therefore gated on `legacy_ini`
/// (`frp-core/src/config/format.rs:223`); the legacy `[common]` case keeps the
/// section (`legacy_ini_scalar_and_section_collision_keeps_the_section_like_go`,
/// `frp-core/src/config/tests.rs:12650`).
#[test]
fn v1_ini_scalar_section_collision_is_still_a_type_error() {
    for (body, expected) in [
        (
            "webServer = 1\n[webServer]\ntls_cert_file = \"x\"\n",
            "expected struct WebServerConfig",
        ),
        ("log = 1\n[log]\nto = \"x\"\n", "expected struct LogConfig"),
        (
            "includes = 1\n[includes]\nlocal_port = 8080\nremote_port = 18080\n",
            "expected a sequence",
        ),
        (
            "log = 1\n[log]\nto = \"x\"\nwebServer = 1\n[webServer]\ntls_cert_file = \"x\"\n",
            "expected struct LogConfig",
        ),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("frpc.ini");
        std::fs::write(&path, body).unwrap();
        for strict in [false, true] {
            let err = format!(
                "{}",
                load_client_config(path.to_str().unwrap(), strict)
                    .expect_err("a `[common]`-less .ini uses Go's v1 decoder")
            );
            assert!(err.contains(expected), "{body:?}, strict={strict}: {err}");
        }
    }

    for (body, expected) in [
        (
            "webServer = 1\n[webServer]\ntls_cert_file = \"x\"\n",
            "expected struct WebServerConfig",
        ),
        ("log = 1\n[log]\nto = \"x\"\n", "expected struct LogConfig"),
        (
            "transport = 1\n[transport]\ntcp_mux = true\n",
            "expected struct ServerTransportConfig",
        ),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("frps.ini");
        std::fs::write(&path, body).unwrap();
        for strict in [false, true] {
            let err = format!(
                "{}",
                load_server_config(path.to_str().unwrap(), strict)
                    .expect_err("a `[common]`-less .ini uses Go's v1 decoder")
            );
            assert!(err.contains(expected), "{body:?}, strict={strict}: {err}");
        }
    }
}

/// **A `[start]` section is still subject to Go's role/type refusals.**
///
/// Go collects a section named `start` when `[common]` has no `start` list
/// (`startAll`, `pkg/config/legacy/client.go:232`) or when that list contains
/// the section's own name (`if !startAll && !shouldStart { continue }`,
/// `pkg/config/legacy/client.go:253-261`). The collected section is parsed like
/// any other, so `role` defaults to `server` and the `switch default:` refusal
/// (`pkg/config/legacy/client.go:283`) still fires. Measured on Go v0.71.0: a
/// lone `[common]` + `[start] role = "weird"` is rc 1 (`proxy start role should
/// be 'server' or 'visitor'`) and `[start] type = "custom"` is rc 1 (`failed to
/// parse proxy start, err: invalid type [custom]`). The round-6 defect removed
/// the root `start` key before collection (`legacy_start_override`,
/// `frp-core/src/config/normalize.rs:2530`), which deleted the section and
/// swallowed both refusals (rc 0); this test reds on `c7495cbd`.
#[test]
fn legacy_ini_start_section_refusals_like_go() {
    let head = "[common]\nserver_addr = 127.0.0.1\nserver_port = 7000\n";
    for (label, body, expected) in [
        (
            "a `[start]` role is validated",
            format!("{head}[start]\nrole = \"weird\"\nlocal_port = 8080\nremote_port = 18080\n"),
            "proxy start role should be 'server' or 'visitor'",
        ),
        (
            "a `[start]` type is validated",
            format!("{head}[start]\ntype = \"custom\"\nlocal_port = 8080\nremote_port = 18080\n"),
            "invalid proxy_type 'custom'",
        ),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("frpc.ini");
        std::fs::write(&path, body).unwrap();
        for strict in [false, true] {
            let err = format!(
                "{}",
                load_client_config(path.to_str().unwrap(), strict)
                    .expect_err("a `[start]` section must be collected, not deleted")
            );
            assert!(err.contains(expected), "{label}, strict={strict}: {err}");
        }
    }
}

/// **A `[start]` section is collected by `startAll`.**
///
/// With no `[common] start` list Go's `startAll` is true
/// (`pkg/config/legacy/client.go:232`) and every non-`common`/non-`range:`
/// section is collected, `start` included
/// (`pkg/config/legacy/client.go:253-261`). Measured on Go v0.71.0 through the
/// admin API (the proxy *set*, not only the count): `[common]` + `p1` + a valid
/// `[start]` registers `{"tcp":["p1","start"]}`, `[common]` + `[start]` alone
/// registers `{"tcp":["start"]}`, a visitor-role `[start]` yields 1 proxy `p1`
/// plus 1 visitor `start`, and a DefaultSection `start = p2` selects nothing
/// (`startAll`). The round-6 defect deleted this section, so on `c7495cbd` the
/// first case reports `proxies: []`.
#[test]
fn legacy_ini_start_section_is_still_a_proxy() {
    let head = "[common]\nserver_addr = 127.0.0.1\nserver_port = 7000\n";
    let p1 = "[p1]\ntype = tcp\nlocal_port = 8001\nremote_port = 18001\n";
    let start = "[start]\ntype = tcp\nlocal_port = 8002\nremote_port = 18002\n";

    for (label, body, expected, expected_start) in [
        (
            "startAll keeps p1 and the `start` section",
            format!("{head}{p1}{start}"),
            vec!["p1", "start"],
            Vec::<&str>::new(),
        ),
        (
            "startAll keeps a lone `start` section",
            format!("{head}{start}"),
            vec!["start"],
            Vec::<&str>::new(),
        ),
        (
            "a DefaultSection `start` selects nothing (`startAll`)",
            format!("start = p2\n{head}{start}"),
            vec!["start"],
            Vec::<&str>::new(),
        ),
        (
            "the control section is unaffected",
            format!("{head}[starter]\ntype = tcp\nlocal_port = 8003\nremote_port = 18003\n"),
            vec!["starter"],
            Vec::<&str>::new(),
        ),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("frpc.ini");
        std::fs::write(&path, body).unwrap();
        for strict in [false, true] {
            let cfg = load_client_config(path.to_str().unwrap(), strict)
                .unwrap_or_else(|e| panic!("{label}, strict={strict}: {e}"));
            let mut names: Vec<&str> = cfg.proxies.iter().map(|p| p.name.as_str()).collect();
            names.sort_unstable();
            assert_eq!(names, expected, "{label}, strict={strict}");
            // Go's `start` list itself: empty means `startAll`, and a
            // DefaultSection `start` must not survive into the runtime filter
            // (`legacy_start_override`, `frp-core/src/config/normalize.rs:2530`).
            let mut started: Vec<&str> = cfg.start.iter().map(String::as_str).collect();
            started.sort_unstable();
            assert_eq!(started, expected_start, "{label}, strict={strict}");
            assert_eq!(cfg.visitors.len(), 0, "{label}, strict={strict}");
        }
    }

    // A visitor-role `[start]` is collected as a visitor, and the proxy beside
    // it stays a proxy (Go: 1 proxy `p1` + 1 visitor `start`).
    let start_visitor = "[start]\nrole = visitor\ntype = stcp\nserver_name = x\nsecret_key = y\nbind_addr = 127.0.0.1\nbind_port = 9000\n";
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("frpc.ini");
    std::fs::write(&path, format!("{head}{p1}{start_visitor}")).unwrap();
    for strict in [false, true] {
        let cfg = load_client_config(path.to_str().unwrap(), strict)
            .unwrap_or_else(|e| panic!("a visitor `[start]`, strict={strict}: {e}"));
        assert_eq!(cfg.proxies.len(), 1, "strict={strict}");
        assert_eq!(cfg.proxies[0].name, "p1", "strict={strict}");
        assert_eq!(cfg.visitors.len(), 1, "strict={strict}");
        assert_eq!(cfg.visitors[0].name, "start", "strict={strict}");
    }
}

/// **A `[common] start` list selects the sections it names.**
///
/// Go tests the section's own name against the list
/// (`if !startAll && !shouldStart { continue }`,
/// `pkg/config/legacy/client.go:253-261`), so `[common] start = "start"`
/// collects the `[start]` section — the same root key the list itself occupies
/// — and skips every unlisted section; `"start,p1"` collects both. Measured on
/// Go v0.71.0 (admin `/api/status`): `start = p1` + `p1` + `[start]` registers
/// `{"tcp":["p1"]}`; `start = "start"` + `p1` + `[start]` registers
/// `{"tcp":["start"]}`; `start = "start,p1"` registers `{"tcp":["p1","start"]}`;
/// a spaced `start = " p1 , start "` registers both. The round-6 defect landed
/// on the opposite side of this rule (the root `start` key was removed before
/// collection, so `start = p1` kept the section and `start = "start"` dropped
/// it); this test reds on `c7495cbd`.
#[test]
fn legacy_ini_common_start_list_selects_named_sections() {
    let head = "[common]\nserver_addr = 127.0.0.1\nserver_port = 7000\n";
    let p1 = "[p1]\ntype = tcp\nlocal_port = 8001\nremote_port = 18001\n";
    let start = "[start]\ntype = tcp\nlocal_port = 8002\nremote_port = 18002\n";

    for (label, body, expected) in [
        (
            "`start = p1` skips the unlisted `start` section",
            format!("{head}start = p1\n{p1}{start}"),
            vec!["p1"],
        ),
        (
            "`start = \"start\"` selects the `start` section",
            format!("{head}start = \"start\"\n{start}"),
            vec!["start"],
        ),
        (
            "`start = \"start\"` skips an unlisted p1",
            format!("{head}start = \"start\"\n{p1}{start}"),
            vec!["start"],
        ),
        (
            "`start = \"start,p1\"` selects both",
            format!("{head}start = \"start,p1\"\n{p1}{start}"),
            vec!["p1", "start"],
        ),
        (
            "a spaced `start = \" p1 , start \"` is trimmed and selects both",
            format!("{head}start = \" p1 , start \"\n{p1}{start}"),
            vec!["p1", "start"],
        ),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("frpc.ini");
        std::fs::write(&path, body).unwrap();
        for strict in [false, true] {
            let cfg = load_client_config(path.to_str().unwrap(), strict)
                .unwrap_or_else(|e| panic!("{label}, strict={strict}: {e}"));
            let mut names: Vec<&str> = cfg.proxies.iter().map(|p| p.name.as_str()).collect();
            names.sort_unstable();
            assert_eq!(names, expected, "{label}, strict={strict}");
            // The written-back list is the same one the dispatch used, so the
            // runtime start filter cannot re-add a section the dispatch skipped.
            let mut started: Vec<&str> = cfg.start.iter().map(String::as_str).collect();
            started.sort_unstable();
            assert_eq!(started, expected, "{label}, strict={strict}");
        }
    }
}

/// **An array literal in `[common] start` names no section.**
///
/// Go fills `Start []string` (`pkg/config/legacy/client.go:119`) through
/// `gopkg.in/ini.v1`, whose `Key.Strings(",")` splits the **raw value text**
/// (key.go:492): `start = ["start"]` is the single piece `["start"]`, which
/// matches no section, and `startAll` stays false. `frp-core/src/config/format.rs`
/// instead infers a TOML array for `[..]` literals — a deliberate frp-rs
/// extension for slice-typed fields — so the dispatch used to see the
/// *elements*. `ini_value_for_key` (`frp-core/src/config/format.rs:428`) keeps
/// this one key as its text, and the trailing `cfg.start` assertions are those
/// same pieces after Go's comma split and trim. Measured on Go v0.71.0 (rc 0,
/// no proxy registered): `["start"]` beside a `[start]` section, `["p1","p2"]`,
/// `[]`, and `[p1, 2, p2]`.
#[test]
fn legacy_ini_start_array_literal_selects_nothing_like_go() {
    let head = "[common]\nserver_addr = 127.0.0.1\nserver_port = 7000\n";
    let p1 = "[p1]\ntype = tcp\nlocal_port = 8001\nremote_port = 18001\n";
    let p2 = "[p2]\ntype = tcp\nlocal_port = 8003\nremote_port = 18003\n";
    let start = "[start]\ntype = tcp\nlocal_port = 8002\nremote_port = 18002\n";

    for (label, body, expected) in [
        (
            "a quoted name is one bracket-carrying piece",
            format!("{head}start = [\"start\"]\n{p1}{start}"),
            vec!["[\"start\"]"],
        ),
        (
            "two quoted names match no section either",
            format!("{head}start = [\"p1\",\"p2\"]\n{p1}{p2}{start}"),
            vec!["[\"p1\"", "\"p2\"]"],
        ),
        (
            "an empty literal is the piece `[]`",
            format!("{head}start = []\n{p1}{start}"),
            vec!["[]"],
        ),
        (
            "a mixed literal keeps its brackets and trims each piece",
            format!("{head}start = [p1, 2, p2]\n{p1}{p2}{start}"),
            vec!["[p1", "2", "p2]"],
        ),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("frpc.ini");
        std::fs::write(&path, body).unwrap();
        for strict in [false, true] {
            let cfg = load_client_config(path.to_str().unwrap(), strict)
                .unwrap_or_else(|e| panic!("{label}, strict={strict}: {e}"));
            assert!(
                cfg.proxies.is_empty(),
                "{label}, strict={strict}: {:?}",
                cfg.proxies.iter().map(|p| &p.name).collect::<Vec<_>>()
            );
            let pieces: Vec<&str> = cfg.start.iter().map(String::as_str).collect();
            assert_eq!(pieces, expected, "{label}, strict={strict}");
        }
    }
}

/// **A comma list of non-string scalars keeps every piece.**
///
/// `start = 1,2` is Go's pieces `1` and `2` through `Key.Strings(",")`
/// (key.go:492) — no section carries those names, so nothing is dispatched —
/// while `start = p1,2` still selects `[p1]`; measured on Go v0.71.0: rc 0 with
/// no proxy, and rc 0 with proxy `p1`. Such a list round-trips against its raw
/// text, so `frp-core/src/config/format.rs` keeps it an array and
/// `ini_start_names` renders each element as Go's text
/// (`frp-core/src/config/normalize.rs:2484`). Dropping the non-string element
/// instead emptied the list and let `startAll` collect every section.
#[test]
fn legacy_ini_numeric_start_list_selects_nothing_like_go() {
    let head = "[common]\nserver_addr = 127.0.0.1\nserver_port = 7000\n";
    let p1 = "[p1]\ntype = tcp\nlocal_port = 8001\nremote_port = 18001\n";
    let start = "[start]\ntype = tcp\nlocal_port = 8002\nremote_port = 18002\n";

    for (label, body, expected) in [
        (
            "a numeric list names no section",
            format!("{head}start = 1,2\n{p1}{start}"),
            Vec::<&str>::new(),
        ),
        (
            "a mixed list still selects the named section",
            format!("{head}start = p1,2\n{p1}{start}"),
            vec!["p1"],
        ),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("frpc.ini");
        std::fs::write(&path, body).unwrap();
        for strict in [false, true] {
            let cfg = load_client_config(path.to_str().unwrap(), strict)
                .unwrap_or_else(|e| panic!("{label}, strict={strict}: {e}"));
            let mut names: Vec<&str> = cfg.proxies.iter().map(|p| p.name.as_str()).collect();
            names.sort_unstable();
            assert_eq!(names, expected, "{label}, strict={strict}");
        }
    }
}

/// **An empty `[common] start` selects every section like Go's `startAll`.**
///
/// `Key.Strings(",")` returns an empty slice for empty text (key.go:492), so
/// `startProxy` is empty, `startAll` is true (`pkg/config/legacy/client.go:232`)
/// and every section is collected — including one whose `role` is invalid, which
/// is then refused (`pkg/config/legacy/client.go:283`). Measured on Go v0.71.0:
/// `start = ""` beside a valid `[p1]` and `[start]` registers both, while the
/// same value beside `[p1] role = "weird"` is rc 1 with `proxy p1 role should be
/// 'server' or 'visitor'`; `start =` (blank) behaves identically. The empty set
/// must stay `None`, not `Some({})`: treating it as a list selects nothing and
/// silently swallows the refusal.
#[test]
fn legacy_ini_empty_start_dispatches_every_section_like_go() {
    let head = "[common]\nserver_addr = 127.0.0.1\nserver_port = 7000\n";
    let p1 = "[p1]\ntype = tcp\nlocal_port = 8001\nremote_port = 18001\n";
    let start = "[start]\ntype = tcp\nlocal_port = 8002\nremote_port = 18002\n";

    for (label, body) in [
        ("a blank value", format!("{head}start =\n{p1}{start}")),
        (
            "an empty string",
            format!("{head}start = \"\"\n{p1}{start}"),
        ),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("frpc.ini");
        std::fs::write(&path, body).unwrap();
        for strict in [false, true] {
            let cfg = load_client_config(path.to_str().unwrap(), strict)
                .unwrap_or_else(|e| panic!("{label}, strict={strict}: {e}"));
            let mut names: Vec<&str> = cfg.proxies.iter().map(|p| p.name.as_str()).collect();
            names.sort_unstable();
            assert_eq!(names, vec!["p1", "start"], "{label}, strict={strict}");
        }
    }

    for (label, body) in [
        (
            "a blank value still role-checks",
            format!("{head}start =\n[p1]\nrole = \"weird\"\n"),
        ),
        (
            "an empty string still role-checks",
            format!("{head}start = \"\"\n[p1]\nrole = \"weird\"\n"),
        ),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("frpc.ini");
        std::fs::write(&path, body).unwrap();
        for strict in [false, true] {
            let err = format!(
                "{}",
                load_client_config(path.to_str().unwrap(), strict)
                    .expect_err("startAll must dispatch every section")
            );
            assert!(
                err.contains("proxy p1 role should be 'server' or 'visitor'"),
                "{label}, strict={strict}: {err}"
            );
        }
    }
}

/// **A section the `[common] start` list does not name is never role-checked.**
///
/// Go continues before the role switch when the list does not name the section
/// (`if !startAll && !shouldStart { continue }`,
/// `pkg/config/legacy/client.go:253-261`), so a `[p2] role = "weird"` without
/// `type`/ports — not a collector candidate, hence never removed — is never
/// parsed: measured on Go v0.71.0, `[common] start = p1` beside a valid `[p1]`
/// and that `[p2]` is rc 0 with proxy `p1`. Non-strict frp-rs matches; the strict
/// checker still reports the leftover table (`unknown field "p2"`), the
/// pre-existing residue of a non-candidate section documented at
/// `frp-core/src/config/tests.rs:12845`. Without the `ini_section_started`
/// guard the role scan at `frp-core/src/config/normalize.rs:2187` refuses the
/// file (rc 1, `proxy p2 role should be 'server' or 'visitor'`).
#[test]
fn legacy_ini_start_skips_role_scan_for_unlisted_sections() {
    let body = concat!(
        "[common]\nserver_addr = 127.0.0.1\nserver_port = 7000\nstart = p1\n",
        "[p1]\ntype = tcp\nlocal_port = 8001\nremote_port = 18001\n",
        "[p2]\nrole = \"weird\"\n",
    );
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("frpc.ini");
    std::fs::write(&path, body).unwrap();

    let cfg = load_client_config(path.to_str().unwrap(), false)
        .expect("the unlisted section must be skipped, not role-checked");
    let names: Vec<&str> = cfg.proxies.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(names, vec!["p1"]);

    let err = format!(
        "{}",
        load_client_config(path.to_str().unwrap(), true)
            .expect_err("strict mode still reports the leftover table")
    );
    assert!(err.contains("unknown field \"p2\""), "{err}");
    assert!(!err.contains("role should be"), "{err}");
}

/// **`ini_start_names` maps a `[common] start` value to Go's names.**
///
/// Unit tooth for the dispatch helper (`frp-core/src/config/normalize.rs:2484`),
/// whose `Table` arm is masked end to end: a nested `[common.start]` header is a
/// section of its own in Go's `gopkg.in/ini.v1`, so `[common]` has no `start` key
/// and `startAll` is true, while frp-rs nests the table under `common` and then
/// writes it back to the root `start` — the resulting `invalid type: map,
/// expected a sequence` (the disclosed residual `a8`/`a9`) hides whichever
/// proxies the dispatch picked. The mapping is therefore pinned directly: text
/// splits into Go's `Key.Strings(",")` pieces, empty text is `startAll` (`None`),
/// a comma array keeps each element's text, and a nested table is `None` — never
/// its keys.
#[test]
fn legacy_ini_start_names_maps_go_text_and_nested_tables() {
    use std::collections::HashSet;

    let table = toml::Value::Table(
        [("zzz".to_string(), toml::Value::Integer(1))]
            .into_iter()
            .collect(),
    );
    assert_eq!(super::normalize::ini_start_names(&table), None);

    let text = toml::Value::String("p2, p1".to_string());
    assert_eq!(
        super::normalize::ini_start_names(&text),
        Some(HashSet::from(["p2".to_string(), "p1".to_string()]))
    );

    let empty = toml::Value::String(String::new());
    assert_eq!(super::normalize::ini_start_names(&empty), None);

    let array = toml::Value::Array(vec![
        toml::Value::String("p1".to_string()),
        toml::Value::Integer(2),
    ]);
    assert_eq!(
        super::normalize::ini_start_names(&array),
        Some(HashSet::from(["p1".to_string(), "2".to_string()]))
    );
}

/// **Item 3: a `[common.foo]`-only `.ini` reaches the legacy collector in frp-rs
/// but not in Go (recorded divergence).**
///
/// `q4_dotted_common_role_only.ini` (`[common.foo] role = "weird"`) measured on
/// Go v0.71.0: strict rc 1 `json: unknown field "common"`, non-strict rc 0. Go
/// asks `GetSection("common")` in `DetectLegacyINIFormat`
/// (`pkg/config/load.go:65`), and a literal `common.foo` header does not satisfy
/// it, so the file never reaches the legacy reader. frp-rs nests the dotted
/// header under `common` (`ini_section_path`, `frp-core/src/config/format.rs:323`)
/// and the collector's own detector (`frp-core/src/config/normalize.rs:1183`)
/// therefore sees a `common` table, hoists its `foo` subtable and refuses it as a
/// proxy: rc 1 in **both** modes. The strict verdict agrees with Go, the
/// non-strict refusal is the loose-only divergence the item calls a follow-up.
/// Recorded deliberate: making the two detectors agree would mean dropping
/// `common` from the dotted-section roots, which the `[common.webServer.tls]`
/// spelling pinned at `frp-core/src/config/tests.rs:7405` still needs. A mutant
/// that forces `legacy_ini` false in the collector loads this file non-strict.
#[test]
fn dotted_common_only_section_is_legacy_for_the_collector_both_modes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("q4_dotted_common_role_only.ini");
    std::fs::write(&path, "[common.foo]\nrole = \"weird\"\n").unwrap();
    for strict in [false, true] {
        let err = format!(
            "{}",
            load_client_config(path.to_str().unwrap(), strict)
                .expect_err("the hoisted foo table is refused as a proxy role")
        );
        assert!(
            err.contains("proxy foo role should be 'server' or 'visitor'"),
            "strict={strict}: {err}"
        );
    }
}

/// **Item 3: a `[DEFAULT]` header is an ordinary section in frp-rs (recorded
/// divergence).**
///
/// `y10`/`y11` measured on Go v0.71.0: rc 1 in both loader modes. `[DEFAULT]` is
/// not a TOML table, so Go's first decode fails
/// (`json: cannot unmarshal array into Go value of type v1.rawClientConfig`) and
/// the YAML/JSON fallback that an `.ini` extension falls through to rejects it as
/// well. frp-rs spells the header as a section literally named `DEFAULT`: strict
/// reports `unknown field "DEFAULT"`, non-strict keeps it as an inert table and
/// loads `[p1]` through the v1 path. Recorded deliberate — matching Go would mean
/// routing a `[common]`-less `.ini` into the YAML/JSON fallback frp-rs does not
/// have. Both modes pinned.
#[test]
fn default_section_header_is_an_ordinary_section_both_modes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("y10_default.ini");
    std::fs::write(
        &path,
        "[DEFAULT]\nserver_addr = 127.0.0.1\nserver_port = 7000\n\
         [p1]\ntype = tcp\nlocal_port = 8080\nremote_port = 18080\n",
    )
    .unwrap();
    let cfg = load_client_config(path.to_str().unwrap(), false)
        .expect("non-strict keeps DEFAULT as an inert section");
    assert_eq!(cfg.proxies.len(), 1);
    assert_eq!(cfg.proxies[0].name, "p1");
    let err = format!(
        "{}",
        load_client_config(path.to_str().unwrap(), true)
            .expect_err("strict reports the DEFAULT table as unknown")
    );
    assert!(err.contains("unknown field \"DEFAULT\""), "{err}");
}

/// **Item 3: the `r_toml.ini` `.ini`/TOML hybrid is a v1 shape in frp-rs
/// (recorded divergence).**
///
/// `server_addr` plus a `[[proxies]]` array-of-tables header measured on Go
/// v0.71.0: rc 1 in both modes (strict `json: unknown field "server_addr"`,
/// non-strict `decode proxy at index 0: unknown proxy type:`). frp-rs's `.ini`
/// reader spells `[[proxies]]` as a section literally named `[proxies]`: strict
/// reports `unknown field "[proxies]"`, non-strict keeps the scalar `server_addr`
/// and loads zero proxies. The strict rc agrees; only the message and the
/// non-strict verdict diverge, and matching Go's non-strict message would mean
/// addressing the array element as `proxies[0]`, which the `.ini` reader does not
/// do (pinned as out of scope at `frp-core/src/config/tests.rs:12887`). Both
/// modes pinned.
#[test]
fn r_toml_hybrid_ini_is_a_v1_shape_both_modes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("r_toml.ini");
    std::fs::write(
        &path,
        "server_addr = \"127.0.0.1\"\nserver_port = 7000\n\
         [[proxies]]\nname = \"p\"\nrole = \"weird\"\n",
    )
    .unwrap();
    let cfg = load_client_config(path.to_str().unwrap(), false)
        .expect("non-strict keeps server_addr and loads no proxy");
    assert_eq!(cfg.server_addr, "127.0.0.1");
    assert!(cfg.proxies.is_empty());
    let err = format!(
        "{}",
        load_client_config(path.to_str().unwrap(), true)
            .expect_err("strict reports the literal [proxies] section")
    );
    assert!(err.contains("unknown field \"[proxies]\""), "{err}");
}

/// **Item 3: a `[range:...]` section missing a port is skipped with a warning in
/// frp-rs where Go fails the load (recorded divergence).**
///
/// `y16_default_start_masks_range_render_error.ini` (`start = p2`, `[common]`,
/// `[range:p] local_port = 8080` with no `remote_port`, and a valid `[p2]`)
/// measured on Go v0.71.0: rc 1 in both modes, `failed to render template for
/// proxy range:p: local_port or remote_port is empty`
/// (`renderRangeProxyTemplates`, `pkg/config/legacy/client.go:289`). frp-rs logs
/// `legacy INI [range:...] section: missing or invalid remote_port; skipped`
/// (`frp-core/src/config/normalize.rs:2331`) and loads `p2`, rc 0. Recorded
/// deliberate: making a missing port fatal is a separate design question, and the
/// sibling skip paths are pinned as intentional at
/// `frp-core/src/config/tests.rs:10587` / `:10612`. Both modes pinned.
#[test]
fn range_section_without_remote_port_is_skipped_not_fatal_both_modes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("y16_range_render.ini");
    std::fs::write(
        &path,
        "start = p2\n[common]\nserver_addr = 127.0.0.1\nserver_port = 7000\n\
         [range:p]\nlocal_port = 8080\n\
         [p2]\ntype = tcp\nlocal_port = 8081\nremote_port = 18081\n",
    )
    .unwrap();
    for strict in [false, true] {
        let cfg = load_client_config(path.to_str().unwrap(), strict)
            .unwrap_or_else(|e| panic!("strict={strict}: the range section is skipped: {e}"));
        let names: Vec<&str> = cfg.proxies.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["p2"], "strict={strict}");
    }
}

/// **Item 1, reserved-root `type`-only sections: frp-rs keeps them as v1
/// settings (recorded design decision).**
///
/// `i4c.ini` (`[common]` + `[web_server] type = "tcp"`) measured on Go v0.71.0:
/// rc 0 in both loader modes, and the legacy collector registers a proxy named
/// `web_server` of type `tcp` with listen port 0 — Go's
/// `LoadAllProxyConfsFromIni` skips only the default section, `common` and
/// `range:`, so every other header is a proxy regardless of its name. frp-rs
/// keeps its known-settings-root guard (`KNOWN_SECTIONS` in
/// `frp-core/src/config/normalize.rs:2042`) and reports `Proxies: 0`, rc 0 in
/// both modes. Keying the bypass on `type` instead of the ports would also
/// collect `[log] type = "custom" disable_print_color = true` (Go rc 1
/// `failed to parse proxy log, err: invalid type [custom]`, frp-rs rc 0 today)
/// and would contradict `test_legacy_ini_known_section_with_type_not_collected`
/// (`frp-core/src/config/tests.rs:10637`). The item calls this a design question
/// about whether frp-rs keeps supporting v1 settings roots in `.ini` at all, so
/// the divergence is recorded deliberate rather than forced. The sibling
/// typeless/port-less shape (`c2.ini`, `[p] custom_domains = ["a.com"]`) is
/// pinned the same way both modes: Go collects `p` (rc 0), frp-rs keeps it a v1
/// section (`unknown field "p"` strict, rc 0 non-strict), matching
/// `typeless_ini_section_without_ports_stays_a_v1_section`
/// (`frp-core/src/config/tests.rs:7658`).
#[test]
fn legacy_ini_reserved_root_type_only_section_is_not_collected_both_modes() {
    let dir = tempfile::tempdir().unwrap();
    let i4c = dir.path().join("i4c.ini");
    std::fs::write(
        &i4c,
        "[common]\nserver_addr = 127.0.0.1\nserver_port = 7000\n\
         [web_server]\ntype = \"tcp\"\n",
    )
    .unwrap();
    for strict in [false, true] {
        let cfg = load_client_config(i4c.to_str().unwrap(), strict)
            .unwrap_or_else(|e| panic!("i4c strict={strict}: frp-rs keeps the settings root: {e}"));
        assert!(
            cfg.proxies.is_empty(),
            "i4c strict={strict}: Go registers [web_server] as a type-tcp proxy, frp-rs does not"
        );
    }

    let c2 = dir.path().join("c2.ini");
    std::fs::write(
        &c2,
        "[common]\nserver_addr = 127.0.0.1\nserver_port = 7000\n\
         [p]\ncustom_domains = [\"a.com\"]\n",
    )
    .unwrap();
    let lenient = load_client_config(c2.to_str().unwrap(), false).unwrap();
    assert!(lenient.proxies.is_empty(), "c2 non-strict");
    let err = format!(
        "{}",
        load_client_config(c2.to_str().unwrap(), true).unwrap_err()
    );
    assert!(
        err.contains("unknown field \"p\""),
        "c2 strict keeps the typeless, port-less section a v1 shape: {err}"
    );
}

/// **Item 1, server side: no legacy collector means a dotted or reserved root
/// stays a v1 key, and Go's legacy server reader simply ignores those headers.**
///
/// The four `frps` shapes measured on Go v0.71.0 (a `[common]` header makes the
/// file legacy for Go, whose server reader then reads its typed `[common]`
/// fields and ignores every other section):
/// * `s2.ini` `[proxies.foo] type = tcp`: Go rc 0 in both loader modes; frp-rs
///   strict rc 1 `unknown field "proxies.foo"`, non-strict rc 0.
/// * `i6a.ini` `[http_plugins.foo] name = "u"`: Go rc 0 both; frp-rs rc 1 both
///   `invalid type: map, expected a sequence`.
/// * `i6b.ini` `[plugin.user] ops = login`: Go rc 1 both `invalid http plugin
///   ops, optional values are [Login NewProxy CloseProxy Ping NewWorkConn
///   NewUserConn]`; frp-rs rc 1 both `server config: http_plugins entry 'user'
///   has no addr` — the refusal agrees, the message does not.
/// * `i7.ini` `[feature.foo] x = true`: Go rc 0 both; frp-rs rc 1 both
///   `invalid type: map, expected a boolean`.
///
/// frp-rs has no server-side legacy collector (the item says so explicitly), so
/// these are recorded as deliberate divergences rather than forced to Go's
/// verdicts: `[feature]`/`[http_plugins]` are typed v1 settings roots, and
/// accepting an arbitrary subtable would weaken those types. Both modes pinned.
#[test]
fn legacy_ini_server_side_dotted_and_reserved_roots_stay_v1_both_modes() {
    let dir = tempfile::tempdir().unwrap();
    let cases: [(&str, &str, Option<&str>); 4] = [
        (
            "s2.ini",
            "[common]\nbind_port = 7000\n[proxies.foo]\ntype = tcp\n",
            Some("unknown field \"proxies.foo\""),
        ),
        (
            "i6a.ini",
            "[common]\nbind_port = 7000\n[http_plugins.foo]\nname = \"u\"\n",
            Some("invalid type: map, expected a sequence"),
        ),
        (
            "i6b.ini",
            "[common]\nbind_port = 7000\n[plugin.user]\nops = login\n",
            Some("http_plugins entry 'user' has no addr"),
        ),
        (
            "i7.ini",
            "[common]\nbind_port = 7000\n[feature.foo]\nx = true\n",
            Some("invalid type: map, expected a boolean"),
        ),
    ];
    for (name, body, strict_err) in cases {
        let path = dir.path().join(name);
        std::fs::write(&path, body).unwrap();
        for strict in [false, true] {
            let outcome = load_server_config(path.to_str().unwrap(), strict);
            match (name, strict, strict_err) {
                // The one shape where frp-rs agrees with Go in non-strict mode.
                ("s2.ini", false, _) => {
                    outcome.unwrap_or_else(|e| panic!("s2 non-strict must load: {e}"));
                }
                (_, _, Some(fragment)) => {
                    let err = match outcome {
                        Err(e) => format!("{e}"),
                        Ok(_) => panic!(
                            "{name} strict={strict} loaded, expected an error containing {fragment:?}"
                        ),
                    };
                    assert!(
                        err.contains(fragment),
                        "{name} strict={strict}: expected {fragment:?}, got {err}"
                    );
                }
                (_, _, None) => unreachable!("every case names its strict error"),
            }
        }
    }
}

// ─── The strict acceptance set vs the compiled serde field set (item 4) ──

/// Whether `feature` — one of `FEATURE_GATED_SERVER_PORTS`' names — compiled the
/// matching field into **this** build.
///
/// `cfg!` cannot take a runtime name, so the three arms are written out; the
/// catch-all keeps a typo in the table from silently answering `false`.
fn feature_gated_port_field_is_compiled_in(feature: &str) -> bool {
    match feature {
        "kcp" => cfg!(feature = "kcp"),
        "quic" => cfg!(feature = "quic"),
        "websocket" => cfg!(feature = "websocket"),
        other => panic!("`{other}` is not a feature-gated server port"),
    }
}

/// **The recorded divergence, measured in both build shapes.** `known_server_keys()`
/// is a *static* allow-list that names all three feature-gated listener ports in every
/// build (`frp-core/src/config/strict.rs`), while the serde field each spelling writes
/// is `#[cfg(feature = "…")]`-gated (`frp-core/src/config/server.rs`), so strict mode
/// accepts a key this build cannot honour and the server then ignores it.
///
/// That is deliberate, not an oversight. Refusing the key would be the "false 400"
/// direction `docs/deployment.md` rules out, and the repo's own `frps.toml` writes
/// `kcp_bind_port = 17000` + `quic_bind_port = 17001`, so rejection would stop every
/// `micro`/`tiny` build from loading the documented example — the invariant
/// `frp-core/src/config/strict.rs` records next to `subdomain_host`. There is no
/// client-side counterpart to record: `frp-core/src/config/client.rs` carries no
/// `#[cfg(feature …)]` at all, so `known_client_keys()` cannot go stale.
///
/// What this pin adds to the class pin above is the **compiled field set** half of the
/// measurement: `serde_json::to_value(&cfg)` is the serde field set this build actually
/// has, so it carries `kcp_bind_port` / `quic_bind_port` / `websocket_port` exactly when
/// the feature is compiled in.
///
/// * compiled in — the snake *and* the camel spelling land in the field
///   (`17500`); with the caller reporting the listener (`Present`) the
///   unhonoured-record list is empty, and with it reporting `Absent` — the
///   hand-named inner-feature shape — the key is recorded;
/// * compiled out — strict mode **still accepts** both spellings (the
///   divergence), the field is absent from `to_value`, and the load records the
///   accepted-but-unhonoured key once per load, whatever the caller reports.
///
/// One function measures both shapes (`frp-core/src/config/loader.rs:1182-1205`): the default
/// lanes compile all three features in, `cargo test -p frp-core --no-default-features` compiles all three out.
#[test]
fn feature_gated_port_keys_are_accepted_while_the_compiled_field_set_follows_the_build() {
    for (snake, camel, feature) in FEATURE_GATED_SERVER_PORTS {
        let compiled_in = feature_gated_port_field_is_compiled_in(feature);
        for spelling in [snake, camel] {
            let body = format!("bind_port = 17000\n{spelling} = 17500\n");
            let (cfg, presence) = load_server_with_presence(&body);
            let value = serde_json::to_value(&cfg).unwrap();
            let serialized = value.get(snake).and_then(|port| port.as_u64());
            let names_key = |readers| {
                presence
                    .unhonoured_server_feature_key_records(readers)
                    .iter()
                    .any(|record| record.contains(snake))
            };
            if compiled_in {
                assert_eq!(
                    serialized,
                    Some(17500),
                    "{snake}: `{spelling}` must land in the field this build compiles in"
                );
                // The reader is the whole question in this shape: `Absent` is the
                // hand-named inner-feature build (field compiled, listener not),
                // and it must record; `Present` is the ordinary default build and
                // must stay silent. Both directions are asserted, so a record list
                // that ignored the reader reds here.
                assert!(
                    !names_key(all_gated_listener_readers()),
                    "{snake}: a build whose caller reports the listener must not record \
                     `{spelling}`"
                );
                assert!(
                    names_key(no_gated_listener_readers()),
                    "{snake}: a build that deserializes `{spelling}` without the listener \
                     must record it"
                );
            } else {
                assert!(
                    serialized.is_none(),
                    "{snake}: strict mode accepts `{spelling}` but this build compiles no field \
                     for it, so the serde field set must not carry it"
                );
                // The field-less half ignores the caller's answer — no reader can
                // read a field this build never compiled.
                for readers in [no_gated_listener_readers(), all_gated_listener_readers()] {
                    assert!(
                        names_key(readers),
                        "{snake}: the accepted-but-unhonoured key must be recorded once per \
                         load, whatever the caller reports"
                    );
                }
            }
        }
    }
}
