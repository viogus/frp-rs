//! `frpc verify` against Go frp v0.71.0's own shipped legacy INI fixture.
//!
//! `frp-core/src/config/fixtures/frpc_legacy_full.ini` is a byte-identical copy
//! of Go's `conf/legacy/frpc_legacy_full.ini` (see that directory's README).
//! Go's own `frpc verify -c` exits 0 on it and the file's bare numeric values
//! are strings there (`token = 12345678` → the token `"12345678"`; measured on
//! `frp_0.71.0_darwin_arm64`, see `TODO.md:1359`).
//!
//! The counts are Go's own config-level counts: Go frpc v0.71.0 against a Go
//! frps logs `proxy added: [43 names]` and `visitor added: [p2p_tcp_visitor
//! secret_tcp_visitor]` for the same file (every port swapped for a free one;
//! no other byte changed). `[range:tcp_port]` alone is 17 of those proxies.
//!
//! The full-load assertions (every proxy name, the visitor fields, the inferred
//! values) live in `frp-core/src/config/tests.rs`; this pins the CLI surface a
//! user actually types, which is what Go's `verify` subcommand is.
//!
//! Gated on `full` for the same reason as `admin_cli.rs`/`cli_inputs.rs`: the
//! `frpc` bin carries `required-features = ["full"]`, so without the gate this
//! file would fail to compile in the feature-reduced lanes CI runs.
#![cfg(feature = "full")]

use std::process::Command;

/// Go's shipped legacy INI fixture passes `frpc verify` in strict mode with the
/// count Go registers, and prints no `[range:...] skipped` warning.
#[test]
fn verify_accepts_the_vendored_go_legacy_fixture() {
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../frp-core/src/config/fixtures/frpc_legacy_full.ini"
    );
    let out = Command::new(env!("CARGO_BIN_EXE_frpc"))
        .args(["verify", "-c", fixture])
        .output()
        .expect("spawn frpc verify");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stdout={stdout} stderr={stderr}"
    );
    assert!(
        stdout.contains("frpc: the configuration file") && stdout.contains("syntax is ok"),
        "verify must report the file valid with Go's success sentence: {stdout}"
    );
    assert!(
        stdout.contains("Proxies: 43"),
        "the 17 `[range:tcp_port]` proxies and the 11 `[range:udp_port]` ones \
         must be counted: {stdout}"
    );
    assert!(
        stdout.contains("Visitors: 2"),
        "the two role=visitor sections must be counted: {stdout}"
    );
    assert!(
        !stderr.contains("skipped"),
        "no `[range:...]` section may be skipped: {stderr}"
    );
}
