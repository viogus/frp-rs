//! `frpc verify` against Go frp v0.71.0's own shipped legacy INI fixture.
//!
//! `frp-core/src/config/fixtures/frpc_legacy_full.ini` is a byte-identical copy
//! of Go's `conf/legacy/frpc_legacy_full.ini` (see that directory's README).
//! Go's own `frpc verify -c` exits 0 on it and the file's bare numeric values
//! are strings there (`token = 12345678` → the token `"12345678"`; measured on
//! `frp_0.71.0_darwin_arm64`, see `TODO.md:2609`).
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

/// A scratch directory removed on drop (no `tempfile` dev-dependency in this
/// crate; the same hand-rolled shape as `admin_config_get_warning.rs`).
struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let p =
            std::env::temp_dir().join(format!("frpc-ini-include-{tag}-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// **Round-5: the `./`-form config path (`-c ./frpc.ini`) is the shape that made
/// a dot-spelling `[common] includes` fail, and it must be rc 0 like Go.**
///
/// `frpc verify` is spawned with its working directory set to the fixture
/// directory, so `-c ./frpc.ini` is exactly the CLI form a user types. The CLI
/// derives the include base directory from `Path::new(path).parent()`
/// (`frp-core/src/config/normalize.rs:633`), which is `"."` here — the
/// empty-parent case that used to fire the missing-directory guard. Go v0.71.0
/// (measured in both loader modes) is rc 0 with zero proxies for all four
/// spellings, because `filepath.Dir("") = Dir(".") = Dir("./") = Dir("././") =
/// "."` and `filepath.Base` of each matches no entry.
///
/// The bare `-c frpc.ini` form is the same defect one step further: its base
/// directory is the empty `Some("")`, spelling "the config's directory" as
/// nothing at all. A missing bare-name include is still a zero-match, not a
/// missing directory.
#[test]
fn verify_dot_spelling_includes_from_a_relative_config_path() {
    for pattern in ["", ".", "./", "././"] {
        let dir = TempDir::new("dot");
        std::fs::write(
            dir.0.join("frpc.ini"),
            format!(
                "[common]\nserver_addr = 127.0.0.1\nserver_port = 7000\nincludes = \"{pattern}\"\n"
            ),
        )
        .unwrap();
        for (label, argv) in [
            ("-c ./frpc.ini", vec!["verify", "-c", "./frpc.ini"]),
            ("-c frpc.ini", vec!["verify", "-c", "frpc.ini"]),
        ] {
            let out = Command::new(env!("CARGO_BIN_EXE_frpc"))
                .args(&argv)
                .current_dir(&dir.0)
                .output()
                .expect("spawn frpc verify");
            let stdout = String::from_utf8_lossy(&out.stdout);
            assert_eq!(
                out.status.code(),
                Some(0),
                "{label}, includes=\"{pattern}\": Go resolves it to the config's own directory, \
                 not a missing one\nstdout={stdout}"
            );
            assert!(
                stdout.contains("Proxies: 0"),
                "{label}, includes=\"{pattern}\": the pattern matches no entry, like Go: {stdout}"
            );
        }
    }

    // A *missing* directory spelled with a trailing separator must refuse, not
    // silently match nothing: Go's `filepath.Dir("nonexistent/")` is
    // `nonexistent`, so `os.Stat` fails and the load is rc 1
    // (`include: directory of ... not exist`, `frp-core/src/config/file.rs:424`).
    // Before round 5 the `./` form was rc 0 here, because the old rule took the
    // parent of the join result (`./nonexistent/` → `.`, which exists).
    let dir = TempDir::new("dot-missing-dir");
    std::fs::write(
        dir.0.join("frpc.ini"),
        "[common]\nserver_addr = 127.0.0.1\nserver_port = 7000\nincludes = \"nonexistent/\"\n",
    )
    .unwrap();
    for (label, argv) in [
        ("-c ./frpc.ini", vec!["verify", "-c", "./frpc.ini"]),
        ("-c frpc.ini", vec!["verify", "-c", "frpc.ini"]),
    ] {
        let out = Command::new(env!("CARGO_BIN_EXE_frpc"))
            .args(&argv)
            .current_dir(&dir.0)
            .output()
            .expect("spawn frpc verify");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert_eq!(
            out.status.code(),
            Some(1),
            "{label}: a missing include directory must refuse, like Go\nstdout={stdout}"
        );
        assert!(
            stdout.contains("include: directory of"),
            "{label}: the refusal must come from the include guard: {stdout}"
        );
    }

    // Control: a bare filename include in the `./` form still expands, so the
    // pin above cannot pass by resolving nothing at all.
    let dir = TempDir::new("dot-control");
    std::fs::write(
        dir.0.join("sub.ini"),
        "[p1]\ntype = tcp\nlocal_port = 8080\nremote_port = 18080\n",
    )
    .unwrap();
    std::fs::write(
        dir.0.join("frpc.ini"),
        "[common]\nserver_addr = 127.0.0.1\nserver_port = 7000\nincludes = \"sub.ini\"\n",
    )
    .unwrap();
    for (label, argv) in [
        ("-c ./frpc.ini", vec!["verify", "-c", "./frpc.ini"]),
        ("-c frpc.ini", vec!["verify", "-c", "frpc.ini"]),
    ] {
        let out = Command::new(env!("CARGO_BIN_EXE_frpc"))
            .args(&argv)
            .current_dir(&dir.0)
            .output()
            .expect("spawn frpc verify");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert_eq!(
            out.status.code(),
            Some(0),
            "{label}: a bare-name include beside the config must load\nstdout={stdout}"
        );
        assert!(
            stdout.contains("Proxies: 1"),
            "{label}: the included proxy must be counted: {stdout}"
        );
    }
}
