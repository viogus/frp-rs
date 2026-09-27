//! Pins hazard (a) of `TODO.md`'s “Two test-harness hazards” item: when a
//! `dashboard`-lane test resolves an `frps` artifact that carries no dashboard
//! listener, it must fail **with a message that names the cause** — not 15s
//! later with `frps dashboard_port not ready` and, in the same run, a wave of
//! orphaned children.
//!
//! The mechanism under test is `common::assert_frps_has_dashboard`, which
//! `common::frps_binary()` runs whenever the test target is compiled with the
//! `dashboard` feature (see the ordering note on `frps_binary`).
//!
//! **Keep exactly one `#[test]` in this file.** It mutates the process-global
//! `FRPS_BIN` env var and then calls `common::frps_binary()`, which reads it; a
//! second test in this binary would race the first. (Separate integration-test
//! files are separate processes, so this does not affect any other test file.)

#![cfg(feature = "dashboard")]

mod common;

/// Panic payload → text, so the assertions below can be about the *message*
/// rather than about "something panicked".
fn panic_text(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else if let Some(s) = payload.downcast_ref::<&'static str>() {
        (*s).to_string()
    } else {
        "<non-string panic payload>".to_string()
    }
}

#[test]
fn missing_dashboard_listener_fails_with_a_rebuild_instruction() {
    let dir = tempfile::TempDir::new().unwrap();
    // The lane's own `FRPS_BIN`, saved so the positive control below resolves
    // the **same path the lane resolves**. Without this the control would fall
    // through to the relative `../target/debug/frps` fallback, which ignores
    // `CARGO_TARGET_DIR` and `FRPS_BIN` both — and would go red for the wrong
    // reason (a path that does not exist) while the lane's artifact is fine.
    let lane_frps_bin = std::env::var("FRPS_BIN").ok();
    let restore_frps_bin = || match &lane_frps_bin {
        Some(v) => std::env::set_var("FRPS_BIN", v),
        None => std::env::remove_var("FRPS_BIN"),
    };

    // ── negative control: a readable file that is not a dashboard frps build ──
    let fake = dir.path().join("frps");
    std::fs::write(&fake, b"not a dashboard frps build\n").unwrap();
    let fake_path = fake.to_str().unwrap().to_string();

    // The guard itself…
    let err = std::panic::catch_unwind(|| common::assert_frps_has_dashboard(&fake_path))
        .expect_err("a binary without the dashboard listener must panic");
    let msg = panic_text(&*err);
    assert!(
        msg.contains("rebuild `frps --features dashboard`"),
        "the panic must name the fix (`rebuild `frps --features dashboard``); got: {msg}"
    );
    assert!(
        msg.contains(&fake_path),
        "the panic must name the artifact it checked; got: {msg}"
    );
    assert!(
        msg.contains(common::DASHBOARD_LISTEN_MARKER),
        "the panic must name the marker it looked for; got: {msg}"
    );
    // A readable file with no execute bit is `Some(false)` (it is *not* the
    // silent `None` branch), and the panic reports the mode — measured, the
    // spawn of such a file fails `Os { code: 13, kind: PermissionDenied }`, so
    // the message has to say that this may not be a feature problem.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&fake).unwrap().permissions().mode() & 0o777;
        if mode & 0o111 == 0 {
            assert!(
                msg.contains(&format!("mode {mode:o}")) && msg.contains("PermissionDenied"),
                "a readable but non-executable artifact must be diagnosed as such \
                 (mode {mode:o}); got: {msg}"
            );
        }
    }

    // …and the resolution path the dashboard lane actually goes through, with
    // `FRPS_BIN` pointing at the same marker-less file.
    std::env::set_var("FRPS_BIN", &fake_path);
    let err = std::panic::catch_unwind(common::frps_binary)
        .expect_err("frps_binary() must run the guard in a dashboard build");
    restore_frps_bin();
    let msg = panic_text(&*err);
    assert!(
        msg.contains("rebuild `frps --features dashboard`"),
        "frps_binary()'s failure must carry the same rebuild instruction; got: {msg}"
    );
    assert!(
        msg.contains(&fake_path),
        "frps_binary()'s failure must name the FRPS_BIN it resolved; got: {msg}"
    );

    // ── positive control 1: the marker, not the file name, decides ──
    // The real dashboard artifact holds this byte string twice — the plain
    // `"Dashboard listening on {}"` and the TLS `"…{} (TLS)"` format string —
    // so a marked file with the TLS suffix must also pass (that is the
    // misfire this pins against).
    let marked = dir.path().join("frps-with-marker");
    std::fs::write(
        &marked,
        b"... Dashboard listening on 127.0.0.1:7500 (TLS) ...\n",
    )
    .unwrap();
    let marked_path = marked.to_str().unwrap();
    assert_eq!(
        common::dashboard_listener_present(marked_path),
        Some(true),
        "a file carrying the listener marker must be reported present"
    );
    common::assert_frps_has_dashboard(marked_path); // must not panic

    // ── positive control 2: the artifact *this lane* resolves passes the guard ──
    // `FRPS_BIN` was restored above, so `frps_binary()` here is the same call
    // and the same path the dashboard lane itself uses (CI sets `FRPS_BIN`
    // explicitly). Non-vacuous on purpose: a missing binary is reported `None`
    // (silent) by the guard, so existence *and* the marker are asserted here,
    // and the resolved path is pinned to `FRPS_BIN` when the lane set it.
    let real = common::frps_binary();
    if let Some(lane) = &lane_frps_bin {
        assert_eq!(
            &real, lane,
            "the positive control must resolve the lane's own `FRPS_BIN`, not a fallback"
        );
    }
    assert!(
        std::path::Path::new(&real).is_file(),
        "this lane resolved `{real}` (FRPS_BIN={lane_frps_bin:?}), which does not exist — \
         build `frps --features dashboard` first"
    );
    assert_eq!(
        common::dashboard_listener_present(&real),
        Some(true),
        "the artifact this lane resolved (`{real}`) carries no `{}`: it was replaced by a \
         no-dashboard build (`cargo test -p frps`, or any plain `cargo build -p frps`). \
         Rebuild it with `cargo build -p frps --features dashboard` and re-run this lane.",
        common::DASHBOARD_LISTEN_MARKER
    );

    // Re-asking must give the same verdict, and re-running the guard on it must
    // stay silent. This cannot observe the per-process cache: every `cargo test`
    // test binary is a fresh process, so a hit and a re-scan are
    // indistinguishable from in here — the caching is reasoned about in
    // `common::DASHBOARD_VERDICTS`, not pinned by this test.
    assert_eq!(common::dashboard_listener_present(&real), Some(true));
    common::assert_frps_has_dashboard(&real); // must not panic

    // ── the silent branch: an absent / unreadable path is not a feature claim ──
    // `assert_frps_has_dashboard` must stay silent there, because a missing
    // binary's own `Command::spawn` error (`Os { code: 2, kind: NotFound }`) is
    // the better message. This is a deliberate partial-coverage decision, so it
    // is pinned rather than left to a future edit.
    let absent = dir.path().join("no-such-frps-at-all");
    let absent_path = absent.to_str().unwrap();
    assert_eq!(
        common::dashboard_listener_present(absent_path),
        None,
        "an absent path must be reported unknown (None), not absent-marker (Some(false))"
    );
    common::assert_frps_has_dashboard(absent_path); // must not panic
    assert_eq!(
        common::dashboard_listener_present(dir.path().to_str().unwrap()),
        None,
        "a directory must be reported unknown (None), not absent-marker (Some(false))"
    );
    common::assert_frps_has_dashboard(dir.path().to_str().unwrap()); // must not panic

    // A marker-less `FRPS_BIN` verdict must not be reported for the real
    // artifact's path (whatever bookkeeping the guard keeps is keyed by path,
    // and this is the arm that would catch a key mix-up).
    std::env::set_var("FRPS_BIN", &fake_path);
    let err = std::panic::catch_unwind(common::frps_binary)
        .expect_err("frps_binary() must still guard the marker-less FRPS_BIN");
    restore_frps_bin();
    assert!(
        panic_text(&*err).contains("rebuild `frps --features dashboard`"),
        "the guard must not have been disabled by the earlier successful checks"
    );
    assert_eq!(
        common::dashboard_listener_present(&real),
        Some(true),
        "the marker-less FRPS_BIN verdict must not be cached under the real artifact's path"
    );
}
