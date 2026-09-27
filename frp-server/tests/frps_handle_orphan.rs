//! Pins hazard (b) of `TODO.md`'s “Two test-harness hazards” item:
//! `FrpsHandle::start` used to spawn `frps` and `.expect()` its port waits
//! **before** constructing the handle whose `Drop` kills and reaps — so a panic
//! in a wait left a live `frps` behind with `PPID 1`, its `TempDir` already
//! removed, and its ports still held (measured at the pre-fix head: 17 such
//! children at `PPID 1`, 20 listeners, when the dashboard lane ran against the
//! no-dashboard artifact).
//!
//! The forcing here needs no second binary and no env var: the config points
//! the dashboard at an address no host can bind (TEST-NET-1), so frps cannot
//! bring the dashboard up, the dashboard wait times out, and the
//! `.expect("frps dashboard_port not ready")` panics — the exact panic path
//! that used to orphan the child. The test then asserts the child is gone,
//! using the control port it was observed to hold as the witness (so the
//! assertion cannot pass vacuously on a child that never started), and reaps
//! what a regression leaked *before* failing.

mod common;

use std::process::Command;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;

/// Panic payload → text, so the assertion below can check *which* wait failed.
fn panic_text(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else if let Some(s) = payload.downcast_ref::<&'static str>() {
        (*s).to_string()
    } else {
        "<non-string panic payload>".to_string()
    }
}

/// `(pid, "pid … ppid … command …")` for every process listening on
/// `127.0.0.1:port`, via `lsof -t` + `ps`. `Err` only when the tools could not
/// be run at all, so the failure message can distinguish "no survivor" from
/// "could not look" instead of reporting an empty list for both.
fn listeners_on(port: u16) -> Result<Vec<(String, String)>, String> {
    let out = Command::new("lsof")
        .args(["-nP", &format!("-iTCP:{port}"), "-sTCP:LISTEN", "-t"])
        .output()
        .map_err(|e| format!("could not run lsof: {e}"))?;
    // lsof exits 1 with empty output when the selector matches nothing.
    let mut found = Vec::new();
    for pid in String::from_utf8_lossy(&out.stdout).split_whitespace() {
        let desc = match Command::new("ps")
            .args(["-o", "pid=,ppid=,command=", "-p", pid])
            .output()
        {
            Ok(o) => String::from_utf8_lossy(&o.stdout).trim().to_string(),
            Err(e) => format!("pid {pid} (ps failed: {e})"),
        };
        found.push((pid.to_string(), desc));
    }
    Ok(found)
}

#[tokio::test]
async fn start_panic_does_not_orphan_the_child_it_spawned() {
    let bind_port = common::allocate_port();
    let dashboard_port = common::allocate_port();

    // Forcing, measured with this exact shape (`/tmp/hh-probe2.sh` against the
    // dashboard artifact): `[web_server].addr = "192.0.2.1"` is TEST-NET-1, an
    // address no host here can bind, so frps logs
    // `Dashboard server failed: Can't assign requested address (os error 49)`
    // and **stays alive** holding the control port — the orphan this test pins.
    // The dashboard wait then times out and the `.expect("frps dashboard_port
    // not ready")` panics, which is the pre-fix `common/mod.rs` shape recorded
    // in the item.
    //
    // `[auth].token` is required or frps refuses to start at all ("security
    // misconfiguration: … token … resolved empty"), which would move the panic
    // to the bind-port wait. Credentials under `[web_server]` are required or
    // the no-auth force-bind in `frp-server/src/dashboard.rs` rewrites the
    // address to 127.0.0.1, the dashboard comes up healthy, and `start` never
    // panics at all. Do not drop either block.
    let cfg = format!(
        "bind_addr = \"127.0.0.1\"\n\
         bind_port = {bind_port}\n\
         \n\
         [auth]\n\
         method = \"token\"\n\
         token = \"test-token\"\n\
         \n\
         [web_server]\n\
         addr = \"192.0.2.1\"\n\
         port = {dashboard_port}\n\
         user = \"admin\"\n\
         password = \"admin\"\n"
    );

    // Run the panicking `start` on its own task: a panic inside a tokio task is
    // caught by the runtime and surfaces as a `JoinError`, which also lets the
    // test observe the moment the wait fails.
    let task = tokio::spawn(async move {
        let _handle = common::FrpsHandle::start_with_timeout(&cfg, Duration::from_secs(5)).await;
    });

    // Witness that the child really was alive and listening on the control port
    // before the panic: without this, "the port is free afterwards" would be
    // true for a child that never started. Bounded by its own deadline.
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut saw_bound = false;
    while Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", bind_port)).await.is_ok() {
            saw_bound = true;
            break;
        }
        if task.is_finished() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    let join = task
        .await
        .expect_err("the forcing config must make FrpsHandle::start panic");
    assert!(
        join.is_panic(),
        "FrpsHandle::start must have panicked (not been cancelled): {join:?}"
    );
    let payload = join.into_panic();
    let msg = panic_text(&*payload);
    assert!(
        msg.contains("frps dashboard_port not ready"),
        "the panic must come from the dashboard wait this test forces; got: {msg}"
    );
    assert!(
        saw_bound,
        "the child never bound 127.0.0.1:{bind_port} before the panic, so the assertions \
         below would pass vacuously"
    );

    // No child outlives the test: the handle's Drop ran during unwinding, so
    // the control listener this test observed is gone and the port is free.
    let connect_refused = TcpStream::connect(("127.0.0.1", bind_port)).await.is_err();
    let rebindable = std::net::TcpListener::bind(("127.0.0.1", bind_port)).is_ok();
    if !connect_refused || !rebindable {
        // Name the survivor, then reap it before failing: this test is *about*
        // leaked children, so it must not leak one itself.
        let survivors = match listeners_on(bind_port) {
            Ok(v) if v.is_empty() => vec![(
                String::from("<none>"),
                format!(
                    "`lsof` reports nothing listening on 127.0.0.1:{bind_port} \
                     (connect_refused={connect_refused}, rebindable={rebindable}) — the port is \
                     held by something `lsof` did not name"
                ),
            )],
            Ok(v) => v,
            Err(e) => vec![(String::from("<unknown>"), e)],
        };
        for (pid, _) in &survivors {
            if pid.chars().all(|c| c.is_ascii_digit()) {
                let _ = Command::new("kill").arg(pid).status();
            }
        }
        panic!(
            "a process outlived the test on 127.0.0.1:{bind_port} \
             (connect_refused={connect_refused}, rebindable={rebindable}); killed before \
             failing:\n  {}",
            survivors
                .iter()
                .map(|(_, d)| d.as_str())
                .collect::<Vec<_>>()
                .join("\n  ")
        );
    }
}
