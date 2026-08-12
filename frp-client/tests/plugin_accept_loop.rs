//! Documented-attempt regression test for the audit finding "plugin listener
//! dies on transient accept error".
//!
//! The fix: an accept error (EMFILE/ENFILE fd exhaustion, etc.) is logged at
//! warn and the loop retries after a brief 100ms pause, breaking only on the
//! shutdown signal. `serve_plugin` is the shared accept loop for all 8 TCP
//! plugins (http_proxy, socks5, static_file, tls2raw, http2http/http2https/
//! https2http/https2https); `unix_socket.rs` has its own copy of the loop,
//! covered by a churn test in `plugin_unix_socket.rs`.
//!
//! The harness cannot inject a real accept error: `serve_plugin` binds its
//! own listener inside the spawned task, and the public `PluginHandle`
//! exposes neither the listener nor a way to force fd exhaustion (lowering
//! RLIMIT_NOFILE inside a parallel cargo test process would destabilize the
//! sibling tests sharing the process). The closest observable proxy is loop
//! liveness: the listener must keep accepting and handling connections
//! across churn — pre-fix, a single accept error (which any transient
//! condition can produce) broke the loop permanently.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use frp_core::config::PluginConfig;

/// Start the http_proxy plugin and verify the accept loop survives repeated
/// connection churn. Each iteration connects, sends a request the handler
/// rejects, half-closes, and must observe the handler closing the connection
/// (EOF) — proof the connection was accepted AND handled. A dead accept loop
/// would leave the connection sitting unaccepted in the kernel queue and the
/// read would hang.
#[tokio::test]
async fn test_plugin_accept_loop_survives_connection_churn() {
    let cfg = PluginConfig {
        plugin_type: "http_proxy".into(),
        ..Default::default()
    };
    let handle = match frp_client::plugin::start_http_proxy(&cfg).await {
        Ok(h) => h,
        Err(e) => {
            eprintln!("Skipping test: cannot start plugin (sandboxed): {e}");
            return;
        }
    };

    for i in 0..3 {
        let mut client = TcpStream::connect(handle.local_addr)
            .await
            .unwrap_or_else(|e| {
                panic!("churn iteration {i}: connect failed — accept loop dead: {e}")
            });
        // Garbage request, then half-close: the handler fails to parse it
        // and closes the connection — EOF proves accepted + handled.
        client.write_all(b"not-an-http-request\r\n").await.unwrap();
        client.shutdown().await.unwrap();
        let mut buf = [0u8; 16];
        let n = tokio::time::timeout(std::time::Duration::from_secs(5), client.read(&mut buf))
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "churn iteration {i}: read timed out — connection was never accepted/handled"
                )
            })
            .expect("read");
        assert_eq!(
            n, 0,
            "churn iteration {i}: handler must close the connection, got {n} bytes"
        );
    }

    // Shutdown must still terminate the loop: breaking ONLY on the shutdown
    // signal means dropping the handle ends the task and closes the
    // listener. Poll briefly for the close (the task may take a tick).
    let addr = handle.local_addr;
    drop(handle);
    let mut closed = false;
    for _ in 0..50 {
        if TcpStream::connect(addr).await.is_err() {
            closed = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(
        closed,
        "listener still accepting connections after shutdown"
    );
}
