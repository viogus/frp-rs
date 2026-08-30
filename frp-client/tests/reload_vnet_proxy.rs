//! M6 regression: a reload that changes a `virtual_net` plugin proxy must
//! NOT abort unrelated proxy changes in the same reload.
//!
//! Pre-fix, the reload plugin-restart loop called `start_plugin` for every
//! added/changed proxy carrying a plugin section; `start_plugin` returns
//! `None` for `plugin_type == "virtual_net"` (it is not a local-listener
//! plugin — startup skips it the same way), and the changed-arm misread
//! that `None` as a restart FAILURE and aborted the ENTIRE reload with
//! "plugin 'virtual_net' failed to restart ...". The tcp proxy's remotePort
//! change in the same reload was silently dropped.
//!
//! The reload path needs a config FILE (Service::new's `config_file`
//! argument), so this test drives `request_reload()` and observes the
//! effect: the tcp proxy must come up on its NEW remote port. In this test
//! environment the vnet TUN cannot open (needs root/CAP_NET_ADMIN) — the
//! client warns and continues, which is exactly the tolerated path.

mod common;

use std::sync::Arc;
use std::time::Duration;

use frp_client::service::Service as ClientService;
use frp_core::config::load_client_config;

use common::{allocate_port, init_tracing, start_echo_server, wait_for_port};

fn write_config(
    path: &std::path::Path,
    server_port: u16,
    echo_port: u16,
    tcp_remote_port: u16,
    vnet_name: &str,
) {
    std::fs::write(
        path,
        format!(
            r#"serverAddr = "127.0.0.1"
serverPort = {server_port}
loginFailExit = false
token = "reload-vnet-token"

[transport]
tcpMux = false

[featureGates]
VirtualNet = true

[virtualNet]
address = "10.0.0.1"

[[proxies]]
name = "vnet-proxy"
type = "tcp"
remotePort = 0
virtual_net = "{vnet_name}"

[proxies.plugin]
type = "virtual_net"

[[proxies]]
name = "tcp-proxy"
type = "tcp"
localIp = "127.0.0.1"
localPort = {echo_port}
remotePort = {tcp_remote_port}
"#
        ),
    )
    .expect("write config");
}

#[tokio::test]
async fn reload_vnet_proxy_change_does_not_abort_unrelated_changes() {
    init_tracing();
    let echo_port = allocate_port();
    let server_port = allocate_port();
    let p1 = allocate_port();
    let p2 = allocate_port();

    // 1. Echo server + frps.
    let _echo = start_echo_server(echo_port);
    let _server = common::start_frps(server_port, "reload-vnet-token").await;
    let server_addr: std::net::SocketAddr = format!("127.0.0.1:{server_port}").parse().unwrap();
    wait_for_port(server_addr, Duration::from_secs(5))
        .await
        .expect("server ready");

    // 2. Config file with a virtual_net plugin proxy + a plain tcp proxy.
    let dir = std::env::temp_dir().join(format!("frp-reload-vnet-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let cfg_path = dir.join("frpc.toml");
    write_config(&cfg_path, server_port, echo_port, p1, "corp-net");

    let cfg = load_client_config(cfg_path.to_str().unwrap(), false).expect("load initial config");
    let client = Arc::new(
        ClientService::new(cfg, Some(cfg_path.to_string_lossy().into()))
            .await
            .expect("create client service"),
    );
    let runner = {
        let client = client.clone();
        tokio::spawn(async move {
            let _ = client.run().await;
        })
    };

    // 3. Initial tcp proxy live on p1.
    let p1_addr: std::net::SocketAddr = format!("127.0.0.1:{p1}").parse().unwrap();
    wait_for_port(p1_addr, Duration::from_secs(15))
        .await
        .expect("initial proxy port ready");

    // 4. Rewrite the config: change the vnet proxy's network AND the tcp
    // proxy's remote port in one reload. Pre-fix, the vnet change hit the
    // plugin-restart Err arm and the whole reload aborted — p2 never opens.
    write_config(&cfg_path, server_port, echo_port, p2, "corp-net-2");
    client.request_reload();

    // 5. The tcp proxy must come up on the NEW port within the window.
    let p2_addr: std::net::SocketAddr = format!("127.0.0.1:{p2}").parse().unwrap();
    wait_for_port(p2_addr, Duration::from_secs(15))
        .await
        .expect("reload must apply the tcp proxy change despite the virtual_net proxy change (M6)");

    // 6. And the new proxy must actually carry traffic.
    let mut stream = tokio::net::TcpStream::connect(p2_addr)
        .await
        .expect("connect to reloaded proxy port");
    let payload = b"reload vnet regression\n";
    tokio::io::AsyncWriteExt::write_all(&mut stream, payload)
        .await
        .expect("write through reloaded proxy");
    let mut buf = vec![0u8; payload.len()];
    tokio::io::AsyncReadExt::read_exact(&mut stream, &mut buf)
        .await
        .expect("read echo through reloaded proxy");
    assert_eq!(&buf, payload, "echo through reloaded proxy must match");

    client.request_stop();
    let _ = tokio::time::timeout(Duration::from_secs(5), runner).await;
    let _ = std::fs::remove_dir_all(&dir);
}
