//! SSH Tunnel Gateway — SSH client registration → frp proxy.
//!
//! Users connect with a standard SSH client:
//!   ssh -R :80:127.0.0.1:8080 v0@server -p 2200 tcp --proxy_name "web" --remote_port 9090
//!
//! The remote command string is parsed into a ProxyConfig.
//!
//! SSH reverse forwarding (`tcpip_forward` / `-R`) is supported: the port
//! allocation/work-connection bridge opens `forwarded-tcpip` channels back to
//! the SSH client, matching Go frp's ssh tunnel gateway (pkg/ssh/server.go,
//! gateway.go). Go semantics: `tcpip-forward` is accepted without binding a
//! port; the recorded address is used as the forwarded-tcpip channel payload.
//!
//! NOTE: russh 0.61 transitively depends on rsa 0.10.0-rc.18 which has a known
//! timing sidechannel (RUSTSEC-2023-0071, Marvin Attack). Only affects the SSH
//! gateway feature. Monitor upstream for fix.

mod args;
mod bridge;
mod session;
pub use session::SshSession;
mod frame;
use bridge::handle_work_conn_requests;
mod keys;
#[cfg(test)]
use frame::exec_request_log_summary;
use frame::{build_v1_frame_from_args, log_exec_request};
mod stream;
use keys::{load_or_generate_host_key, parse_authorized_keys};
mod virtual_control;
use args::{parse_ssh_args, ssh_gateway_usage, ParsedProxyArgs};
#[cfg(test)]
use args::{shell_split, VALID_PROXY_TYPES};
#[cfg(test)]
use frp_core::msg::{FrpMessage, NewProxyResp};
#[cfg(test)]
use russh::server::{Auth, Handler};
use std::sync::Arc;
use stream::{terminate_ssh_session, CloseableSshStream};
pub use virtual_control::{VirtualControl, WorkConnRequest};

use crate::service::AppState;

/// Clean up a disconnected SSH session: remove all registered proxies.
pub async fn cleanup_session(run_id: &str, state: &Arc<AppState>) {
    #[cfg(feature = "vnet")]
    state.remove_run_id_vnet_routes(run_id).await;
    state.proxy_manager.remove_client(run_id).await;
    tracing::info!(run_id = %run_id, "SSH session {} cleaned up", run_id);
}

#[cfg(test)]
mod tests;

use std::borrow::Cow;

use russh::server::Config;
use tokio::net::TcpListener;

const SSH_MAX_CONNECTIONS: usize = 128;
const SSH_AUTH_DEADLINE: std::time::Duration = std::time::Duration::from_secs(15);
const SSH_DISCONNECT_GRACE: std::time::Duration = std::time::Duration::from_millis(250);

/// Per-IP pre-auth connection cap (round-13 audit S finding). The global
/// 128-slot semaphore cannot stop ONE source IP from occupying every slot:
/// a denied conn (bad password/key, throttle window) holds its slot for
/// the whole auth deadline (~15s), so a single reconnect-looping source
/// (~8.5 attempts/s — each fresh TCP conn gets a fresh pre-auth hold)
/// fills all 128 slots in ~15s and starves every other client. Each source
/// IP therefore gets its own small PRE-AUTH budget; the permit is held
/// only while the conn is unauthenticated and released as soon as auth
/// settles — success (the conn then counts against the global 128 like
/// any other tunnel) or the conn ends. Legit clients with many concurrent
/// sessions are unaffected: post-auth conns hold no per-IP permit.
const SSH_PREAUTH_PER_IP_CAP: usize = 8;

/// Per-IP pre-auth slot registry: source IP -> its own pre-auth semaphore.
/// Entries are removed when the last outstanding permit of an IP returns
/// (see `PreauthPermit::drop`), so the map stays bounded by the number of
/// IPs with in-flight pre-auth conns (itself bounded by the global
/// SSH_MAX_CONNECTIONS cap) instead of growing per distinct source IP.
type PerIpPreauthMap = std::sync::Mutex<
    std::collections::HashMap<std::net::IpAddr, std::sync::Arc<tokio::sync::Semaphore>>,
>;

/// A held per-IP pre-auth slot. Release returns the slot to the IP's
/// semaphore; when that release empties the semaphore (all of the IP's
/// pre-auth conns have settled), the map entry is removed.
struct PreauthPermit {
    ip: std::net::IpAddr,
    map: std::sync::Arc<PerIpPreauthMap>,
    sem: std::sync::Arc<tokio::sync::Semaphore>,
    permit: Option<tokio::sync::OwnedSemaphorePermit>,
}

impl Drop for PreauthPermit {
    fn drop(&mut self) {
        // Release the slot first so the availability check below reflects
        // this release.
        drop(self.permit.take());
        if let Ok(mut map) = self.map.lock() {
            if let Some(entry) = map.get(&self.ip) {
                // Remove only when (a) THIS semaphore is still the one the
                // map holds — a concurrent acquire may have removed and
                // re-inserted a fresh semaphore after an earlier release,
                // and removing that entry would drop the new owner's slot
                // bookkeeping — and (b) no permits are outstanding.
                if std::sync::Arc::ptr_eq(entry, &self.sem)
                    && entry.available_permits() == SSH_PREAUTH_PER_IP_CAP
                {
                    map.remove(&self.ip);
                }
            }
        }
    }
}

/// How long exec_request waits for the NewProxyResp of a registration —
/// Go frp's waitProxyStatusReady poll budget (time.Second).
const PROXY_REGISTER_WAIT: std::time::Duration = std::time::Duration::from_secs(1);

/// SSH tunnel gateway listener. Binds a TCP port and accepts SSH connections.
pub struct SshListener {
    bind_addr: String,
    bind_port: u16,
    server_token: String,
    state: std::sync::Arc<AppState>,
    host_key: russh::keys::PrivateKey,
    authorized_keys: Vec<russh::keys::PublicKey>,
    auth_deadline: std::time::Duration,
    /// Authenticated-session idle timeout in seconds. 0 = disabled (default,
    /// Go frp parity — Go has no SSH idle timeout). Wired from
    /// `SshTunnelGatewayConfig.ssh_session_idle_timeout`.
    ssh_session_idle_timeout: u64,
}

impl SshListener {
    pub async fn new(
        cfg: &frp_core::config::ServerConfig,
        state: std::sync::Arc<AppState>,
        server_token: String,
    ) -> Result<Option<Self>, String> {
        let ssh_cfg = &cfg.ssh_tunnel_gateway;
        if ssh_cfg.bind_port == 0 {
            return Ok(None);
        }

        let host_key = load_or_generate_host_key(
            &ssh_cfg.private_key_file,
            &ssh_cfg.auto_gen_private_key_path,
        )
        .await?;

        let authorized_keys = if !ssh_cfg.authorized_keys_file.is_empty() {
            let path = std::path::Path::new(&ssh_cfg.authorized_keys_file);
            if path.exists() {
                std::fs::read_to_string(path)
                    .map(|s| parse_authorized_keys(&s))
                    .unwrap_or_default()
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        // SECURITY: when neither authorized_keys nor server_token is
        // configured, auth_none accepts every connection (Go frp NoClientAuth
        // compat). Fail closed by default — refuse to start — unless the
        // operator explicitly opts in with `allowNoneAuth = true`. A gateway
        // that silently accepts every SSH client and lets it register proxies
        // (ports/domains) must never come up by accident.
        if authorized_keys.is_empty() && server_token.is_empty() {
            if !ssh_cfg.allow_none_auth {
                return Err(
                    "SSH gateway: no authorized_keys and no server_token configured — refusing to start with unauthenticated access. Configure ssh_tunnel_gateway.authorized_keys_file / server token, or set ssh_tunnel_gateway.allowNoneAuth = true to explicitly allow unauthenticated connections on a trusted network."
                        .into(),
                );
            }
            tracing::warn!(
                "SSH gateway: no authorized_keys and no server_token configured — ANY SSH client can connect without authentication and register proxies (allowNoneAuth = true)"
            );
        }

        Ok(Some(Self {
            bind_addr: ssh_cfg.bind_addr.clone(),
            bind_port: ssh_cfg.bind_port,
            server_token,
            state,
            host_key,
            authorized_keys,
            auth_deadline: SSH_AUTH_DEADLINE,
            ssh_session_idle_timeout: ssh_cfg.ssh_session_idle_timeout,
        }))
    }

    pub async fn run(self) -> Result<(), Box<dyn std::error::Error>> {
        let addr = format!("{}:{}", self.bind_addr, self.bind_port);
        let listener = TcpListener::bind(&addr).await?;
        tracing::info!(address = %addr, "SSH tunnel gateway listening on {}", addr);

        // Build russh server config, wrap in Arc (required by run_stream)
        let mut russh_config = Config::default();
        russh_config.keys.push(self.host_key.clone());
        russh_config.auth_rejection_time = std::time::Duration::from_secs(3);
        russh_config.server_id = russh::SshId::Standard(Cow::Owned(format!(
            "SSH-2.0-frp-rs_{}",
            env!("CARGO_PKG_VERSION")
        )));
        let russh_config = std::sync::Arc::new(russh_config);
        let ssh_connections = Arc::new(tokio::sync::Semaphore::new(SSH_MAX_CONNECTIONS));
        // Per-IP pre-auth slot registry (see SSH_PREAUTH_PER_IP_CAP).
        let per_ip_preauth: std::sync::Arc<PerIpPreauthMap> =
            std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
        let auth_timeout = self.auth_deadline;

        loop {
            // Check for graceful shutdown before blocking on accept.
            if self.state.shutdown_token.is_cancelled() {
                tracing::info!("SSH tunnel gateway shutting down");
                return Ok(());
            }
            let (stream, peer_addr) = match listener.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    tracing::error!(error = %e, "SSH accept error: {}", e);
                    continue;
                }
            };

            tracing::info!(peer_address = %peer_addr, "SSH connection from {}", peer_addr);

            // SSH terminal traffic is the canonical small-message workload — disable Nagle.
            frp_core::transport::set_nodelay(&stream);
            if self.state.tcp_keepalive > 0 {
                frp_core::transport::set_keepalive(&stream, self.state.tcp_keepalive as u64);
            }

            let state = self.state.clone();
            let server_token = self.server_token.clone();
            let authorized_keys = self.authorized_keys.clone();
            let russh_config = russh_config.clone();
            let ssh_session_idle_timeout = self.ssh_session_idle_timeout;
            let auth_deadline = tokio::time::Instant::now() + auth_timeout;
            let ssh_permit = match ssh_connections.clone().try_acquire_owned() {
                Ok(permit) => permit,
                Err(_) => {
                    tracing::warn!(peer_address = %peer_addr, "SSH connection limit reached");
                    continue;
                }
            };
            let global_permit = match state.conn_semaphore.as_ref() {
                Some(semaphore) => match semaphore.clone().try_acquire_owned() {
                    Ok(permit) => Some(permit),
                    Err(_) => {
                        tracing::warn!(peer_address = %peer_addr, "Global connection limit reached for SSH");
                        continue;
                    }
                },
                None => None,
            };
            // Per-IP pre-auth slot: acquire BEFORE the SSH handshake (the
            // handshake runs unauthenticated for up to the auth deadline).
            // A denied conn must not be allowed to hold one of the 128
            // global slots for the full deadline while a single source
            // reconnect-loops (see SSH_PREAUTH_PER_IP_CAP). At an IP's own
            // cap the conn is dropped immediately — no handshake started.
            let preauth_permit = {
                let ip = peer_addr.ip();
                // Look up (or create) the IP's semaphore and acquire under
                // the SAME lock hold: try_acquire_owned never blocks, and
                // holding the map lock across clone + acquire closes the
                // round-13 review race where a final permit release removes
                // the entry between a clone and the acquire — an acquire on
                // that orphaned semaphore would let a fresh full entry
                // coexist with the stale holder (transient 9th concurrent
                // pre-auth). Once a permit is held the entry is pinned:
                // removal requires all SSH_PREAUTH_PER_IP_CAP permits
                // returned (see PreauthPermit::drop), so no later release
                // can remove it while this one is outstanding.
                let mut map = per_ip_preauth.lock().unwrap_or_else(|e| e.into_inner());
                let sem = map
                    .entry(ip)
                    .or_insert_with(|| {
                        std::sync::Arc::new(tokio::sync::Semaphore::new(SSH_PREAUTH_PER_IP_CAP))
                    })
                    .clone();
                match sem.clone().try_acquire_owned() {
                    Ok(permit) => PreauthPermit {
                        ip,
                        map: per_ip_preauth.clone(),
                        sem,
                        permit: Some(permit),
                    },
                    Err(_) => {
                        tracing::warn!(peer_address = %peer_addr, "SSH pre-auth connection cap reached for {}", ip);
                        continue;
                    }
                }
            };

            tokio::spawn(async move {
                let _ssh_permit = ssh_permit;
                let _global_permit = global_permit;
                let preauth_permit = preauth_permit;
                let (stream, stream_closer) = CloseableSshStream::new(stream);
                let (auth_complete_tx, mut auth_complete_rx) = tokio::sync::watch::channel(false);
                let authenticated_run_id = Arc::new(std::sync::Mutex::new(None));
                // Session-wide teardown signal: cancelled when the SSH
                // virtual control handler exits (see auth_succeeded).
                let control_exit = tokio_util::sync::CancellationToken::new();
                let session = SshSession::new(
                    server_token,
                    authorized_keys,
                    state.clone(),
                    peer_addr,
                    auth_complete_tx,
                    authenticated_run_id.clone(),
                    auth_deadline,
                    control_exit.clone(),
                );

                let running = match tokio::time::timeout_at(
                    auth_deadline,
                    russh::server::run_stream(russh_config, stream, session),
                )
                .await
                {
                    Ok(Ok(running)) => running,
                    Ok(Err(e)) => {
                        tracing::debug!(peer_address = %peer_addr, error = ?e, "SSH handshake failed");
                        return;
                    }
                    Err(_) => {
                        tracing::warn!(peer_address = %peer_addr, "SSH handshake timed out");
                        let run_id = authenticated_run_id
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .clone();
                        if let Some(run_id) = run_id {
                            cleanup_session(&run_id, &state).await;
                        }
                        return;
                    }
                };
                let session_handle = running.handle();
                let mut session_task = tokio::spawn(running);

                let pre_auth_result = if *auth_complete_rx.borrow() {
                    None
                } else {
                    tokio::select! {
                        biased;
                        changed = auth_complete_rx.changed() => {
                            let _ = changed;
                            None
                        }
                        result = &mut session_task => Some(result),
                        _ = tokio::time::sleep_until(auth_deadline) => {
                            if *auth_complete_rx.borrow() {
                                None
                            } else {
                                tracing::warn!(peer_address = %peer_addr, "SSH authentication timed out");
                                terminate_ssh_session(
                                    async {
                                        let _ = session_handle.disconnect(
                                        russh::Disconnect::ByApplication,
                                        "SSH authentication timed out".into(),
                                        String::new(),
                                    )
                                    .await;
                                    },
                                    &mut session_task,
                                    &stream_closer,
                                    SSH_DISCONNECT_GRACE,
                                ).await;
                                let run_id = authenticated_run_id.lock().unwrap_or_else(|e| e.into_inner()).clone();
                                if let Some(run_id) = run_id {
                                    cleanup_session(&run_id, &state).await;
                                }
                                return;
                            }
                        }
                    }
                };

                // Auth settled. When the session authenticated, the conn is
                // a trusted tunnel — release the per-IP pre-auth slot (it
                // now counts against the global 128 like any other conn; a
                // legit client's 9th+ concurrent session must not be
                // blocked by its own earlier tunnels). When it did not,
                // the conn is ending and the permit drops with this task
                // (either path above that `return`s, or the session-task
                // result match below).
                if *auth_complete_rx.borrow() {
                    drop(preauth_permit);
                }

                let result = match pre_auth_result {
                    Some(result) => result,
                    None => {
                        // Idle timeout: bound the authenticated-session wait
                        // so an idle session cannot hold its conn_semaphore
                        // permit / task / fd forever. 0 = disabled (Go frp
                        // parity — Go has no SSH idle timeout).
                        //
                        // The wait is also raced against the virtual control
                        // handler's exit: the SSH virtual client never sends
                        // Ping, so with an operator-set
                        // transport.heartbeatTimeout the server's heartbeat
                        // cleanup kills handle_control (and sweeps the
                        // SSH-registered proxies) while the russh session
                        // would otherwise keep running — holding the SSH fd +
                        // conn_semaphore permit and silently dropping every
                        // later -R tcpip-forward work conn. When the control
                        // handler exits we terminate the SSH session
                        // deterministically instead.
                        let outcome = tokio::select! {
                            biased;
                            _ = control_exit.cancelled() => {
                                let run_id = authenticated_run_id
                                    .lock()
                                    .unwrap_or_else(|e| e.into_inner())
                                    .clone();
                                tracing::warn!(
                                    run_id = ?run_id,
                                    "SSH session: virtual control handler exited; closing SSH session"
                                );
                                terminate_ssh_session(
                                    async {
                                        let _ = session_handle.disconnect(
                                            russh::Disconnect::ByApplication,
                                            "control handler exited".into(),
                                            String::new(),
                                        )
                                        .await;
                                    },
                                    &mut session_task,
                                    &stream_closer,
                                    SSH_DISCONNECT_GRACE,
                                ).await;
                                if let Some(run_id) = run_id {
                                    cleanup_session(&run_id, &state).await;
                                }
                                return;
                            }
                            r = async {
                                if ssh_session_idle_timeout > 0 {
                                    tokio::time::timeout(
                                        std::time::Duration::from_secs(ssh_session_idle_timeout),
                                        &mut session_task,
                                    )
                                    .await
                                } else {
                                    Ok((&mut session_task).await)
                                }
                            } => r,
                        };
                        match outcome {
                            Ok(r) => r,
                            Err(_) => {
                                let run_id = authenticated_run_id
                                    .lock()
                                    .unwrap_or_else(|e| e.into_inner())
                                    .clone();
                                tracing::warn!(
                                    run_id = ?run_id,
                                    idle_timeout_secs = ssh_session_idle_timeout,
                                    "SSH session idle timeout ({}s), closing",
                                    ssh_session_idle_timeout
                                );
                                session_task.abort();
                                if let Some(run_id) = run_id {
                                    cleanup_session(&run_id, &state).await;
                                }
                                return;
                            }
                        }
                    }
                };
                let run_id = authenticated_run_id
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .clone();
                match result {
                    Ok(Ok(())) => {
                        tracing::info!(run_id = ?run_id, "SSH session ended normally");
                    }
                    Ok(Err(e)) => {
                        tracing::error!(
                            run_id = ?run_id,
                            error = ?e,
                            "SSH session error"
                        );
                    }
                    Err(e) => {
                        tracing::debug!(run_id = ?run_id, error = %e, "SSH session task cancelled")
                    }
                }

                if let Some(run_id) = run_id {
                    cleanup_session(&run_id, &state).await;
                }
            });
        }
    }
}

#[cfg(test)]
mod key_tests;

#[cfg(test)]
mod virtual_ctrl_tests;

/// B10: `PreauthPermit` map-removal semantics — an IP's semaphore entry
/// lives exactly as long as the IP has an outstanding pre-auth permit
/// (bounded map, no growth per distinct source), and a stale permit can
/// never remove a newer entry (round-13 review race: a final release
/// removing a fresh re-inserted semaphore would orphan the new owner).
#[cfg(test)]
mod preauth_tests;
