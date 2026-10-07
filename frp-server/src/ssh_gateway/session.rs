//! The per-connection SSH session handler (`SshSession` + its russh
//! `Handler` impl) and the exec-channel response writer.
//!
//! Split out of `ssh_gateway.rs` as a pure text move; the parent re-exports
//! `SshSession` for its listener loop, and the sibling `tests` module drives
//! the auth methods and reads a handful of fields directly.

use std::sync::Arc;

use anyhow::anyhow;
use dashmap::DashMap;
use frp_core::auth::constant_time_eq;
use frp_core::msg::NewProxyResp;
use russh::server::{Auth, ChannelOpenHandle, Handler, Msg, Session};
use russh::{Channel, ChannelId, ChannelOpenFailure, MethodKind, MethodSet};
use tokio::sync::mpsc;

use crate::service::AppState;

use super::{
    build_v1_frame_from_args, handle_work_conn_requests, log_exec_request, parse_ssh_args,
    ssh_gateway_usage, VirtualControl, PROXY_REGISTER_WAIT,
};

// ==============================================================
// SshSession — russh server::Handler impl
// ==============================================================

/// Per-connection SSH session handler.
///
/// Lifecycle:
/// 1. `auth_succeeded` → store handle, spawn work-connection background task
/// 2. `exec_request` → parse proxy args from SSH remote command
/// 3. `tcpip_forward` → accepted (Go semantics: no port bound, address
///    recorded); when a work connection is requested, the control handler
///    opens a `forwarded-tcpip` channel back to the SSH client
/// 4. When a work connection is needed, the control handler opens a
///    `forwarded-tcpip` channel back to the SSH client (the reverse tunnel).
pub struct SshSession {
    /// Unique run_id for this SSH client (used as FRP run_id).
    pub run_id: String,
    /// Proxy names registered by this session (for cleanup).
    pub registered_proxies: Vec<String>,
    /// Stored after auth_succeeded; retained for session lifecycle handling.
    /// (Reverse-forward channels are opened via `channel_open_forwarded_tcpip`
    /// when a work connection is requested.)
    pub ssh_handle: Option<russh::server::Handle>,
    /// V1 frame sender into the VirtualControl channel (→ control handler).
    pub(super) frame_tx: Option<mpsc::Sender<Vec<u8>>>,
    /// NewProxyResp receiver from the VirtualControl read task: exec_request
    /// waits up to PROXY_REGISTER_WAIT on it for the registration result of
    /// each NewProxy (Go frp's waitProxyStatusReady) and writes the
    /// outcome — success banner or error text — to the SSH client.
    proxy_resp_rx: Option<mpsc::Receiver<NewProxyResp>>,
    /// Server auth token for password authentication.
    server_token: String,
    /// Allowed public keys (loaded from authorized_keys file).
    authorized_keys: Vec<russh::keys::PublicKey>,
    /// Shared server state (proxy manager, used_ports, etc.).
    pub(super) state: std::sync::Arc<AppState>,
    /// Set to true by auth_succeeded.
    pub(super) authenticated: bool,
    pub(super) peer_addr: std::net::SocketAddr,
    auth_complete_tx: tokio::sync::watch::Sender<bool>,
    authenticated_run_id: Arc<std::sync::Mutex<Option<String>>>,
    pub(super) auth_deadline: tokio::time::Instant,
    /// `tcpip_forward` request payload (bind_addr, port). Go semantics: the
    /// address is recorded, not actually bound; it becomes the
    /// forwarded-tcpip channel payload.
    reverse_forward: Arc<std::sync::Mutex<Option<(String, u32)>>>,
    /// Data routing table for forwarded-tcpip channels: SSH client → bridge
    /// task read half. Sharded by ChannelId (DashMap), so the per-chunk
    /// `data` callback lock for one reverse channel never serializes against
    /// the other reverse channels of this session.
    reverse_data_tx: Arc<DashMap<russh::ChannelId, mpsc::Sender<Vec<u8>>>>,
    /// Cancelled when the virtual control handler exits (e.g. the server's
    /// heartbeat-timeout cleanup kills it — the SSH virtual client never
    /// sends Ping). The listener task and the work-conn bridge race on it so
    /// the whole SSH session is torn down deterministically instead of
    /// lingering with a dead control.
    control_exit: tokio_util::sync::CancellationToken,
}

impl Drop for SshSession {
    fn drop(&mut self) {
        tracing::debug!(run_id = %self.run_id, has_handle = %self.ssh_handle.is_some(), "SshSession {} dropped (has handle: {})", self.run_id, self.ssh_handle.is_some());
    }
}

impl SshSession {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        server_token: String,
        authorized_keys: Vec<russh::keys::PublicKey>,
        state: std::sync::Arc<AppState>,
        peer_addr: std::net::SocketAddr,
        auth_complete_tx: tokio::sync::watch::Sender<bool>,
        authenticated_run_id: Arc<std::sync::Mutex<Option<String>>>,
        auth_deadline: tokio::time::Instant,
        control_exit: tokio_util::sync::CancellationToken,
    ) -> Self {
        Self {
            run_id: String::new(),
            registered_proxies: Vec::new(),
            ssh_handle: None,
            frame_tx: None,
            proxy_resp_rx: None,
            server_token,
            authorized_keys,
            state,
            authenticated: false,
            peer_addr,
            auth_complete_tx,
            authenticated_run_id,
            auth_deadline,
            reverse_forward: Arc::new(std::sync::Mutex::new(None)),
            reverse_data_tx: Arc::new(DashMap::new()),
            control_exit,
        }
    }

    pub(super) fn begin_authentication(&mut self) -> bool {
        if self.authenticated || tokio::time::Instant::now() >= self.auth_deadline {
            return false;
        }
        self.authenticated = true;
        let _ = self.auth_complete_tx.send(true);
        true
    }
}

impl Handler for SshSession {
    type Error = anyhow::Error;

    // ── Authentication ──────────────────────────────────────

    async fn auth_password(&mut self, _user: &str, password: &str) -> Result<Auth, Self::Error> {
        // No token configured → disable password auth per spec. Intended
        // (round-13 audit note): on a pubkey-only gateway this path always
        // rejects with NO credential comparison, so it needs no pacing and
        // consumes no per-IP throttle slot — every attempt costs the
        // attacker a full auth round-trip with nothing evaluated, and the
        // per-IP pre-auth cap (SSH_PREAUTH_PER_IP_CAP) bounds the
        // concurrent attempts from one source regardless.
        if self.server_token.is_empty() {
            return Ok(Auth::Reject {
                proceed_with_methods: None,
                partial_success: false,
            });
        }
        // Per-IP throttle, fail-closed PRE-AUTH gate (round-12 audit A1):
        // an IP inside its throttle window is denied BEFORE the constant-
        // time compare, so no guess is evaluated during the window —
        // mirroring frp-server/src/control/login/throttle.rs:91 `is_login_throttled`. Round-11 ran the
        // deny only on the mismatch branch (after the compare): fail-open
        // meant an armed IP still got one full credential evaluation per
        // fresh connection (online guessing of the actual password was
        // never stopped — the correct password still accepted), and the
        // `Err` elided russh's `auth_rejection_time` reject pacing, making
        // the 6th+ guess FASTER than the pre-fix paced rejects. The
        // pre-gate restores the actual 5-per-60s rate limit: no compare,
        // no accept, no reject round-trip for a throttled IP.
        // The throttle is the same deliberate frp-rs hardening as the
        // login throttle (Go frp's SSH gateway has no password path at all
        // — pkg/ssh/gateway.go:74-76 NoClientAuth/PublicKeyCallback only).
        // NOTE (audit E1/S1e): this is the SAME table as the main-port
        // frpc login throttle — SSH password failures and failed frpc
        // logins share one per-IP budget. (Pubkey and "none" rejections do
        // NOT pass through this site: `auth_publickey` / `auth_none`
        // return Reject without calling `check_login_throttle`, so only
        // password failures consume slots.) Cross-surface collateral: 5
        // failed SSH passwords from a NAT IP arm that IP's main-port login
        // window too (and vice versa) — and the fail-closed SSH pre-gate
        // means a correct password from that IP is denied on BOTH surfaces
        // for the window (same property login.rs already has). The source
        // is TCP, not spoofable, so this arms no new attack. Only
        // PLAIN-KCP frpc logins are exempt from the table (spoofable UDP
        // source — state.rs scopes that exemption to the 4 non-TLS KCP
        // accept arms); KCP+TLS logins key the table like every TCP
        // surface, and a KCP+TLS frpc retry loop can arm this pre-gate.
        if self.state.is_login_throttled(Some(self.peer_addr)).await {
            tracing::warn!(
                ip = %self.peer_addr.ip(),
                "SSH gateway: denying password auth before credential check (60s throttle window)"
            );
            return Err(anyhow!(
                "ssh gateway: too many failed authentication attempts (60s window)"
            ));
        }
        if constant_time_eq(password.as_bytes(), self.server_token.as_bytes()) {
            Ok(Auth::Accept)
        } else {
            // Failure path: consume a throttle slot (only real failures
            // count). The Err arm below is reachable only through a race —
            // two in-flight sessions from the same IP both passed the
            // pre-gate at count 4 and this one arrives second at count 5 —
            // and returns Err (russh treats a handler error as fatal for
            // the session: the connection dies, no USERAUTH_FAILURE
            // round-trip) instead of handing out another guess.
            let allowed = self.state.check_login_throttle(self.peer_addr).await;
            if !allowed {
                tracing::warn!(
                    ip = %self.peer_addr.ip(),
                    "SSH gateway: rejecting session after 5 failed passwords (60s throttle window)"
                );
                return Err(anyhow!(
                    "ssh gateway: too many failed authentication attempts (60s window)"
                ));
            }
            Ok(Auth::Reject {
                proceed_with_methods: None,
                partial_success: false,
            })
        }
    }

    async fn auth_publickey(
        &mut self,
        _user: &str,
        public_key: &russh::keys::PublicKey,
    ) -> Result<Auth, Self::Error> {
        if self.authorized_keys.iter().any(|k| k == public_key) {
            tracing::debug!("SSH public key auth accepted");
            Ok(Auth::Accept)
        } else {
            tracing::debug!("SSH public key auth rejected, fall through to password");
            Ok(Auth::Reject {
                proceed_with_methods: Some(MethodSet::from(&[MethodKind::Password][..])),
                partial_success: false,
            })
        }
    }

    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        // Reject auth_none unless both authorized_keys AND server_token are
        // empty (no auth configured at all).  When a token is set the client
        // must authenticate via password; when keys are set it must
        // authenticate via publickey.  Accepting auth_none with a token
        // configured would let any SSH client bypass authentication
        // (OpenSSH always sends the "none" probe first).
        //
        // Go compat note: Go frp's gateway.go:74 does NoClientAuth when
        // authorizedKeysFile is empty *and* no password auth is configured.
        // Our equivalent: both fields empty.
        if self.authorized_keys.is_empty() && self.server_token.is_empty() {
            Ok(Auth::Accept)
        } else {
            Ok(Auth::Reject {
                proceed_with_methods: None,
                partial_success: false,
            })
        }
    }

    async fn auth_succeeded(&mut self, session: &mut Session) -> Result<(), Self::Error> {
        if !self.begin_authentication() {
            return Err(anyhow!("SSH authentication expired or already completed"));
        }
        self.run_id = uuid::Uuid::new_v4().to_string();
        self.ssh_handle = Some(session.handle());

        let enc_key = frp_core::encryption::derive_key(&self.server_token);
        let (vc, frame_tx, work_conn_rx, proxy_resp_rx, _phase2) = VirtualControl::channel(enc_key);
        self.frame_tx = Some(frame_tx);
        self.proxy_resp_rx = Some(proxy_resp_rx);

        let now_ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let login = frp_core::msg::Login {
            version: Some("0.69.1".into()),
            hostname: Some("ssh-gateway".into()),
            os: None,
            arch: None,
            user: Some("v0".into()),
            run_id: Some(self.run_id.clone()),
            client_id: None,
            pool_count: Some(1),
            timestamp: Some(now_ts),
            privilege_key: Some(frp_core::auth::generate_token(&self.server_token, now_ts)),
            metas: None,
            client_spec: Some(frp_core::msg::ClientSpec {
                client_type: None,
                always_auth_pass: Some(true),
            }),
            multiplexer: None,
        };
        let ctrl_state = self.state.clone();
        let peer_addr = self.peer_addr;
        let ctl_task = tokio::spawn(async move {
            crate::control::handle_control(
                vc,
                login,
                ctrl_state,
                Some(peer_addr),
                None,
                false,
                None,
                true,
            )
            .await;
        });
        // The SSH virtual client never sends Ping, so with an operator-set
        // transport.heartbeatTimeout the server's heartbeat cleanup kills
        // handle_control (and sweeps the SSH-registered proxies) while the
        // russh session would otherwise keep running — holding the SSH fd +
        // conn_semaphore permit and silently dropping every later -R
        // tcpip-forward work conn. Watch the control handler: when it exits
        // for any reason, cancel the session-wide token so the listener task
        // terminates the SSH session deterministically.
        let control_exit = self.control_exit.clone();
        tokio::spawn(async move {
            let _ = ctl_task.await;
            tracing::debug!(
                "SSH session: virtual control handler exited; requesting session termination"
            );
            control_exit.cancel();
        });

        *self
            .authenticated_run_id
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(self.run_id.clone());
        tracing::info!(run_id = %self.run_id, "SSH session {} authenticated", self.run_id);

        // Spawn the work-connection bridge: ReqWorkConn signals open a
        // forwarded-tcpip channel back to the SSH client and hand the
        // channel's pipe end to the control layer as a work conn.
        let run_id = self.run_id.clone();
        let ssh_handle = self.ssh_handle.clone().expect("ssh handle set after auth");
        let state = self.state.clone();
        let reverse_forward = self.reverse_forward.clone();
        let reverse_data_tx = self.reverse_data_tx.clone();
        let control_exit = self.control_exit.clone();
        tokio::spawn(async move {
            handle_work_conn_requests(
                work_conn_rx,
                run_id,
                ssh_handle,
                state,
                reverse_forward,
                reverse_data_tx,
                control_exit,
            )
            .await;
        });

        Ok(())
    }

    // ── Command execution ───────────────────────────────────

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let handle = session.handle();
        let run_id = self.run_id.clone();

        let cmd = match std::str::from_utf8(data) {
            Ok(cmd) => cmd.trim().to_string(),
            Err(e) => {
                // Go parity: client-visible failures are written to the SSH
                // client, then the connection closes (pkg/ssh/server.go
                // writeToClient + return). Returning Err here would drop the
                // text — see write_text_and_close.
                write_text_and_close(
                    &run_id,
                    &handle,
                    channel,
                    format!("exec command is not valid UTF-8: {e}"),
                )
                .await;
                return Ok(());
            }
        };

        if cmd.is_empty() {
            // Empty remote command: print the usage, then close. Divergence
            // (documented): Go v0.71.0 never parses an empty payload — its
            // addr+payload wait loop (server.go:230-256) breaks only when a
            // NON-empty extraPayload arrived, so a bare `ssh v0@host`
            // session stalls the full 3s window and dies with "get addr and
            // extra payload timeout" and no client text. frp-rs answers
            // instantly with the usage text (the same text Go writes for
            // --help/-h, the ErrHelp path). The trim above also sends
            // whitespace-only payloads here — Go would hand "   " to
            // strings.Split and reject it with the blank-type
            // `invalid proxy type: , support types: [...]` error
            // (server.go:267-277); parse_ssh_args reproduces that verbatim
            // for direct callers.
            write_text_and_close(&run_id, &handle, channel, ssh_gateway_usage()).await;
            return Ok(());
        }

        let args = match parse_ssh_args(&cmd) {
            Ok(args) => args,
            Err(e) => {
                tracing::warn!(
                    run_id = %run_id,
                    error = %e,
                    "SSH session {}: parse error: {}",
                    run_id,
                    e
                );
                // `e` is either the usage text (--help/-h) or the parse
                // error text (unknown flag, bad value, ...); Go writes
                // whichever it is and closes.
                write_text_and_close(&run_id, &handle, channel, e).await;
                return Ok(());
            }
        };
        log_exec_request(&run_id, &args);

        // Go parity gap, documented (FIX 2): Go consumes --user/--token/
        // --client-id when it builds the virtual client — server.go
        // parseClientAndConfigurer returns them in the client config, and
        // Run() hands that config to virtual.NewClient (server.go:104-130),
        // so they shape the frps LOGIN (user, privilege_key, client_id).
        // frp-rs establishes that Login in auth_succeeded — BEFORE the exec
        // payload is parsed — with user "v0", the gateway's own
        // server_token, and a fresh run_id; the CipherStream key derives
        // from server_token at VirtualControl::channel, so honoring
        // per-exec credentials would require re-establishing the whole
        // control connection (new Login + new derived key) mid-session.
        // The flags are therefore accepted and parsed (the Go surface stays
        // green — a Go-authored command line never fails on them) but do
        // not affect the registration; proxy-level auth keeps working via
        // the per-proxy flags (--sk/--http_user/...). --user would have no
        // effect anyway: Go overrides the flag with the SSH username
        // (server.go:117-119) after parsing.
        if !args.user.is_empty() || !args.token.is_empty() || !args.client_id.is_empty() {
            tracing::warn!(
                run_id = %run_id,
                "SSH gateway: --user/--token/--client-id accepted but unused (the control login predates the exec payload; Go consumes them at virtual-client login)"
            );
        }

        // Check per-client port limit (matching Go frp's GetUsedPortsNum logic).
        if self.state.max_ports_per_client > 0 {
            let used = self
                .state
                .client_ports_used
                .read()
                .await
                .get(&run_id)
                .copied()
                .unwrap_or(0);
            if used + 1 > self.state.max_ports_per_client {
                write_text_and_close(
                    &run_id,
                    &handle,
                    channel,
                    format!(
                        "maximum number of ports ({}) reached for this client",
                        self.state.max_ports_per_client
                    ),
                )
                .await;
                return Ok(());
            }
        }

        // Register the proxy: build NewProxy V1 frame, send to control handler.
        // Port allocation happens inside handle_new_proxy (single owner of
        // used_ports) — pre-allocating here would double-book the port.
        let v1_frame = match build_v1_frame_from_args(&args, args.remote_port) {
            Ok(frame) => frame,
            Err(e) => {
                write_text_and_close(&run_id, &handle, channel, e.to_string()).await;
                return Ok(());
            }
        };

        let Some(frame_tx) = self.frame_tx.as_ref() else {
            // exec cannot run before auth_succeeded in practice; treat this
            // as an internal breach and let the session die with an error.
            return Err(anyhow!("SSH session control is not initialized"));
        };
        if frame_tx.try_send(v1_frame).is_err() {
            // The virtual control handler exited (server-side cleanup); the
            // session is being torn down anyway — report, then close.
            write_text_and_close(
                &run_id,
                &handle,
                channel,
                "virtual control channel closed".to_string(),
            )
            .await;
            return Ok(());
        }

        let proxy_name = args.proxy_name.clone();
        let proxy_type = args.proxy_type.clone();

        // Wait for the registration result — Go parity (waitProxyStatusReady,
        // pkg/ssh/server.go): poll the proxy status for up to PROXY_REGISTER_WAIT
        // and report Running → createSuccessInfo banner, StartErr/Closed → the
        // server's error text verbatim, timeout → "wait proxy status ready
        // timeout". Responses for earlier execs (impossible with sequential
        // execs) are skipped against the same deadline.
        let deadline = tokio::time::Instant::now() + PROXY_REGISTER_WAIT;
        let resp_rx = self
            .proxy_resp_rx
            .as_mut()
            .ok_or_else(|| anyhow!("SSH session control is not initialized"))?;
        let resp = loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            let outcome = tokio::time::timeout(remaining, resp_rx.recv()).await;
            match outcome {
                Err(_elapsed) => {
                    write_text_and_close(
                        &run_id,
                        &handle,
                        channel,
                        "wait proxy status ready timeout".to_string(),
                    )
                    .await;
                    return Ok(());
                }
                Ok(None) => {
                    // Receiver dropped: the read task exited, so the control
                    // handler is gone — same teardown path as a closed
                    // frame_tx above.
                    write_text_and_close(
                        &run_id,
                        &handle,
                        channel,
                        "virtual control channel closed".to_string(),
                    )
                    .await;
                    return Ok(());
                }
                Ok(Some(resp)) if resp.proxy_name == proxy_name => break resp,
                // Stale response for an earlier exec — keep waiting on the
                // remaining budget.
                Ok(Some(_)) => {}
            }
        };

        if let Some(err_text) = resp.error {
            // Go parity: a failed registration reports the server's own
            // error text (NewProxyResp.error ≈ Go WorkingStatus.Err), then
            // closes. The proxy is NOT registered, so nothing is recorded.
            tracing::warn!(
                run_id = %run_id,
                proxy_name = %proxy_name,
                error = %err_text,
                "SSH gateway: proxy '{}' registration failed: {}",
                proxy_name,
                err_text
            );
            write_text_and_close(&run_id, &handle, channel, err_text).await;
            return Ok(());
        }

        // Success (Go createSuccessInfo, pkg/ssh/terminal.go): report the
        // registration and KEEP the session open — the tunnel serves until
        // the client disconnects (the banner's "Ctrl+C to quit").
        let remote_addr = resp.remote_addr.as_deref().unwrap_or("");
        let banner = format!(
            "\nfrp (via SSH) (Ctrl+C to quit)\n\nUser: v0\nProxyName: {}\nType: {}\nRemoteAddress: {}\n",
            resp.proxy_name, proxy_type, remote_addr
        );
        tracing::info!(
            proxy_name = %proxy_name,
            proxy_type = %proxy_type,
            remote_addr = %remote_addr,
            run_id = %run_id,
            "SSH gateway: registered proxy '{}' type={} remote_addr='{}' (run_id={})",
            proxy_name,
            proxy_type,
            remote_addr,
            run_id
        );
        self.registered_proxies.push(resp.proxy_name.clone());
        // Best-effort: a closed channel means the client is already gone;
        // the registered proxy is still cleaned up on session teardown.
        let _ = handle.data(channel, banner.into_bytes()).await;
        Ok(())
    }

    // ── Reverse forward (proxy registration) ────────────────

    async fn tcpip_forward(
        &mut self,
        address: &str,
        port: &mut u32,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        // Go semantics (pkg/ssh/server.go): accept and record the address;
        // no port is actually bound — it is used as the forwarded-tcpip
        // channel payload when a work connection is opened.
        tracing::info!(
            run_id = %self.run_id,
            address = %address,
            port = %*port,
            "SSH -R tcpip-forward requested for {}:{}",
            address,
            port
        );
        *self
            .reverse_forward
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some((address.to_string(), *port));
        Ok(true)
    }

    // ── Environment / PTY ────────────────────────────────────

    async fn env_request(
        &mut self,
        channel: ChannelId,
        _variable_name: &str,
        _variable_value: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.handle().channel_success(channel).await.ok();
        Ok(())
    }

    // ── Channels ─────────────────────────────────────────────

    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        // Accept session channels (needed for exec_request/shell_request)
        reply.accept().await;
        Ok(())
    }

    async fn channel_open_forwarded_tcpip(
        &mut self,
        _channel: Channel<Msg>,
        _host: &str,
        _port: u32,
        _origin: &str,
        _origin_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        // Server-opened reverse channels do not pass through this callback
        // (it only handles client-initiated forwarded-tcpip, a non-standard
        // pattern). Reject client-initiated ones.
        tracing::debug!(
            run_id = %self.run_id,
            "SSH gateway {}: rejecting client-initiated forwarded-tcpip channel",
            self.run_id
        );
        reply
            .reject(ChannelOpenFailure::AdministrativelyProhibited)
            .await;
        Ok(())
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        _channel: Channel<Msg>,
        _host: &str,
        _port: u32,
        _origin: &str,
        _origin_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        // Reject: no -L (local forward) support
        reply
            .reject(ChannelOpenFailure::AdministrativelyProhibited)
            .await;
        Ok(())
    }

    // ── Data (bridged by control handler) ───────────────────

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        // Forwarded-tcpip channel data is routed to the bridge task's read
        // half (data from the SSH client = local service response). The
        // bounded channel provides backpressure when the frps side reads
        // slower than the SSH client sends (Go net.Pipe is blocking too).
        // Clone the sender under the shard lock, then await the send outside
        // it so the future stays Send. The map is sharded per ChannelId
        // (DashMap), so concurrent reverse channels do not serialize their
        // data callback on a single mutex.
        let tx = self
            .reverse_data_tx
            .get(&channel)
            .map(|e| e.value().clone());
        if let Some(tx) = tx {
            if tx.send(data.to_vec()).await.is_err() {
                // Bridge task exited (channel closed) — drop the entry.
                self.reverse_data_tx.remove(&channel);
            }
        }
        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        // The peer closed the forwarded-tcpip channel (local service exited).
        // Drop the data sender so the bridge task's `data_rx.recv()` returns
        // and the task (plus its duplex) exits — otherwise the bridge hangs
        // forever holding the channel entry in the map.
        if self.reverse_data_tx.remove(&channel).is_some() {
            tracing::debug!(
                run_id = %self.run_id,
                channel = ?channel,
                "SSH gateway: forwarded-tcpip channel closed, bridge task will exit"
            );
        }
        Ok(())
    }
}

/// Write `text` to the exec channel, then disconnect the SSH session.
/// Mirrors Go frp's writeToClient + close: parse errors, help text, and
/// proxy-register failures reach the client exactly once, then the
/// connection ends.
///
/// russh contract: exec_request must return Ok(()) afterwards — returning
/// Err aborts the session run loop BEFORE the queued `data` message is
/// flushed to the socket, silently dropping the text. `data()` and
/// `disconnect()` go through the same Handle's FIFO sender, so the text is
/// always written ahead of the DISCONNECT.
async fn write_text_and_close(
    run_id: &str,
    handle: &russh::server::Handle,
    channel: ChannelId,
    text: String,
) {
    tracing::debug!(
        run_id = %run_id,
        bytes = text.len(),
        "SSH gateway: writing {} bytes to client, then disconnecting",
        text.len()
    );
    // Both sends are best-effort: the session may already be closing, and a
    // stuck channel must not wedge the exec handler.
    let _ = handle.data(channel, text.into_bytes()).await;
    let _ = handle
        .disconnect(
            russh::Disconnect::ByApplication,
            "ssh tunnel gateway: done".to_string(),
            "en".to_string(),
        )
        .await;
}
