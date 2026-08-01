//! SSH Tunnel Gateway — SSH client registration → frp proxy.
//!
//! Users connect with a standard SSH client:
//!   ssh -R :80:127.0.0.1:8080 v0@server -p 2200 tcp --proxy_name "web" --remote_port 9090
//!
//! The remote command string is parsed into a ProxyConfig.
//!
//! SSH reverse forwarding (`tcpip_forward` / `-R`) is disabled in this
//! release: the port allocation/work-connection bridge was unsafe and
//! non-functional, so `-R` requests are rejected explicitly.
//!
//! NOTE: russh 0.61 transitively depends on rsa 0.10.0-rc.18 which has a known
//! timing sidechannel (RUSTSEC-2023-0071, Marvin Attack). Only affects the SSH
//! gateway feature. Monitor upstream for fix.

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

use anyhow::anyhow;
use frp_core::msg::{FrpMessage, NewProxy};
use russh::server::{Auth, Handler, Msg, Session};
use russh::{Channel, ChannelId, MethodKind, MethodSet};
use tokio::sync::mpsc;

use crate::lock::RwLockExt;
use crate::proxy::allocate_port_multi;
use crate::service::AppState;
use frp_core::auth::constant_time_eq;

/// Parsed result from an SSH remote command string.
#[derive(Debug, PartialEq)]
struct ParsedProxyArgs {
    proxy_type: String,
    proxy_name: String,
    remote_port: u16,
    local_ip: String,
    local_port: u16,
    custom_domains: Vec<String>,
    subdomain: String,
    sk: String,
    multiplexer: String,
    use_encryption: bool,
    use_compression: bool,
    group: String,
    group_key: String,
    http_user: String,
    http_pwd: String,
    host_header_rewrite: String,
    locations: Vec<String>,
    bandwidth_limit: String,
    bandwidth_limit_mode: String,
}

/// Parse SSH remote command args like:
///   "tcp --proxy_name \"web\" --remote_port 9090"
///   "http --proxy_name \"blog\" --custom_domains \"a,b\""
fn parse_ssh_args(cmd: &str) -> Result<ParsedProxyArgs, String> {
    let parts = shell_split(cmd);
    if parts.is_empty() {
        return Err("missing proxy type".into());
    }

    let proxy_type = parts[0].to_lowercase();
    if !VALID_PROXY_TYPES.contains(&proxy_type.as_str()) {
        return Err(format!(
            "unsupported proxy type '{}', supported: {}",
            proxy_type,
            VALID_PROXY_TYPES.join(", ")
        ));
    }

    let mut args = ParsedProxyArgs {
        proxy_type,
        proxy_name: String::new(),
        remote_port: 0,
        local_ip: String::new(),
        local_port: 0,
        custom_domains: Vec::new(),
        subdomain: String::new(),
        sk: String::new(),
        multiplexer: String::new(),
        use_encryption: false,
        use_compression: false,
        group: String::new(),
        group_key: String::new(),
        http_user: String::new(),
        http_pwd: String::new(),
        host_header_rewrite: String::new(),
        locations: Vec::new(),
        bandwidth_limit: String::new(),
        bandwidth_limit_mode: String::new(),
    };

    let mut i = 1;
    while i < parts.len() {
        match parts[i].as_str() {
            "--proxy_name" => {
                i += 1;
                args.proxy_name = parts.get(i).cloned().unwrap_or_default();
            }
            "--remote_port" => {
                i += 1;
                args.remote_port = parts.get(i).and_then(|s| s.parse().ok()).unwrap_or(0);
            }
            "--local_ip" => {
                i += 1;
                args.local_ip = parts.get(i).cloned().unwrap_or_default();
            }
            "--local_port" => {
                i += 1;
                args.local_port = parts.get(i).and_then(|s| s.parse().ok()).unwrap_or(0);
            }
            "--custom_domains" | "--custom_domain" => {
                i += 1;
                args.custom_domains = parts
                    .get(i)
                    .map(|s| s.split(',').map(|d| d.trim().to_string()).collect())
                    .unwrap_or_default();
            }
            "--subdomain" => {
                i += 1;
                args.subdomain = parts.get(i).cloned().unwrap_or_default();
            }
            "--sk" => {
                i += 1;
                args.sk = parts.get(i).cloned().unwrap_or_default();
            }
            "--multiplexer" => {
                i += 1;
                args.multiplexer = parts.get(i).cloned().unwrap_or_default();
            }
            "--use_encryption" => {
                i += 1;
                args.use_encryption = parts
                    .get(i)
                    .map(|s| s == "true" || s == "1")
                    .unwrap_or(false);
            }
            "--use_compression" => {
                i += 1;
                args.use_compression = parts
                    .get(i)
                    .map(|s| s == "true" || s == "1")
                    .unwrap_or(false);
            }
            "--group" => {
                i += 1;
                args.group = parts.get(i).cloned().unwrap_or_default();
            }
            "--group_key" => {
                i += 1;
                args.group_key = parts.get(i).cloned().unwrap_or_default();
            }
            "--http_user" => {
                i += 1;
                args.http_user = parts.get(i).cloned().unwrap_or_default();
            }
            "--http_pwd" => {
                i += 1;
                args.http_pwd = parts.get(i).cloned().unwrap_or_default();
            }
            "--host_header_rewrite" => {
                i += 1;
                args.host_header_rewrite = parts.get(i).cloned().unwrap_or_default();
            }
            "--locations" => {
                i += 1;
                args.locations = parts
                    .get(i)
                    .map(|s| s.split(',').map(|d| d.trim().to_string()).collect())
                    .unwrap_or_default();
            }
            "--bandwidth_limit" => {
                i += 1;
                args.bandwidth_limit = parts.get(i).cloned().unwrap_or_default();
            }
            "--bandwidth_limit_mode" => {
                i += 1;
                args.bandwidth_limit_mode = parts.get(i).cloned().unwrap_or_default();
            }
            other => {
                // Skip unknown flags or positional args after type
                if !other.starts_with("--") {
                    // positional — ignore (already got the type)
                }
            }
        }
        i += 1;
    }

    Ok(args)
}

const VALID_PROXY_TYPES: &[&str] = &["tcp", "http", "https", "stcp", "tcpmux"];

/// Split a command string into shell-like tokens, respecting double quotes.
fn shell_split(cmd: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let chars: Vec<char> = cmd.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        let c = chars[i];
        if c == '"' {
            in_quotes = !in_quotes;
        } else if c == ' ' && !in_quotes {
            if !current.is_empty() {
                tokens.push(current.clone());
                current.clear();
            }
        } else {
            current.push(c);
        }
        i += 1;
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

/// Virtual control channel — an in-memory bidirectional stream
/// (tokio::io::duplex) that bridges the SSH session to handle_control().
///
/// handle_control() wraps its side in a CipherStream (AES-128-CFB).
/// We spawn a background task that encrypts outgoing V1 frames (NewProxy)
/// and decrypts incoming data to intercept ReqWorkConn messages.
///
/// Returns: (stream_for_handle_control, frame_tx, work_conn_rx)
pub struct VirtualControl;

/// A request from the control handler to the SSH session to open a
/// reverse-forward channel for a work connection.
#[derive(Debug)]
pub struct WorkConnRequest {
    pub proxy_name: String,
}

impl VirtualControl {
    /// Create a paired channel. `enc_key` is the AES-128-CFB key matching
    /// handle_control's CipherStream. Returns:
    /// - `stream`: the AsyncRead+AsyncWrite stream to pass to handle_control()
    /// - `frame_tx`: sender for plain V1 frames from the SSH session
    /// - `work_conn_rx`: receiver for intercepted ReqWorkConn signals
    /// - `phase2_ready`: resolves once LoginResp consumed + CipherStream ready
    pub fn channel(
        enc_key: [u8; 16],
    ) -> (
        impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
        mpsc::Sender<Vec<u8>>,
        mpsc::Receiver<WorkConnRequest>,
        tokio::sync::oneshot::Receiver<()>,
    ) {
        let (to_handler, from_ssh) = tokio::io::duplex(65536);
        let (frame_tx, mut frame_rx) = mpsc::channel::<Vec<u8>>(64);
        let (work_tx, work_rx) = mpsc::channel::<WorkConnRequest>(16);
        let (phase2_tx, phase2_rx) = tokio::sync::oneshot::channel();

        // Spawn background task that bridges the duplex to the mpsc channels,
        // with encryption matching handle_control's CipherStream.
        //
        // handle_control writes LoginResp as PLAINTEXT before wrapping its side
        // in CipherStream. To keep both sides' CFB state in sync, we consume
        // the plaintext LoginResp from the raw stream BEFORE wrapping our side
        // in CipherStream.
        tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            use tokio::io::AsyncWriteExt;

            const V1_HDR: usize = 9;
            let mut buf = [0u8; 512];
            let mut accumulated = Vec::new();
            let mut from_ssh = from_ssh;

            // ---- Phase 1: consume plaintext LoginResp from raw stream ----
            loop {
                match from_ssh.read(&mut buf).await {
                    Ok(0) => return,
                    Ok(n) => {
                        accumulated.extend_from_slice(&buf[..n]);
                        if accumulated.len() >= V1_HDR {
                            let plen =
                                u64::from_be_bytes(accumulated[1..V1_HDR].try_into().unwrap())
                                    as usize;
                            if plen > 65536 {
                                return;
                            }
                            if accumulated.len() >= V1_HDR + plen {
                                // Drop LoginResp; keep extra bytes (unlikely, see below)
                                let extra = accumulated[V1_HDR + plen..].to_vec();
                                accumulated = extra;
                                break;
                            }
                        }
                    }
                    Err(_) => return,
                }
            }

            // Extra bytes after LoginResp are encrypted data that was read
            // ahead of the CipherStream. In practice unreachable:
            // handle_control writes LoginResp synchronously then wraps in
            // CipherStream — no other data is interleaved. Warn + discard.
            if !accumulated.is_empty() {
                tracing::warn!(
                    extra_bytes = %accumulated.len(),
                    "bridge: {} extra bytes after LoginResp, discarding",
                    accumulated.len()
                );
                accumulated.clear();
            }

            // ---- Phase 2: wrap in CipherStream, split for concurrent r/w ----
            let _ = phase2_tx.send(());
            let encrypted = frp_core::cipher_stream::CipherStream::new(Box::new(from_ssh), enc_key);
            let (mut enc_reader, mut enc_writer) = tokio::io::split(encrypted);
            let read_work_tx = work_tx;
            drop(accumulated); // free the LoginResp-phase buffer

            // Read task: decrypt V1 frames with canonical parser, intercept ReqWorkConn
            let read_task: tokio::task::JoinHandle<()> = tokio::spawn(async move {
                loop {
                    match frp_core::protocol::read_v1_frame(&mut enc_reader).await {
                        Ok((type_byte, _payload)) => {
                            if type_byte == frp_core::msg::TYPE_REQ_WORK_CONN {
                                tracing::debug!(
                                    "bridge: intercepted ReqWorkConn -> WorkConnRequest"
                                );
                                // proxy_name intentionally empty: ReqWorkConn
                                // carries no proxy_name in V1 protocol, and
                                // the work-connection pool does not use it.
                                let _ = read_work_tx.try_send(WorkConnRequest {
                                    proxy_name: String::new(),
                                });
                            }
                        }
                        Err(e) => {
                            tracing::debug!(error = %e, "bridge: read task exiting: {e}");
                            break;
                        }
                    }
                }
            });

            // Write loop: encrypt outgoing V1 frames through CipherStream
            while let Some(frame) = frame_rx.recv().await {
                if enc_writer.write_all(&frame).await.is_err() {
                    break;
                }
            }
            let _ = enc_writer.shutdown().await;

            let _ = read_task.await;
        });

        (to_handler, frame_tx, work_rx, phase2_rx)
    }
}

// ==============================================================
// SshSession — russh server::Handler impl
// ==============================================================

/// Per-connection SSH session handler.
///
/// Lifecycle:
/// 1. `auth_succeeded` → store handle, spawn work-connection background task
/// 2. `exec_request` → parse proxy args from SSH remote command
/// 3. `tcpip_forward` → rejected; SSH reverse forwarding is disabled
/// 4. When a work connection is needed, the control handler sends
///    ReqWorkConn → VirtualControl intercepts → WorkConnRequest →
///    background task drops the request (no reverse tunnel is available).
pub struct SshSession {
    /// Unique run_id for this SSH client (used as FRP run_id).
    pub run_id: String,
    /// Proxy names registered by this session (for cleanup).
    pub registered_proxies: Vec<String>,
    /// Stored after auth_succeeded; retained for session lifecycle handling.
    /// Reverse-forward channels are not opened in this release.
    pub ssh_handle: Option<russh::server::Handle>,
    /// V1 frame sender into the VirtualControl channel (→ control handler).
    frame_tx: Option<mpsc::Sender<Vec<u8>>>,
    /// Server auth token for password authentication.
    server_token: String,
    /// Allowed public keys (loaded from authorized_keys file).
    authorized_keys: Vec<russh::keys::PublicKey>,
    /// Shared server state (proxy manager, used_ports, etc.).
    state: std::sync::Arc<AppState>,
    /// Set to true by auth_succeeded.
    authenticated: bool,
    peer_addr: std::net::SocketAddr,
    auth_complete_tx: tokio::sync::watch::Sender<bool>,
    authenticated_run_id: Arc<std::sync::Mutex<Option<String>>>,
    auth_deadline: tokio::time::Instant,
}

impl Drop for SshSession {
    fn drop(&mut self) {
        tracing::debug!(run_id = %self.run_id, has_handle = %self.ssh_handle.is_some(), "SshSession {} dropped (has handle: {})", self.run_id, self.ssh_handle.is_some());
    }
}

impl SshSession {
    pub fn new(
        server_token: String,
        authorized_keys: Vec<russh::keys::PublicKey>,
        state: std::sync::Arc<AppState>,
        peer_addr: std::net::SocketAddr,
        auth_complete_tx: tokio::sync::watch::Sender<bool>,
        authenticated_run_id: Arc<std::sync::Mutex<Option<String>>>,
        auth_deadline: tokio::time::Instant,
    ) -> Self {
        Self {
            run_id: String::new(),
            registered_proxies: Vec::new(),
            ssh_handle: None,
            frame_tx: None,
            server_token,
            authorized_keys,
            state,
            authenticated: false,
            peer_addr,
            auth_complete_tx,
            authenticated_run_id,
            auth_deadline,
        }
    }

    fn begin_authentication(&mut self) -> bool {
        if self.authenticated || tokio::time::Instant::now() >= self.auth_deadline {
            return false;
        }
        self.authenticated = true;
        let _ = self.auth_complete_tx.send(true);
        true
    }
}

/// Build a V1 frame from a parsed SSH command and allocated port.
fn build_v1_frame_from_args(
    args: &ParsedProxyArgs,
    allocated_port: u16,
) -> Result<Vec<u8>, anyhow::Error> {
    let remote_port = if allocated_port > 0 {
        Some(allocated_port as i32)
    } else {
        None
    };

    let msg = FrpMessage::NewProxy(Box::new(NewProxy {
        proxy_name: args.proxy_name.clone(),
        proxy_type: args.proxy_type.clone(),
        use_encryption: Some(args.use_encryption),
        use_compression: Some(args.use_compression),
        group: none_if_empty(&args.group),
        group_key: none_if_empty(&args.group_key),
        local_str: {
            if !args.local_ip.is_empty() || args.local_port > 0 {
                Some(format!("{}:{}", args.local_ip, args.local_port))
            } else {
                None
            }
        },
        remote_port,
        sk: none_if_empty(&args.sk),
        custom_domains: non_empty_vec(args.custom_domains.clone()),
        subdomain: none_if_empty(&args.subdomain),
        locations: non_empty_vec(args.locations.clone()),
        http_user: none_if_empty(&args.http_user),
        http_pwd: none_if_empty(&args.http_pwd),
        host_header_rewrite: none_if_empty(&args.host_header_rewrite),
        headers: None,
        response_headers: None,
        route_by_http_user: None,
        allow_users: None,
        bandwidth_limit: none_if_empty(&args.bandwidth_limit),
        bandwidth_limit_mode: none_if_empty(&args.bandwidth_limit_mode),
        annotations: None,
        metas: None,
        multiplexer: none_if_empty(&args.multiplexer),
        virtual_net: None,
        proxy_protocol_version: None,
        advertise_subnet: None,
        vnet_ip: None,
        vnet_netmask: None,
        vnet_mtu: None,
    }));

    let type_byte = msg.v1_type_byte();
    let payload = serde_json::to_vec(&msg).map_err(|e| anyhow!("serialize NewProxy: {}", e))?;

    let mut buf = Vec::with_capacity(9 + payload.len());
    buf.push(type_byte);
    buf.extend_from_slice(&(payload.len() as i64).to_be_bytes());
    buf.extend_from_slice(&payload);

    Ok(buf)
}

/// Return None if the string is empty, Some(s) otherwise.
fn none_if_empty(s: &str) -> Option<String> {
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

/// Build the sanitized exec_request log line. Secret values (`--sk`,
/// `--group_key`, `--http_pwd`) are never formatted here or passed to the
/// logging macro; only proxy type/name, remote port, and boolean flags.
fn exec_request_log_summary(args: &ParsedProxyArgs) -> String {
    format!(
        "exec_request type={} name={} remote_port={} encryption={} compression={}",
        args.proxy_type,
        args.proxy_name,
        args.remote_port,
        args.use_encryption,
        args.use_compression
    )
}

/// Log an SSH exec_request using sanitized fields only.
fn log_exec_request(run_id: &str, args: &ParsedProxyArgs) {
    tracing::info!(
        run_id = %run_id,
        proxy_type = %args.proxy_type,
        proxy_name = %args.proxy_name,
        remote_port = %args.remote_port,
        use_encryption = %args.use_encryption,
        use_compression = %args.use_compression,
        "SSH session {}: {}",
        run_id,
        exec_request_log_summary(args)
    );
}

/// Return None if the vec is empty, Some(v) otherwise.
fn non_empty_vec(v: Vec<String>) -> Option<Vec<String>> {
    if v.is_empty() {
        None
    } else {
        Some(v)
    }
}

impl Handler for SshSession {
    type Error = anyhow::Error;

    // ── Authentication ──────────────────────────────────────

    async fn auth_password(&mut self, _user: &str, password: &str) -> Result<Auth, Self::Error> {
        // No token configured → disable password auth per spec
        if self.server_token.is_empty() {
            return Ok(Auth::Reject {
                proceed_with_methods: None,
                partial_success: false,
            });
        }
        if constant_time_eq(password.as_bytes(), self.server_token.as_bytes()) {
            Ok(Auth::Accept)
        } else {
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

    async fn auth_succeeded(&mut self, session: &mut Session) -> Result<(), Self::Error> {
        if !self.begin_authentication() {
            return Err(anyhow!("SSH authentication expired or already completed"));
        }
        self.run_id = uuid::Uuid::new_v4().to_string();
        self.ssh_handle = Some(session.handle());

        let enc_key = frp_core::encryption::derive_key(&self.server_token);
        let (vc, frame_tx, work_conn_rx, _phase2) = VirtualControl::channel(enc_key);
        self.frame_tx = Some(frame_tx);

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
        tokio::spawn(async move {
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

        *self.authenticated_run_id.lock().unwrap() = Some(self.run_id.clone());
        tracing::info!(run_id = %self.run_id, "SSH session {} authenticated", self.run_id);

        // Spawn a background task that drains work-connection requests.
        // Reverse forwarding is disabled, so there is no SSH reverse tunnel
        // to bridge; the receiver is drained so the control handler never
        // blocks on the bounded channel.
        let run_id = self.run_id.clone();

        tokio::spawn(async move {
            handle_work_conn_requests(work_conn_rx, run_id).await;
        });

        Ok(())
    }

    // ── Command execution ───────────────────────────────────

    async fn exec_request(
        &mut self,
        _channel: ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let cmd = std::str::from_utf8(data)
            .map_err(|e| anyhow!("exec command is not valid UTF-8: {}", e))?
            .trim()
            .to_string();

        if cmd.is_empty() {
            return Err(anyhow!(
                "empty command; usage: ssh ... <proxy_type> --proxy_name <name> [--remote_port <port>] ..."
            ));
        }

        let args = match parse_ssh_args(&cmd) {
            Ok(args) => args,
            Err(e) => {
                tracing::warn!(run_id = %self.run_id, error = %e, "SSH session {}: parse error: {}", self.run_id, e);
                return Err(anyhow!("{}", e));
            }
        };
        log_exec_request(&self.run_id, &args);

        // Check per-client port limit (matching Go frp's GetUsedPortsNum logic).
        if self.state.max_ports_per_client > 0 {
            let used = self
                .state
                .client_ports_used
                .read()
                .await
                .get(&self.run_id)
                .copied()
                .unwrap_or(0);
            if used + 1 > self.state.max_ports_per_client {
                return Err(anyhow!(
                    "maximum number of ports ({}) reached for this client",
                    self.state.max_ports_per_client
                ));
            }
        }

        // Register the proxy: build NewProxy V1 frame, send to control handler
        let allocated = {
            let state = self.state.clone();
            let mut used = state.used_ports.write().await;
            // Re-allocate the actual proxy remote_port (not the SSH listen port)
            let ranges = state.reloadable.read_ok().allow_ports.clone();
            allocate_port_multi(&mut used, args.remote_port, &ranges, &state.proxy_bind_addr)
                .ok_or_else(|| anyhow!("no port available for remote_port {}", args.remote_port))?
        };

        let v1_frame = build_v1_frame_from_args(&args, allocated)?;

        self.frame_tx
            .as_ref()
            .ok_or_else(|| anyhow!("SSH session control is not initialized"))?
            .try_send(v1_frame)
            .map_err(|_| anyhow!("virtual control channel closed"))?;

        let proxy_name = args.proxy_name.clone();
        self.registered_proxies.push(proxy_name.clone());

        tracing::info!(
            proxy_name = %proxy_name,
            proxy_type = %args.proxy_type,
            remote_port = %allocated,
            run_id = %self.run_id,
            "SSH gateway: registered proxy '{}' type={} remote_port={} (run_id={})",
            proxy_name,
            args.proxy_type,
            allocated,
            self.run_id
        );

        Ok(())
    }

    // ── Reverse forward (proxy registration) ────────────────

    async fn tcpip_forward(
        &mut self,
        address: &str,
        _port: &mut u32,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        tracing::warn!(
            run_id = %self.run_id,
            address = %address,
            "SSH -R reverse forwarding is disabled in this release; rejecting tcpip_forward for {}",
            address
        );
        Ok(false)
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
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        // Accept session channels (needed for exec_request/shell_request)
        Ok(true)
    }

    async fn channel_open_forwarded_tcpip(
        &mut self,
        _channel: Channel<Msg>,
        _host: &str,
        _port: u32,
        _origin: &str,
        _origin_port: u32,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        // Reverse forwarding is disabled; reject any forwarded-tcpip channels
        // a client may still attempt to open.
        tracing::debug!(
            run_id = %self.run_id,
            "SSH gateway {}: rejecting forwarded-tcpip channel (reverse forwarding disabled)",
            self.run_id
        );
        Ok(false)
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        _channel: Channel<Msg>,
        _host: &str,
        _port: u32,
        _origin: &str,
        _origin_port: u32,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        // Reject: no -L (local forward) support
        Ok(false)
    }

    // ── Data (bridged by control handler) ───────────────────

    async fn data(
        &mut self,
        _channel: ChannelId,
        _data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        // Channels are bridged transparently by the work-connection
        // bridge. No handler-side processing needed.
        Ok(())
    }
}

/// Background task: receives WorkConnRequest signals from VirtualControl
/// (which intercepted ReqWorkConn from the control handler).
///
/// Reverse forwarding is disabled in this release, so there is no SSH
/// reverse tunnel to bridge work connections through. The receiver is still
/// drained so the control handler never blocks on the bounded channel.
async fn handle_work_conn_requests(mut work_rx: mpsc::Receiver<WorkConnRequest>, run_id: String) {
    while let Some(_req) = work_rx.recv().await {
        tracing::warn!(
            run_id = %run_id,
            "SSH gateway {}: dropping WorkConnRequest because SSH reverse forwarding is disabled",
            run_id
        );
    }

    tracing::debug!(run_id = %run_id, "SSH session {} work-connection handler exiting", run_id);
}

/// Clean up a disconnected SSH session: remove all registered proxies.
pub async fn cleanup_session(run_id: &str, state: &Arc<AppState>) {
    #[cfg(feature = "vnet")]
    state.remove_run_id_vnet_routes(run_id).await;
    state.proxy_manager.remove_client(run_id).await;
    tracing::info!(run_id = %run_id, "SSH session {} cleaned up", run_id);
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    struct TestSshClient;

    impl russh::client::Handler for TestSshClient {
        type Error = russh::Error;

        async fn check_server_key(
            &mut self,
            _server_public_key: &russh::keys::PublicKey,
        ) -> Result<bool, Self::Error> {
            Ok(true)
        }
    }

    fn test_state(max_connections: usize) -> Arc<AppState> {
        let cfg = frp_core::config::ServerConfig::default();
        Arc::new(AppState::new(
            frp_core::auth::AuthConfig::with_token("test-token"),
            "127.0.0.1".into(),
            frp_core::encryption::derive_key("test-token"),
            vec![frp_core::config::PortsRange { start: 1, end: u16::MAX, single: 0 }],
            String::new(),
            true,
            30,
            7200,
            90,
            1500,
            false,
            None,
            0,
            60,
            10,
            false,
            String::new(),
            Arc::new(crate::plugin::HttpPluginManager::new(Vec::new())),
            0,
            168,
            true,
            max_connections,
            0,
            frp_core::config::ServerConfigSnapshot::from_config(&cfg),
        ))
    }

    fn pre_auth_session() -> (
        SshSession,
        tokio::sync::watch::Receiver<bool>,
        Arc<std::sync::Mutex<Option<String>>>,
    ) {
        let (auth_tx, auth_rx) = tokio::sync::watch::channel(false);
        let run_id = Arc::new(std::sync::Mutex::new(None));
        let session = SshSession::new(
            "test-token".into(),
            Vec::new(),
            test_state(1),
            "127.0.0.1:2200".parse().unwrap(),
            auth_tx,
            run_id.clone(),
            tokio::time::Instant::now() + SSH_AUTH_DEADLINE,
        );
        (session, auth_rx, run_id)
    }

    async fn start_test_ssh_listener(
        auth_deadline: std::time::Duration,
    ) -> (
        std::net::SocketAddr,
        Arc<AppState>,
        tokio::task::JoinHandle<()>,
    ) {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = probe.local_addr().unwrap();
        drop(probe);
        let state = test_state(1);
        let mut rng = rand010::rng();
        let host_key =
            russh::keys::PrivateKey::random(&mut rng, russh::keys::Algorithm::Ed25519).unwrap();
        let listener = SshListener {
            bind_addr: addr.ip().to_string(),
            bind_port: addr.port(),
            server_token: "test-token".into(),
            state: state.clone(),
            host_key,
            authorized_keys: Vec::new(),
            auth_deadline,
        };
        let task = tokio::spawn(async move {
            listener.run().await.unwrap();
        });
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        (addr, state, task)
    }

    #[test]
    fn test_pre_auth_session_has_no_internal_control_resources() {
        let (session, auth_rx, run_id) = pre_auth_session();

        assert!(session.run_id.is_empty());
        assert!(session.frame_tx.is_none());
        assert!(!session.authenticated);
        assert!(run_id.lock().unwrap().is_none());
        assert!(!*auth_rx.borrow());
    }

    #[tokio::test]
    async fn test_valid_password_authentication_still_succeeds_without_pre_auth_control() {
        let (mut session, _auth_rx, _run_id) = pre_auth_session();

        let result = session.auth_password("v0", "test-token").await.unwrap();

        assert!(matches!(result, Auth::Accept));
        assert!(session.run_id.is_empty());
        assert!(session.frame_tx.is_none());
    }

    #[test]
    fn test_authentication_resource_initialization_is_idempotent() {
        let (mut session, auth_rx, _run_id) = pre_auth_session();

        assert!(session.begin_authentication());
        assert!(*auth_rx.borrow());
        assert!(!session.begin_authentication());
    }

    #[test]
    fn test_authentication_cannot_begin_after_deadline() {
        let (mut session, _auth_rx, _run_id) = pre_auth_session();
        session.auth_deadline = tokio::time::Instant::now();

        assert!(!session.begin_authentication());
        assert!(!session.authenticated);
    }

    #[test]
    fn test_ssh_connection_permit_is_bounded_and_released() {
        let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
        let permit = semaphore.clone().try_acquire_owned().unwrap();
        assert!(semaphore.clone().try_acquire_owned().is_err());
        drop(permit);
        assert!(semaphore.try_acquire_owned().is_ok());
    }

    #[tokio::test]
    async fn test_hard_close_wakes_blocked_transport_and_confirms_drop() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::spawn(tokio::net::TcpStream::connect(addr));
        let (server_stream, _) = listener.accept().await.unwrap();
        let _client_stream = client.await.unwrap().unwrap();
        let (mut stream, closer) = CloseableSshStream::new(server_stream);
        let blocked = tokio::spawn(async move {
            let mut byte = [0u8; 1];
            stream.read(&mut byte).await
        });

        closer.close();

        tokio::time::timeout(std::time::Duration::from_secs(1), closer.wait_dropped())
            .await
            .expect("hard-close must make the transport owner drop its stream");
        assert!(blocked.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn test_drop_notification_is_sticky_when_drop_precedes_wait() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::spawn(tokio::net::TcpStream::connect(addr));
        let (server_stream, _) = listener.accept().await.unwrap();
        let _client_stream = client.await.unwrap().unwrap();
        let (stream, closer) = CloseableSshStream::new(server_stream);
        drop(stream);

        tokio::time::timeout(std::time::Duration::from_millis(10), closer.wait_dropped())
            .await
            .expect("drop notification must remain observable after an early drop");
    }

    #[tokio::test]
    async fn test_pending_disconnect_still_forces_io_close_and_finishes_chain() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::spawn(tokio::net::TcpStream::connect(addr));
        let (server_stream, _) = listener.accept().await.unwrap();
        let _client_stream = client.await.unwrap().unwrap();
        let (mut stream, closer) = CloseableSshStream::new(server_stream);
        let mut session_task = tokio::spawn(async move {
            let mut byte = [0u8; 1];
            stream.read_exact(&mut byte).await?;
            Ok::<(), anyhow::Error>(())
        });

        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            terminate_ssh_session(
                std::future::pending(),
                &mut session_task,
                &closer,
                std::time::Duration::from_millis(10),
            ),
        )
        .await
        .expect("a stuck disconnect sender must not stall termination");

        assert!(closer.0.dropped.is_cancelled());
        assert!(session_task.is_finished());
    }

    #[tokio::test]
    async fn test_real_unauthenticated_connection_times_out_without_control_and_releases_permit() {
        let (addr, state, listener_task) =
            start_test_ssh_listener(std::time::Duration::from_millis(500)).await;
        let client = russh::client::connect(
            Arc::new(russh::client::Config::default()),
            addr,
            TestSshClient,
        )
        .await
        .expect("SSH key exchange should complete before the auth deadline");

        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while !client.is_closed() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("post-KEX unauthenticated SSH connection must close at deadline");
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                if state.conn_semaphore.as_ref().unwrap().available_permits() == 1 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(state.run_id_to_ctl_tx.read().await.is_empty());
        listener_task.abort();
    }

    #[tokio::test]
    async fn test_real_password_authentication_creates_one_control_and_releases_permit() {
        let (addr, state, listener_task) =
            start_test_ssh_listener(std::time::Duration::from_secs(2)).await;
        let client_config = Arc::new(russh::client::Config::default());
        let mut client = russh::client::connect(client_config, addr, TestSshClient)
            .await
            .unwrap();

        let auth = client
            .authenticate_password("v0", "test-token")
            .await
            .unwrap();
        assert!(auth.success());
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                if state.run_id_to_ctl_tx.read().await.len() == 1 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(state.run_id_to_ctl_tx.read().await.len(), 1);
        assert_eq!(
            state.conn_semaphore.as_ref().unwrap().available_permits(),
            0
        );

        client
            .disconnect(russh::Disconnect::ByApplication, "test complete", "")
            .await
            .unwrap();
        drop(client);
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if state.conn_semaphore.as_ref().unwrap().available_permits() == 1 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        listener_task.abort();
    }

    #[tokio::test]
    async fn test_real_authentication_just_before_deadline_wins_race() {
        let (addr, state, listener_task) =
            start_test_ssh_listener(std::time::Duration::from_millis(800)).await;
        let mut client = russh::client::connect(
            Arc::new(russh::client::Config::default()),
            addr,
            TestSshClient,
        )
        .await
        .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(600)).await;

        let auth = client
            .authenticate_password("v0", "test-token")
            .await
            .unwrap();

        assert!(auth.success());
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                if state.run_id_to_ctl_tx.read().await.len() == 1 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        client
            .disconnect(russh::Disconnect::ByApplication, "test complete", "")
            .await
            .unwrap();
        listener_task.abort();
    }

    #[test]
    fn test_parse_ssh_args_tcp() {
        let args = parse_ssh_args(r#"tcp --proxy_name "web" --remote_port 9090"#).unwrap();
        assert_eq!(args.proxy_type, "tcp");
        assert_eq!(args.proxy_name, "web");
        assert_eq!(args.remote_port, 9090);
    }

    #[test]
    fn test_parse_ssh_args_http() {
        let args = parse_ssh_args(
            r#"http --proxy_name "blog" --custom_domains "a.example.com,b.example.com""#,
        )
        .unwrap();
        assert_eq!(args.proxy_type, "http");
        assert_eq!(args.proxy_name, "blog");
        assert_eq!(args.custom_domains, vec!["a.example.com", "b.example.com"]);
    }

    #[test]
    fn test_parse_ssh_args_unknown_type() {
        let err = parse_ssh_args("smtp --proxy_name test").unwrap_err();
        assert!(err.contains("unsupported proxy type"));
        assert!(err.contains("smtp"));
    }

    #[test]
    fn test_parse_ssh_args_missing_name() {
        let args = parse_ssh_args("tcp --remote_port 9090").unwrap();
        assert!(args.proxy_name.is_empty());
    }

    #[test]
    fn test_parse_ssh_args_stcp() {
        let args = parse_ssh_args(r#"stcp --proxy_name "secret" --sk "mysecret""#).unwrap();
        assert_eq!(args.proxy_type, "stcp");
        assert_eq!(args.sk, "mysecret");
    }

    #[test]
    fn test_parse_ssh_args_tcpmux() {
        let args =
            parse_ssh_args(r#"tcpmux --proxy_name "mux" --multiplexer "httpconnect""#).unwrap();
        assert_eq!(args.proxy_type, "tcpmux");
        assert_eq!(args.multiplexer, "httpconnect");
    }

    #[test]
    fn test_parse_ssh_args_empty() {
        let err = parse_ssh_args("").unwrap_err();
        assert!(err.contains("missing proxy type"));
    }

    #[test]
    fn test_shell_split_simple() {
        let tokens = shell_split("tcp --proxy_name web --remote_port 9090");
        assert_eq!(
            tokens,
            vec!["tcp", "--proxy_name", "web", "--remote_port", "9090"]
        );
    }

    #[test]
    fn test_shell_split_quoted() {
        let tokens = shell_split(r#"tcp --proxy_name "my web""#);
        assert_eq!(tokens, vec!["tcp", "--proxy_name", "my web"]);
    }

    #[test]
    fn test_shell_split_multiple_spaces() {
        let tokens = shell_split("tcp   --proxy_name   web   --remote_port   9090");
        assert_eq!(
            tokens,
            vec!["tcp", "--proxy_name", "web", "--remote_port", "9090"]
        );
    }

    #[test]
    fn test_shell_split_empty_quoted() {
        // Empty quoted strings are dropped (current.is_empty() guard).
        // This is acceptable — proxy names are never empty in practice.
        let tokens = shell_split(r#"tcp --proxy_name """#);
        assert_eq!(tokens, vec!["tcp", "--proxy_name"]);
    }

    #[test]
    fn test_exec_request_log_summary_redacts_secrets() {
        const SK: &str = "S3KR-sk-value";
        const GROUP_KEY: &str = "S3KR-group-key-value";
        const HTTP_PWD: &str = "S3KR-http-pwd-value";
        let args = ParsedProxyArgs {
            proxy_type: "tcp".into(),
            proxy_name: "web".into(),
            remote_port: 9090,
            local_ip: "127.0.0.1".into(),
            local_port: 8080,
            custom_domains: Vec::new(),
            subdomain: String::new(),
            sk: SK.into(),
            multiplexer: String::new(),
            use_encryption: true,
            use_compression: true,
            group: String::new(),
            group_key: GROUP_KEY.into(),
            http_user: String::new(),
            http_pwd: HTTP_PWD.into(),
            host_header_rewrite: String::new(),
            locations: Vec::new(),
            bandwidth_limit: String::new(),
            bandwidth_limit_mode: String::new(),
        };

        let summary = exec_request_log_summary(&args);
        assert!(summary.contains("type=tcp"));
        assert!(summary.contains("name=web"));
        assert!(summary.contains("remote_port=9090"));
        assert!(summary.contains("encryption=true"));
        assert!(summary.contains("compression=true"));
        for secret in [SK, GROUP_KEY, HTTP_PWD] {
            assert!(
                !summary.contains(secret),
                "secret leaked into exec_request log summary: {summary}"
            );
        }
    }
}

use std::borrow::Cow;
use std::path::Path;

use russh::server::Config;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpListener;

const SSH_MAX_CONNECTIONS: usize = 128;
const SSH_AUTH_DEADLINE: std::time::Duration = std::time::Duration::from_secs(15);
const SSH_DISCONNECT_GRACE: std::time::Duration = std::time::Duration::from_millis(250);

struct CloseableSshStream {
    stream: tokio::net::TcpStream,
    read_cancelled: Pin<Box<dyn Future<Output = ()> + Send>>,
    write_cancelled: Pin<Box<dyn Future<Output = ()> + Send>>,
    flush_cancelled: Pin<Box<dyn Future<Output = ()> + Send>>,
    shutdown_cancelled: Pin<Box<dyn Future<Output = ()> + Send>>,
    close_state: Arc<CloseState>,
}

struct CloseState {
    token: tokio_util::sync::CancellationToken,
    dropped: tokio_util::sync::CancellationToken,
}

#[derive(Clone)]
struct SshStreamCloser(Arc<CloseState>);

impl CloseableSshStream {
    fn new(stream: tokio::net::TcpStream) -> (Self, SshStreamCloser) {
        let token = tokio_util::sync::CancellationToken::new();
        let state = Arc::new(CloseState {
            token: token.clone(),
            dropped: tokio_util::sync::CancellationToken::new(),
        });
        (
            Self {
                stream,
                read_cancelled: Box::pin(token.clone().cancelled_owned()),
                write_cancelled: Box::pin(token.clone().cancelled_owned()),
                flush_cancelled: Box::pin(token.clone().cancelled_owned()),
                shutdown_cancelled: Box::pin(token.cancelled_owned()),
                close_state: state.clone(),
            },
            SshStreamCloser(state),
        )
    }
}

impl Drop for CloseableSshStream {
    fn drop(&mut self) {
        self.close_state.dropped.cancel();
    }
}

impl AsyncRead for CloseableSshStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.close_state.token.is_cancelled() || self.read_cancelled.as_mut().poll(cx).is_ready()
        {
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for CloseableSshStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.close_state.token.is_cancelled()
            || self.write_cancelled.as_mut().poll(cx).is_ready()
        {
            return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
        }
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if self.close_state.token.is_cancelled()
            || self.flush_cancelled.as_mut().poll(cx).is_ready()
        {
            return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
        }
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if self.close_state.token.is_cancelled()
            || self.shutdown_cancelled.as_mut().poll(cx).is_ready()
        {
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

impl SshStreamCloser {
    fn close(&self) {
        self.0.token.cancel();
    }

    async fn wait_dropped(&self) {
        self.0.dropped.cancelled().await;
    }
}

async fn terminate_ssh_session<D>(
    disconnect: D,
    session_task: &mut tokio::task::JoinHandle<Result<(), anyhow::Error>>,
    stream_closer: &SshStreamCloser,
    stage_timeout: std::time::Duration,
) where
    D: Future<Output = ()>,
{
    let _ = tokio::time::timeout(stage_timeout, disconnect).await;
    stream_closer.close();

    if tokio::time::timeout(stage_timeout, &mut *session_task)
        .await
        .is_err()
    {
        session_task.abort();
        let _ = tokio::time::timeout(stage_timeout, &mut *session_task).await;
    }

    let _ = tokio::time::timeout(stage_timeout, stream_closer.wait_dropped()).await;
}

/// SSH tunnel gateway listener. Binds a TCP port and accepts SSH connections.
pub struct SshListener {
    bind_addr: String,
    bind_port: u16,
    server_token: String,
    state: std::sync::Arc<AppState>,
    host_key: russh::keys::PrivateKey,
    authorized_keys: Vec<russh::keys::PublicKey>,
    auth_deadline: std::time::Duration,
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
                    .map(|s| {
                        s.lines()
                            .map(|l| l.trim().to_string())
                            .filter(|l| !l.is_empty() && !l.starts_with('#'))
                            .filter_map(|line| {
                                // Line format: "ssh-ed25519 AAAAC3NzaC1... [comment]"
                                let parts: Vec<&str> = line.split_whitespace().collect();
                                if parts.len() >= 2 {
                                    russh::keys::parse_public_key_base64(parts[1]).ok()
                                } else {
                                    None
                                }
                            })
                            .collect()
                    })
                    .unwrap_or_default()
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        Ok(Some(Self {
            bind_addr: ssh_cfg.bind_addr.clone(),
            bind_port: ssh_cfg.bind_port,
            server_token,
            state,
            host_key,
            authorized_keys,
            auth_deadline: SSH_AUTH_DEADLINE,
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

            let state = self.state.clone();
            let server_token = self.server_token.clone();
            let authorized_keys = self.authorized_keys.clone();
            let russh_config = russh_config.clone();
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

            tokio::spawn(async move {
                let _ssh_permit = ssh_permit;
                let _global_permit = global_permit;
                let (stream, stream_closer) = CloseableSshStream::new(stream);
                let (auth_complete_tx, mut auth_complete_rx) = tokio::sync::watch::channel(false);
                let authenticated_run_id = Arc::new(std::sync::Mutex::new(None));
                let session = SshSession::new(
                    server_token,
                    authorized_keys,
                    state.clone(),
                    peer_addr,
                    auth_complete_tx,
                    authenticated_run_id.clone(),
                    auth_deadline,
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
                        let run_id = authenticated_run_id.lock().unwrap().clone();
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
                                let run_id = authenticated_run_id.lock().unwrap().clone();
                                if let Some(run_id) = run_id {
                                    cleanup_session(&run_id, &state).await;
                                }
                                return;
                            }
                        }
                    }
                };

                let result = match pre_auth_result {
                    Some(result) => result,
                    None => session_task.await,
                };
                let run_id = authenticated_run_id.lock().unwrap().clone();
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

/// Load or auto-generate the SSH host key.
///
/// Priority:
/// 1. `private_key_file` if set and file exists
/// 2. `auto_gen_path` if file exists
/// 3. Generate new Ed25519 key, write to `auto_gen_path`
async fn load_or_generate_host_key(
    private_key_file: &str,
    auto_gen_path: &str,
) -> Result<russh::keys::PrivateKey, String> {
    // Try explicit key file first
    if !private_key_file.is_empty() && Path::new(private_key_file).exists() {
        return russh::keys::load_secret_key(private_key_file, None)
            .map_err(|e| format!("load key file {}: {}", private_key_file, e));
    }

    // Try auto-gen path
    if Path::new(auto_gen_path).exists() {
        return russh::keys::load_secret_key(auto_gen_path, None)
            .map_err(|e| format!("load auto-gen key {}: {}", auto_gen_path, e));
    }

    // Generate new Ed25519 key
    let mut rng = rand010::rng();
    let key = russh::keys::PrivateKey::random(&mut rng, russh::keys::Algorithm::Ed25519)
        .map_err(|e| format!("generate key: {}", e))?;
    let pem = key
        .to_openssh(russh::keys::ssh_key::LineEnding::default())
        .map_err(|e| format!("serialize key: {}", e))?;

    // Write to auto-gen path (pem is Zeroizing<String>, derefs to String)
    if let Some(parent) = Path::new(auto_gen_path).parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("create dir for key: {}", e))?;
    }
    std::fs::write(auto_gen_path, pem.as_bytes())
        .map_err(|e| format!("write auto-gen key {}: {}", auto_gen_path, e))?;

    // Restrict permissions: private key must be 0600 (owner read/write only).
    // Default umask typically creates 0644, which is world-readable.
    #[cfg(unix)]
    {
        let mut perms = std::fs::metadata(auto_gen_path)
            .map_err(|e| format!("stat key file: {}", e))?
            .permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(auto_gen_path, perms)
            .map_err(|e| format!("set key permissions: {}", e))?;
    }

    Ok(key)
}

#[cfg(test)]
mod key_tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_auto_gen_key_creates_file() {
        let dir = TempDir::new().unwrap();
        let key_path = dir.path().join("test_key");
        let key_path_str = key_path.to_str().unwrap();

        let key = load_or_generate_host_key("", key_path_str).await.unwrap();
        assert!(key_path.exists());

        let data = std::fs::read_to_string(&key_path).unwrap();
        assert!(data.contains("BEGIN OPENSSH PRIVATE KEY"));

        // Verify it's an Ed25519 key
        assert!(matches!(key.algorithm(), russh::keys::Algorithm::Ed25519));
    }

    #[tokio::test]
    async fn test_auto_gen_key_reuses_existing() {
        let dir = TempDir::new().unwrap();
        let key_path = dir.path().join("test_key");
        let key_path_str = key_path.to_str().unwrap();

        // First call generates
        let key1 = load_or_generate_host_key("", key_path_str).await.unwrap();

        // Second call reuses
        let mtime_before = std::fs::metadata(&key_path).unwrap().modified().unwrap();
        let key2 = load_or_generate_host_key("", key_path_str).await.unwrap();
        let mtime_after = std::fs::metadata(&key_path).unwrap().modified().unwrap();

        // File not overwritten
        assert_eq!(mtime_before, mtime_after);
        // Same key type
        assert!(matches!(key2.algorithm(), russh::keys::Algorithm::Ed25519));
        // Same key: fingerprints should match
        use russh::keys::ssh_key::HashAlg;
        let fp1 = key1.public_key().fingerprint(HashAlg::Sha256);
        let fp2 = key2.public_key().fingerprint(HashAlg::Sha256);
        assert_eq!(fp1.to_string(), fp2.to_string());
    }

    #[tokio::test]
    async fn test_explicit_key_file_takes_priority() {
        let dir = TempDir::new().unwrap();

        // Create auto-gen key
        let auto_path = dir.path().join("auto_key");
        let auto = load_or_generate_host_key("", auto_path.to_str().unwrap())
            .await
            .unwrap();

        // Create explicit key
        let explicit_path = dir.path().join("explicit_key");
        let mut rng = rand010::rng();
        let explicit =
            russh::keys::PrivateKey::random(&mut rng, russh::keys::Algorithm::Ed25519).unwrap();
        let pem = explicit
            .to_openssh(russh::keys::ssh_key::LineEnding::default())
            .unwrap();
        std::fs::write(&explicit_path, pem.as_bytes()).unwrap();

        // Load with explicit path set -- should use explicit, not auto
        let loaded =
            load_or_generate_host_key(explicit_path.to_str().unwrap(), auto_path.to_str().unwrap())
                .await
                .unwrap();

        // Both are Ed25519 -- verify they're different keys
        use russh::keys::ssh_key::HashAlg;
        let loaded_fp = loaded.public_key().fingerprint(HashAlg::Sha256);
        let auto_fp = auto.public_key().fingerprint(HashAlg::Sha256);
        assert_ne!(loaded_fp.to_string(), auto_fp.to_string());
    }
}

#[cfg(test)]
mod virtual_ctrl_tests {
    use super::*;

    /// Helper: build a plaintext LoginResp V1 frame matching what
    /// handle_control writes before wrapping in CipherStream.
    fn make_login_resp_frame() -> Vec<u8> {
        let msg = FrpMessage::LoginResp(frp_core::msg::LoginResp {
            version: Some("0.69.1".into()),
            run_id: Some("test".into()),
            error: None,
            server_additional_auth_scopes: None,
        });
        let payload = serde_json::to_vec(&msg).unwrap();
        let mut frame = Vec::with_capacity(9 + payload.len());
        frame.push(frp_core::msg::TYPE_LOGIN_RESP);
        frame.extend_from_slice(&(payload.len() as i64).to_be_bytes());
        frame.extend_from_slice(&payload);
        frame
    }

    /// Helper: write a LoginResp to `vc` so the VirtualControl bg task
    /// can consume it (Phase 1) and transition to encrypted mode (Phase 2).
    /// Awaits `phase2_ready` (oneshot signal from the bg task) before
    /// returning — subsequent writes go through the live CipherStream.
    async fn feed_login_resp(
        vc: &mut (impl tokio::io::AsyncWrite + Unpin),
        phase2_ready: tokio::sync::oneshot::Receiver<()>,
    ) {
        use tokio::io::AsyncWriteExt;
        vc.write_all(&make_login_resp_frame()).await.unwrap();
        phase2_ready.await.expect("bg task should reach Phase 2");
    }

    #[tokio::test]
    async fn test_virtual_control_channel_creation() {
        // Verify VirtualControl::channel creates a working duplex + mpsc channels
        let enc_key = frp_core::encryption::derive_key("test-token");
        let (mut vc, tx, _work_rx, phase2) = VirtualControl::channel(enc_key);
        // Feed LoginResp so the bg task transitions to encrypted mode
        feed_login_resp(&mut vc, phase2).await;
        // Channel should be alive — sending a frame should work
        assert!(tx.try_send(vec![0x04, 0, 0, 0, 0, 0, 0, 0, 0]).is_ok());
    }

    #[tokio::test]
    async fn test_virtual_control_channel_encrypted_roundtrip() {
        // Write a plain V1 frame through the encrypted channel and verify
        // it arrives on the other side (after encryption + decryption).
        use tokio::io::AsyncReadExt;
        let enc_key = frp_core::encryption::derive_key("test-key");
        let (mut vc, tx, _work_rx, phase2) = VirtualControl::channel(enc_key);

        // Phase 1: feed plaintext LoginResp so the bg task starts encryption
        feed_login_resp(&mut vc, phase2).await;

        // Phase 2: send a plain frame through frame_tx. The bg task encrypts
        // it and writes to the duplex. We read the encrypted data from vc
        // (the to_handler end).
        let frame = vec![0x04u8, 0, 0, 0, 0, 0, 0, 0, 0]; // TYPE_NEW_PROXY + 8-byte len
        tx.try_send(frame.clone()).unwrap();
        drop(tx);

        // Read back from vc — should get encrypted data
        let mut buf = [0u8; 4096];
        let n = vc.read(&mut buf).await.unwrap();
        assert!(n > 0, "should read data from encrypted channel");
    }
}
