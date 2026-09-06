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

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

use dashmap::DashMap;

use anyhow::anyhow;
use frp_core::msg::{FrpMessage, NewProxy, NewProxyResp};
use russh::server::{Auth, ChannelOpenHandle, Handler, Msg, Session};
use russh::{Channel, ChannelId, ChannelOpenFailure, MethodKind, MethodSet};
use tokio::sync::mpsc;

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
    if cmd.trim().is_empty() {
        return Err("missing proxy type".into());
    }
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
        let tok = parts[i].as_str();
        if tok == "--" {
            // pflag "--" terminator: everything after it is positional and
            // ignored (no positional args are registered beyond the type).
            break;
        }
        i = if let Some(raw) = tok.strip_prefix("--") {
            parse_long_flag(&mut args, raw, &parts, i)?
        } else if tok.len() > 1 && tok.starts_with('-') {
            parse_short_flags(&mut args, &tok[1..], &parts, i)?
        } else {
            // Non-flag positional token — ignored (the type was already
            // parsed from parts[0]).
            i
        };
        i += 1;
    }

    if args.proxy_name.is_empty() {
        // Go parity (pkg/ssh server.go): an SSH-mode proxy without an
        // explicit name registers under a generated one. Registering the
        // empty name (the old behavior) is unreadable in logs/dashboard and
        // collides with every other unnamed registration.
        args.proxy_name = default_proxy_name(&args.proxy_type);
    }

    Ok(args)
}

/// Parse a single `--name` or `--name=value` long-flag token. `raw` is the
/// text after the leading `--`. Returns the index of the last consumed token,
/// so the caller's trailing `i += 1` skips past it (and its value token).
fn parse_long_flag(
    args: &mut ParsedProxyArgs,
    raw: &str,
    parts: &[String],
    i: usize,
) -> Result<usize, String> {
    // pflag "bad flag syntax" cases: `--`, `--=x`, `---x`.
    if raw.is_empty() || raw.starts_with('-') || raw.starts_with('=') {
        return Err(format!("bad flag syntax: --{raw}"));
    }
    let (name, inline_value) = match raw.split_once('=') {
        Some((name, value)) => (name, Some(value)),
        None => (raw, None),
    };
    let Some(canon) = canonical_flag_name(name) else {
        if name == "help" {
            // pflag: an unregistered `--help` prints the usage (ErrHelp).
            return Err(ssh_gateway_usage());
        }
        return Err(format!("unknown flag: --{name}"));
    };
    match inline_value {
        // `--flag=value`. An explicitly empty value IS applied (and can
        // fail) — Go runs strconv on it too.
        Some(value) => {
            apply_flag_value(args, canon, value)?;
            Ok(i)
        }
        None => {
            // Value from the next token, unless that token is another flag.
            // A truncated flag (no value, or a flag-like next token) leaves
            // the field at its default — a deliberate divergence from
            // Go/pflag, which consumes the next token as the value
            // unconditionally (a `--proxy_name --sk` command would register
            // a proxy literally named "--sk").
            match parts.get(i + 1).filter(|v| !v.starts_with("--")) {
                Some(value) => {
                    apply_flag_value(args, canon, value)?;
                    Ok(i + 1)
                }
                None => Ok(i),
            }
        }
    }
}

/// Parse a run of shorthand flags (`-n`, `-n=web`, `-nweb`, `-n web`),
/// mirroring pflag's cluster semantics: a value-taking shorthand consumes the
/// rest of the cluster, or the next token. Returns the index of the last
/// consumed token (see parse_long_flag).
fn parse_short_flags(
    args: &mut ParsedProxyArgs,
    cluster: &str,
    parts: &[String],
    i: usize,
) -> Result<usize, String> {
    let Some(c) = cluster.chars().next() else {
        return Ok(i);
    };
    let rest = &cluster[c.len_utf8()..];
    let Some(canon) = short_flag_target(c) else {
        if c == 'h' {
            // pflag: an unregistered `-h` prints the usage (ErrHelp).
            return Err(ssh_gateway_usage());
        }
        // pflag reports the full remaining cluster (`in -%s`), not just the
        // remainder after the unknown letter (parseSingleShortArg).
        return Err(format!("unknown shorthand flag: '{c}' in -{cluster}"));
    };
    if let Some(value) = rest.strip_prefix('=') {
        // `-n=web`.
        apply_flag_value(args, canon, value)?;
        return Ok(i);
    }
    if !rest.is_empty() {
        // `-nweb`: the rest of the cluster is the value.
        apply_flag_value(args, canon, rest)?;
        return Ok(i);
    }
    // `-n web`: value from the next token (flag-like tokens excluded — see
    // parse_long_flag), or a truncated flag left at its default.
    match parts.get(i + 1).filter(|v| !v.starts_with("--")) {
        Some(value) => {
            apply_flag_value(args, canon, value)?;
            Ok(i + 1)
        }
        None => Ok(i),
    }
}

/// Canonical (underscore) spelling of a registered long-flag name, if any.
///
/// `_` and `-` are treated as equivalent separators — the intent of Go's
/// pflag `WordSepNormalizeFunc` (frp registers SSH-mode flags as
/// `--proxy_name`; both spellings must parse). Go only folds the FIRST
/// separator; folding every separator is a deliberate frp-rs simplification:
/// no registered flag differs from its dash form by anything but separator
/// placement, so both forms accept the same flag set.
const FLAG_SPELLINGS: &[(&str, &str)] = &[
    ("proxy_name", "proxy_name"),
    ("remote_port", "remote_port"),
    ("local_ip", "local_ip"),
    ("local_port", "local_port"),
    ("custom_domains", "custom_domains"),
    ("custom_domain", "custom_domains"), // legacy alias
    ("subdomain", "subdomain"),
    ("sk", "sk"),
    ("multiplexer", "multiplexer"),
    ("use_encryption", "use_encryption"),
    ("use_compression", "use_compression"),
    ("group", "group"),
    ("group_key", "group_key"),
    ("http_user", "http_user"),
    ("http_pwd", "http_pwd"),
    ("host_header_rewrite", "host_header_rewrite"),
    ("locations", "locations"),
    ("bandwidth_limit", "bandwidth_limit"),
    ("bandwidth_limit_mode", "bandwidth_limit_mode"),
];

fn canonical_flag_name(raw: &str) -> Option<&'static str> {
    let folded = raw.replace('-', "_");
    FLAG_SPELLINGS
        .iter()
        .find(|(spelling, _)| folded == **spelling)
        .map(|(_, canonical)| *canonical)
}

/// Short-flag targets. Go frp registers only these shorthands in SSH mode
/// (pkg/config/flags.go): `-n` proxy_name, `-r` remote_port, `-d`
/// custom_domains.
fn short_flag_target(c: char) -> Option<&'static str> {
    match c {
        'n' => Some("proxy_name"),
        'r' => Some("remote_port"),
        'd' => Some("custom_domains"),
        _ => None,
    }
}

/// Apply a parsed flag value to `args`. Value parse failures produce the
/// pflag-shaped `invalid argument` error Go surfaces from FlagSet.Set (the
/// tail is frp-rs wording — Go embeds strconv's message, which has no Rust
/// equivalent).
fn apply_flag_value(args: &mut ParsedProxyArgs, canon: &str, value: &str) -> Result<(), String> {
    match canon {
        "proxy_name" => args.proxy_name = value.to_string(),
        "remote_port" => args.remote_port = parse_port_value(value, "-r, --remote_port")?,
        "local_ip" => args.local_ip = value.to_string(),
        "local_port" => args.local_port = parse_port_value(value, "--local_port")?,
        "custom_domains" => args.custom_domains = split_csv(value),
        "subdomain" => args.subdomain = value.to_string(),
        "sk" => args.sk = value.to_string(),
        "multiplexer" => args.multiplexer = value.to_string(),
        "use_encryption" => args.use_encryption = matches!(value, "true" | "1"),
        "use_compression" => args.use_compression = matches!(value, "true" | "1"),
        "group" => args.group = value.to_string(),
        "group_key" => args.group_key = value.to_string(),
        "http_user" => args.http_user = value.to_string(),
        "http_pwd" => args.http_pwd = value.to_string(),
        "host_header_rewrite" => args.host_header_rewrite = value.to_string(),
        "locations" => args.locations = split_csv(value),
        "bandwidth_limit" => args.bandwidth_limit = value.to_string(),
        "bandwidth_limit_mode" => args.bandwidth_limit_mode = value.to_string(),
        other => {
            // Defensive: every canonical name is handled above; a future
            // table/arm drift must error, not silently no-op.
            return Err(format!("internal error: unhandled flag {other}"));
        }
    }
    Ok(())
}

/// Parse a port value (`--remote_port` / `--local_port`, 0 = auto-assign).
/// The pflag-shaped error carries the flag's canonical display name (Go
/// formats shorthand flags as "-r, --remote_port").
fn parse_port_value(value: &str, display: &str) -> Result<u16, String> {
    value.parse::<u16>().map_err(|_| {
        format!(
            "invalid argument \"{value}\" for \"{display}\" flag: port must be an integer between 0 and 65535"
        )
    })
}

/// Split a comma-separated flag value, dropping empty entries.
fn split_csv(value: &str) -> Vec<String> {
    value
        .split(',')
        .filter(|d| !d.is_empty())
        .map(|d| d.trim().to_string())
        .collect()
}

/// Generate the default SSH-mode proxy name — Go parity: `sshtunnel-` +
/// proxy type + RandIDWithLen(8) (pkg/util/util.go, random bytes as 8
/// lowercase hex chars).
fn default_proxy_name(proxy_type: &str) -> String {
    use rand::TryRng;
    let mut buf = [0u8; 4];
    // SysRng (getrandom) failure is unreachable on supported platforms; a
    // zero-filled name would still be valid and effectively unique.
    let _ = rand::rngs::SysRng.try_fill_bytes(&mut buf);
    format!("sshtunnel-{}-{}", proxy_type, frp_core::hex_encode(&buf))
}

/// Usage text for `--help` / `-h` and the empty command. Go frp writes the
/// cobra command usage to the SSH client on ErrHelp and closes; this is the
/// frp-rs equivalent listing the flags parse_ssh_args accepts.
fn ssh_gateway_usage() -> String {
    format!(
        concat!(
            "frp-rs SSH tunnel gateway\n",
            "\n",
            "Usage: ssh ... <proxy_type> [flags]\n",
            "Example: ssh -R :9090:127.0.0.1:8080 v0@server -p 2200 tcp --proxy_name web\n",
            "\n",
            "Proxy types: {types}\n",
            "\n",
            "Flags:\n",
            "  -n, --proxy_name string            proxy name (empty = auto: sshtunnel-<type>-<random>)\n",
            "  -r, --remote_port uint16           server listen port, 0 = auto-assign\n",
            "  -d, --custom_domains stringList    custom domains, comma-separated (http/https)\n",
            "      --subdomain string             subdomain on the vhost server (http/https)\n",
            "      --sk string                    secret key (stcp)\n",
            "      --multiplexer string           multiplexer name (tcpmux)\n",
            "      --local_ip string              local service IP\n",
            "      --local_port uint16            local service port\n",
            "      --use_encryption               enable encryption (\"true\" or \"1\")\n",
            "      --use_compression              enable compression (\"true\" or \"1\")\n",
            "      --group string                 group name\n",
            "      --group_key string             group key\n",
            "      --http_user string             HTTP basic-auth user (http/https)\n",
            "      --http_pwd string              HTTP basic-auth password (http/https)\n",
            "      --host_header_rewrite string   rewrite the Host header (http/https)\n",
            "      --locations stringList         vhost locations, comma-separated (http/https)\n",
            "      --bandwidth_limit string       bandwidth limit (e.g. 1MB)\n",
            "      --bandwidth_limit_mode string  bandwidth limit mode: client or server\n",
            "  -h, --help                         show this help and exit\n"
        ),
        types = VALID_PROXY_TYPES.join(", ")
    )
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
/// and decrypts incoming data to intercept ReqWorkConn messages and
/// NewProxyResp messages (proxy registration results).
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
    /// - `proxy_resp_rx`: receiver for intercepted NewProxyResp messages
    ///   (proxy registration results, reported to exec_request)
    /// - `phase2_ready`: resolves once LoginResp consumed + CipherStream ready
    pub fn channel(
        enc_key: [u8; 16],
    ) -> (
        impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
        mpsc::Sender<Vec<u8>>,
        mpsc::Receiver<WorkConnRequest>,
        mpsc::Receiver<NewProxyResp>,
        tokio::sync::oneshot::Receiver<()>,
    ) {
        let (to_handler, from_ssh) = tokio::io::duplex(65536);
        let (frame_tx, mut frame_rx) = mpsc::channel::<Vec<u8>>(64);
        let (work_tx, work_rx) = mpsc::channel::<WorkConnRequest>(16);
        let (resp_tx, resp_rx) = mpsc::channel::<NewProxyResp>(16);
        let (phase2_tx, phase2_rx) = tokio::sync::oneshot::channel();

        // Spawn background task that bridges the duplex to the mpsc channels,
        // with encryption matching handle_control's CipherStream.
        //
        // handle_control writes LoginResp as PLAINTEXT before wrapping its side
        // in CipherStream. To keep both sides' CFB state in sync, we consume
        // the plaintext LoginResp from the raw stream BEFORE wrapping our side
        // in CipherStream.
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;

            let mut from_ssh = from_ssh;

            // ---- Phase 1: consume plaintext LoginResp from raw stream ----
            // Uses the canonical V1 frame reader (frp_core::protocol), which
            // reads the 9-byte header + payload with read_exact, so NOTHING
            // past LoginResp is consumed: the control handler may write an
            // encrypted ReqWorkConn immediately after LoginResp
            // (pool_count>0), and over-reading here would desync the CFB
            // cipher state. read_v1_frame applies the V1_MAX_MSG_LENGTH (10
            // KiB) cap instead of the old ad-hoc 64 KiB allowance — LoginResp
            // is tiny either way, and the canonical cap is the V1 spec.
            if frp_core::protocol::read_v1_frame(&mut from_ssh)
                .await
                .is_err()
            {
                return;
            }
            // LoginResp consumed exactly; any further bytes stay in the stream
            // for the CipherStream phase. No extra-bytes warning is needed:
            // with read_exact the stream position is exact by construction.

            // ---- Phase 2: wrap in CipherStream, split for concurrent r/w ----
            let _ = phase2_tx.send(());
            // Audit B2: OS-RNG failure (IV generation) drops the SSH session
            // like the read failure above instead of aborting the process.
            let encrypted =
                match frp_core::cipher_stream::CipherStream::new(Box::new(from_ssh), enc_key) {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::warn!(error = %e, "ssh session: IV generation failed");
                        return;
                    }
                };
            let (mut enc_reader, mut enc_writer) = tokio::io::split(encrypted);
            let read_work_tx = work_tx;

            // Read task: decrypt V1 frames with canonical parser, intercept
            // ReqWorkConn (→ WorkConnRequest, opens forwarded-tcpip work
            // conns) and NewProxyResp (→ proxy_resp_rx, the exec_request
            // registration wait).
            let read_resp_tx = resp_tx;
            let read_task: tokio::task::JoinHandle<()> = tokio::spawn(async move {
                loop {
                    match frp_core::protocol::read_v1_frame(&mut enc_reader).await {
                        Ok((type_byte, payload)) => {
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
                            } else if type_byte == frp_core::msg::TYPE_NEW_PROXY_RESP {
                                // Registration result for an exec_request's
                                // NewProxy. The frame payload is that
                                // struct's JSON, so decode it directly;
                                // unparseable frames are logged and dropped —
                                // the exec wait then times out like Go's
                                // waitProxyStatusReady.
                                match serde_json::from_slice::<NewProxyResp>(&payload) {
                                    Ok(resp) => {
                                        let _ = read_resp_tx.try_send(resp);
                                    }
                                    Err(e) => tracing::debug!(
                                        error = %e,
                                        "bridge: unparseable NewProxyResp dropped"
                                    ),
                                }
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

        (to_handler, frame_tx, work_rx, resp_rx, phase2_rx)
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
    frame_tx: Option<mpsc::Sender<Vec<u8>>>,
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
    state: std::sync::Arc<AppState>,
    /// Set to true by auth_succeeded.
    authenticated: bool,
    peer_addr: std::net::SocketAddr,
    auth_complete_tx: tokio::sync::watch::Sender<bool>,
    authenticated_run_id: Arc<std::sync::Mutex<Option<String>>>,
    auth_deadline: tokio::time::Instant,
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

    // Pre-guard (audit finding 6e): write_v1_frame's 10 KiB length check
    // does not run on this path — the frame is built by hand and shipped
    // raw over frame_tx — and custom_domains/locations/local_str come from
    // the peer's own `ssh -R` command line, bounded only by the ~32 KiB
    // SSH channel window. An oversized frame would reach the local control
    // handler's read_v1_frame and kill this SSH user's OWN virtual control
    // with "invalid V1 msg length". Reject instead; the caller turns the
    // error into an SSH failure reply scoped to that one session.
    if payload.len() as i64 > frp_core::protocol::V1_MAX_MSG_LENGTH {
        return Err(anyhow!(
            "proxy config too large ({} bytes, max {}): shorten custom_domains/locations",
            payload.len(),
            frp_core::protocol::V1_MAX_MSG_LENGTH
        ));
    }

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
        // mirroring login.rs:680 `is_login_throttled`. Round-11 ran the
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
            // Empty remote command: print the usage, then close (the Go
            // ErrHelp path prints cmd.UsageString() and closes).
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

/// Background task: receives WorkConnRequest signals from VirtualControl
/// (which intercepted ReqWorkConn from the control handler). For each request,
/// opens a `forwarded-tcpip` channel back to the SSH client (Go frp's
/// virtual-client pipeConnector semantics), hands the pipe's work side to the
/// control layer as a work conn, and bridges the SSH channel with the pipe.
async fn handle_work_conn_requests(
    mut work_rx: mpsc::Receiver<WorkConnRequest>,
    run_id: String,
    handle: russh::server::Handle,
    state: Arc<AppState>,
    reverse_forward: Arc<std::sync::Mutex<Option<(String, u32)>>>,
    reverse_data_tx: Arc<DashMap<russh::ChannelId, mpsc::Sender<Vec<u8>>>>,
    control_exit: tokio_util::sync::CancellationToken,
) {
    loop {
        // Race the recv against the session's control-exit token: when the
        // virtual control handler exits, the session is being torn down —
        // stop accepting work-conn requests instead of silently dropping
        // them (no control handler remains to deliver them to).
        let req = tokio::select! {
            biased;
            _ = control_exit.cancelled() => {
                tracing::debug!(
                    run_id = %run_id,
                    "SSH session {} work-connection handler exiting on control exit",
                    run_id
                );
                break;
            }
            req = work_rx.recv() => req,
        };
        let Some(_req) = req else {
            break;
        };
        let Some((addr, port)) = reverse_forward
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
        else {
            tracing::warn!(
                run_id = %run_id,
                "SSH work conn requested but no -R tcpip-forward registered; dropping"
            );
            continue;
        };

        // Open the forwarded-tcpip channel (server-initiated). The payload
        // carries the recorded -R address (Go server.go semantics).
        let channel = match handle
            .channel_open_forwarded_tcpip(&addr, port, &addr, port)
            .await
        {
            Ok(ch) => ch,
            Err(e) => {
                tracing::warn!(
                    run_id = %run_id,
                    error = %e,
                    "SSH: failed to open forwarded-tcpip channel for {}:{}: {}",
                    addr,
                    port,
                    e
                );
                continue;
            }
        };
        let channel_id = channel.id();

        // Register the data route (SSH client → bridge read half).
        // Bounded: backpressure via the SSH data callback above.
        let (data_tx, data_rx) = mpsc::channel::<Vec<u8>>(64);
        reverse_data_tx.insert(channel_id, data_tx);

        // In-memory pipe: one end is the work conn, the other is bridged
        // with the SSH channel (Go virtual client net.Pipe).
        let (work_side, ssh_side) = tokio::io::duplex(64 * 1024);

        let ctl_tx = state.run_id_to_ctl_tx.get(&run_id).map(|c| c.tx.clone());
        let Some(tx) = ctl_tx else {
            tracing::warn!(run_id = %run_id, "SSH: control handler gone; dropping work conn");
            let _ = handle.close(channel_id).await;
            reverse_data_tx.remove(&channel_id);
            continue;
        };
        let work_io = frp_core::transport::IoStream::SshChannel(Box::new(work_side));
        if tx
            .send(crate::service::InternalMsg::NewWorkConn(work_io))
            .await
            .is_err()
        {
            tracing::debug!(run_id = %run_id, "SSH: control gone while delivering work conn");
            let _ = handle.close(channel_id).await;
            reverse_data_tx.remove(&channel_id);
            continue;
        }

        let reg = reverse_data_tx.clone();
        let handle2 = handle.clone();
        tokio::spawn(async move {
            bridge_ssh_side(ssh_side, data_rx, handle2.clone(), channel_id).await;
            let _ = handle2.close(channel_id).await;
            reg.remove(&channel_id);
        });
    }

    tracing::debug!(run_id = %run_id, "SSH session {} work-connection handler exiting", run_id);
}

/// Bridge the duplex SSH side with the SSH forwarded-tcpip channel.
///
/// The control layer first writes a V1 StartWorkConn frame on the pipe; that
/// frame must be consumed here (Go's virtual client consumes it in memory,
/// never sending it to the SSH client). Afterwards bytes flow both ways:
/// - frps user connection → SSH client → local service (via `handle.data`),
/// - local service response → `data` callback → bridge write half → frps.
async fn bridge_ssh_side(
    mut ssh_side: tokio::io::DuplexStream,
    mut data_rx: mpsc::Receiver<Vec<u8>>,
    handle: russh::server::Handle,
    channel_id: russh::ChannelId,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Consume the StartWorkConn V1 frame (type byte + 8-byte BE length + payload).
    // Both reads are bounded by POST_HANDSHAKE_READ_TIMEOUT (30s): the peer
    // (an SSH virtual client bridging via a user connection) is not
    // authenticated on this pipe, so an unbounded read would park this task,
    // the channel, and the session's resources forever on a silent peer.
    let mut header = [0u8; frp_core::protocol::V1_HEADER_LEN];
    let Ok(Ok(_)) = tokio::time::timeout(
        crate::handlers::POST_HANDSHAKE_READ_TIMEOUT,
        ssh_side.read_exact(&mut header),
    )
    .await
    else {
        return;
    };
    let len = u64::from_be_bytes(
        header[1..9]
            .try_into()
            .expect("header is a fixed 9-byte array (V1_HEADER_LEN)"),
    );
    if len <= frp_core::protocol::V1_MAX_MSG_LENGTH as u64 {
        let mut payload = vec![0u8; len as usize];
        let Ok(Ok(_)) = tokio::time::timeout(
            crate::handlers::POST_HANDSHAKE_READ_TIMEOUT,
            ssh_side.read_exact(&mut payload),
        )
        .await
        else {
            return;
        };
    } else {
        // An oversized frame (> 10 KiB V1 cap) from the control-pipe peer
        // is not a legal StartWorkConn — the header's payload-length field
        // is attacker-controlled and the remaining body bytes must NOT be
        // forwarded to the SSH client as tunnel data (round-13 audit
        // finding). Drop the connection; the peer (a frpc virtual client)
        // treats the drop as a failed bridge and re-dials.
        tracing::warn!(
            len,
            channel = ?channel_id,
            "SSH forwarded-tcpip bridge: work-conn header declares {} bytes (V1 cap {}), dropping",
            len,
            frp_core::protocol::V1_MAX_MSG_LENGTH
        );
        return;
    }

    let (mut ssh_read, mut ssh_write) = tokio::io::split(ssh_side);
    // frps user connection → SSH client (→ local service).
    let writer = tokio::spawn(async move {
        let mut buf = [0u8; 16 * 1024];
        loop {
            let n = match ssh_read.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            if handle.data(channel_id, buf[..n].to_vec()).await.is_err() {
                break;
            }
        }
        let _ = handle.eof(channel_id).await;
    });
    // Local service response (SSH client data) → frps user connection.
    while let Some(data) = data_rx.recv().await {
        if ssh_write.write_all(&data).await.is_err() {
            break;
        }
    }
    let _ = ssh_write.shutdown().await;
    let _ = writer.await;
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
            vec![frp_core::config::PortsRange {
                start: 1,
                end: u16::MAX,
                single: 0,
            }],
            String::new(),
            true,
            30,
            7200,
            0,
            0,
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
            0,
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
            tokio_util::sync::CancellationToken::new(),
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
        let mut rng = rand::rng();
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
            ssh_session_idle_timeout: 0,
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
        assert!(run_id.lock().unwrap_or_else(|e| e.into_inner()).is_none());
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

    #[tokio::test]
    async fn test_password_failures_throttle_per_ip() {
        // S1 pin: SSH gateway password failures consume the per-IP login
        // throttle slots (mirror of login.rs `throttled_login_error`) — a
        // brute-forcing IP is cut off after the 5th wrong password, and the
        // success path never consumes a slot (legit sessions are never
        // throttled). Go frp has no SSH-gateway auth throttle; this is the
        // same deliberate frp-rs hardening as the login throttle.
        let (mut session, _auth_rx, _run_id) = pre_auth_session();
        let addr = session.peer_addr;
        let state = session.state.clone();
        for _ in 0..5 {
            let result = session.auth_password("v0", "wrong").await.unwrap();
            assert!(matches!(result, Auth::Reject { .. }));
        }
        assert!(
            !state.check_login_throttle(addr).await,
            "6th attempt from the same IP must be throttled"
        );
        // Round-11 GAP-1 pin: the throttle must DENY, not merely return
        // false from the table. The 6th wrong password on this session is
        // cut off with an Err (russh treats a handler error as fatal for
        // the session — the connection dies) instead of a fresh Reject
        // round-trip. Pre-fix this returned Ok(Reject) again: the
        // check_login_throttle bool was discarded at the call site.
        let result = session.auth_password("v0", "wrong").await;
        assert!(
            result.is_err(),
            "6th wrong password must end the session with Err, got: {result:?}"
        );
        // A FRESH connection from the same IP within the window is denied
        // without a USERAUTH_FAILURE round-trip (same state table, shared
        // below). Round-12 pin (audit A1): the deny is now a FAIL-CLOSED
        // pre-auth gate (login.rs:680 `is_login_throttled` parity) that
        // runs BEFORE the constant-time compare — an armed IP's guess is
        // never evaluated, and even a CORRECT password from an armed IP is
        // denied for the window. Round-11's deny ran only on the mismatch
        // branch (after the compare): fail-open meant the throttle never
        // stopped online guessing of the actual password (1 evaluated guess
        // per fresh conn) and skipped the russh 3s rejection pacing, so the
        // 6th+ guess was FASTER than the pre-fix paced rejects.
        let (auth_tx2, _auth_rx2) = tokio::sync::watch::channel(false);
        let run_id2 = Arc::new(std::sync::Mutex::new(None));
        let mut fresh = SshSession::new(
            "test-token".into(),
            Vec::new(),
            state.clone(),
            addr,
            auth_tx2,
            run_id2,
            tokio::time::Instant::now() + SSH_AUTH_DEADLINE,
            tokio_util::sync::CancellationToken::new(),
        );
        let result = fresh.auth_password("v0", "wrong").await;
        assert!(
            result.is_err(),
            "fresh session from a throttled IP must be cut off, got: {result:?}"
        );
        // Fail-closed pin: the pre-gate denies BEFORE the credential
        // compare, so the CORRECT password from an armed IP inside the
        // window is also cut off (no guess evaluated, no accept). RED on
        // round-11 code: the mismatch-branch-only deny let this Accept.
        let (auth_tx3, _auth_rx3) = tokio::sync::watch::channel(false);
        let run_id3 = Arc::new(std::sync::Mutex::new(None));
        let mut fresh_correct = SshSession::new(
            "test-token".into(),
            Vec::new(),
            state.clone(),
            addr,
            auth_tx3,
            run_id3,
            tokio::time::Instant::now() + SSH_AUTH_DEADLINE,
            tokio_util::sync::CancellationToken::new(),
        );
        let result = fresh_correct.auth_password("v0", "test-token").await;
        assert!(
            result.is_err(),
            "correct password from an armed IP must be denied by the pre-gate, got: {result:?}"
        );
        // Other IPs are unaffected.
        assert!(
            state
                .check_login_throttle(std::net::SocketAddr::from(([127, 0, 0, 2], 1)))
                .await,
            "a different IP must not be throttled"
        );
        // The success path consumes no slot.
        let (mut s2, _a2, _r2) = pre_auth_session();
        let addr2 = s2.peer_addr;
        let state2 = s2.state.clone();
        let result = s2.auth_password("v0", "test-token").await.unwrap();
        assert!(matches!(result, Auth::Accept));
        assert!(
            state2.check_login_throttle(addr2).await,
            "successful auth must not consume a throttle slot"
        );
    }

    #[tokio::test]
    async fn test_pubkey_and_none_rejections_do_not_consume_throttle_slots() {
        // D5 pin: only PASSWORD failures consume per-IP throttle slots.
        // `auth_publickey` / `auth_none` return Reject without calling
        // `check_login_throttle`, so a client that probes with pubkey or
        // "none" methods cannot arm the window against the password path
        // (or the shared frpc-login table) — and 5 pubkey/none rejections
        // from one IP leave a subsequent password attempt fully allowed.
        let (mut session, _auth_rx, _run_id) = pre_auth_session();
        let addr = session.peer_addr;
        let state = session.state.clone();

        // 5 publickey rejections (key not in the empty authorized_keys).
        let key =
            russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519)
                .unwrap();
        let pubkey = key.public_key().clone();
        for i in 0..5 {
            let result = session.auth_publickey("v0", &pubkey).await.unwrap();
            assert!(
                matches!(result, Auth::Reject { .. }),
                "pubkey rejection {i} must reject (key not authorized)"
            );
        }
        assert!(
            state.check_login_throttle(addr).await,
            "5 pubkey rejections must not arm the password throttle window"
        );

        // 5 "none" rejections (token configured → auth_none rejects).
        let mut s2 = session;
        for i in 0..5 {
            let result = s2.auth_none("v0").await.unwrap();
            assert!(
                matches!(result, Auth::Reject { .. }),
                "none rejection {i} must reject (token configured)"
            );
        }
        assert!(
            state.check_login_throttle(addr).await,
            "5 none rejections must not arm the password throttle window"
        );

        // And a password attempt from the same IP is still fully allowed.
        let result = s2.auth_password("v0", "test-token").await.unwrap();
        assert!(matches!(result, Auth::Accept));
    }

    #[tokio::test]
    async fn test_auth_none_rejected_when_token_is_set() {
        // Regression: auth_none must NOT accept when server_token is
        // configured even if authorized_keys is empty — otherwise any
        // SSH client can bypass token auth (OpenSSH sends "none" first).
        let (mut session, _auth_rx, _run_id) = pre_auth_session();
        let result = session.auth_none("v0").await.unwrap();
        assert!(matches!(result, Auth::Reject { .. }));
    }

    #[tokio::test]
    async fn test_auth_none_accepted_when_no_auth_configured() {
        let (auth_tx, _auth_rx) = tokio::sync::watch::channel(false);
        let run_id_arc = Arc::new(std::sync::Mutex::new(None));
        let mut session = SshSession::new(
            String::new(), // empty token
            Vec::new(),    // empty authorized_keys
            test_state(1),
            "127.0.0.1:2200".parse().unwrap(),
            auth_tx,
            run_id_arc,
            tokio::time::Instant::now() + SSH_AUTH_DEADLINE,
            tokio_util::sync::CancellationToken::new(),
        );
        let result = session.auth_none("v0").await.unwrap();
        assert!(matches!(result, Auth::Accept));
    }

    #[tokio::test]
    async fn test_auth_none_rejected_when_only_keys_configured() {
        // When authorized_keys is set but token is empty, auth_none must
        // still reject — client must use pubkey auth, not anonymous.
        let (auth_tx, _auth_rx) = tokio::sync::watch::channel(false);
        let run_id_arc = Arc::new(std::sync::Mutex::new(None));
        let key =
            russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519)
                .unwrap();
        let pubkey = key.public_key().clone();
        let mut session = SshSession::new(
            String::new(),
            vec![pubkey],
            test_state(1),
            "127.0.0.1:2200".parse().unwrap(),
            auth_tx,
            run_id_arc,
            tokio::time::Instant::now() + SSH_AUTH_DEADLINE,
            tokio_util::sync::CancellationToken::new(),
        );
        let result = session.auth_none("v0").await.unwrap();
        assert!(matches!(result, Auth::Reject { .. }));
    }

    /// Round-11 GAP5: the authorized_keys parser is a pure fn with an
    /// externally visible contract (a hostile or hand-edited file must not
    /// crash the gateway, and only valid keys may enter the allow-list).
    /// This was inline in SshListener::new with zero unit coverage; the
    /// shapes below pin the extraction.
    #[test]
    fn test_parse_authorized_keys_shapes() {
        use russh::keys::PublicKeyBase64;

        let key1 =
            russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519)
                .unwrap();
        let key2 =
            russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519)
                .unwrap();
        let k1_b64 = key1.public_key().public_key_base64();
        let k2_b64 = key2.public_key().public_key_base64();
        let expected1 = russh::keys::parse_public_key_base64(&k1_b64).unwrap();
        let expected2 = russh::keys::parse_public_key_base64(&k2_b64).unwrap();

        // (a) valid line with comment; (b) blank + # comment skipped;
        // (c) indented key lines parse (trim).
        let parsed = parse_authorized_keys(&format!(
            "ssh-ed25519 {k1_b64} user@host\n\n  # comment\n   \nssh-ed25519 {k2_b64}\n"
        ));
        assert_eq!(parsed, vec![expected1.clone(), expected2.clone()]);
        assert_eq!(parsed[0].algorithm(), russh::keys::Algorithm::Ed25519);

        // (d) type-only line (no base64) is dropped;
        // (e) garbage base64 is dropped, neighbors survive.
        let parsed = parse_authorized_keys(&format!(
            "ssh-ed25519\nssh-rsa NOT-BASE64!!\nssh-ed25519 {k1_b64}\n"
        ));
        assert_eq!(parsed, vec![expected1.clone()]);

        // (f) a wrong type field does not invalidate a decodable key
        // (the blob itself carries the type; see the fn doc).
        let parsed = parse_authorized_keys(&format!("ssh-rsa {k2_b64} comment\n"));
        assert_eq!(parsed, vec![expected2.clone()]);

        // (g) empty body / comment-only body parse to nothing.
        assert!(parse_authorized_keys("").is_empty());
        assert!(parse_authorized_keys("# only comments\n\n").is_empty());

        // (h) OpenSSH option-prefixed lines parse (round-12 A2: the old
        // parts[1]-as-base64 reader dropped every options line — a
        // migrated stock authorized_keys uses options everywhere). Covers
        // bare options, quoted values with embedded spaces/commas, and
        // option lists that swallow several tokens.
        let parsed = parse_authorized_keys(&format!(
            "restrict,command=\"echo hi\",from=\"1.2.3.4, 5.6.7.8\" ssh-ed25519 {k1_b64} u@h\n\
             no-port-forwarding ssh-ed25519 {k2_b64}\n"
        ));
        assert_eq!(parsed, vec![expected1.clone(), expected2.clone()]);

        // (i) certificate entries are dropped whole (frp-rs has no CA trust
        // store — see the fn doc) even when the blob decodes — the cert
        // anchor + a raw key blob is the (f)-style trap: the old parser
        // accepted the embedded raw key with zero CA validation; neighbor
        // lines survive.
        let parsed = parse_authorized_keys(&format!(
            "ssh-ed25519-cert-v01@openssh.com {k1_b64}\n\
             ssh-ed25519 {k2_b64}\n"
        ));
        assert_eq!(parsed, vec![expected2]);

        // (j) options lines whose key material does not decode are dropped
        // (the malformed line, not the file — per-line-drop divergence).
        let parsed = parse_authorized_keys(&format!(
            "restrict,from=\"9.9.9.9\" ssh-ed25519 NOT-BASE64!!\n\
             ssh-ed25519 {k1_b64}\n"
        ));
        assert_eq!(parsed, vec![expected1]);
    }

    /// Round-13: the quote-aware tokenizer's `\`-escape arm (an escaped
    /// quote inside a quoted option value must NOT close the quote) has no
    /// direct coverage — a hand-edited file like
    /// `command="echo \"hi\"" ssh-ed25519 ...` must still yield the key.
    #[test]
    fn test_parse_authorized_key_line_backslash_escaped_quotes() {
        use russh::keys::PublicKeyBase64;

        let key1 =
            russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519)
                .unwrap();
        let k1_b64 = key1.public_key().public_key_base64();
        let expected1 = russh::keys::parse_public_key_base64(&k1_b64).unwrap();
        let key2 =
            russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519)
                .unwrap();
        let k2_b64 = key2.public_key().public_key_base64();

        // `\"` inside a quoted option value: the tokenizer must not close
        // the quote at the escaped `"`, so the keytype+blob pair stays
        // reachable. The SECOND line is the discriminating shape: a real
        // key material pair sits inside an unterminated quote — the
        // quote-aware parser drops the whole line, while a naive
        // whitespace tokenizer would surface it. Exactly key1 must parse.
        let parsed = parse_authorized_keys(&format!(
            "restrict,command=\"echo \\\"hi\\\"\",from=\"a b\" ssh-ed25519 {k1_b64} u@h\n\
             command=\"unterminated quote swallows ssh-ed25519 {k2_b64} u@h\n"
        ));
        assert_eq!(
            parsed,
            vec![expected1],
            "escaped quotes must not split the option token, and key material \
             inside an unterminated quote must stay dropped (got {} keys)",
            parsed.len()
        );
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
        assert!(state.run_id_to_ctl_tx.is_empty());
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
                if state.run_id_to_ctl_tx.len() == 1 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(state.run_id_to_ctl_tx.len(), 1);
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

    /// Authenticate a russh client against the test SSH listener.
    async fn auth_test_client(addr: std::net::SocketAddr) -> russh::client::Handle<TestSshClient> {
        let client_config = Arc::new(russh::client::Config::default());
        let mut client = russh::client::connect(client_config, addr, TestSshClient)
            .await
            .unwrap();
        let auth = client
            .authenticate_password("v0", "test-token")
            .await
            .unwrap();
        assert!(auth.success());
        client
    }

    #[tokio::test]
    async fn test_exec_parse_error_written_to_client_then_close() {
        // P10 + P6: an exec parse error must reach the SSH client as text,
        // then the session closes (Go writeToClient + close). Returning Err
        // from exec_request would drop the text — the write is queued via
        // Handle::data and flushed only after exec_request returns Ok.
        let (addr, state, listener_task) =
            start_test_ssh_listener(std::time::Duration::from_secs(2)).await;
        let client = auth_test_client(addr).await;
        let mut channel = client.channel_open_session().await.unwrap();
        channel.exec(true, "tcp --bogus_flag value").await.unwrap();
        let mut reader = channel.make_reader();
        let mut text = String::new();
        use tokio::io::AsyncReadExt;
        // The session disconnects after the text, so the read ends at EOF.
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            reader.read_to_string(&mut text),
        )
        .await;
        assert!(
            text.contains("unknown flag: --bogus_flag"),
            "parse error must be written to the client, got: {text:?}"
        );
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
    async fn test_exec_success_writes_banner_and_keeps_session_open() {
        // P6: a successful registration writes the Go createSuccessInfo
        // banner ("Ctrl+C to quit") to the client and KEEPS the session
        // open — the tunnel serves until the client leaves. (The old code
        // wrote nothing and returned immediately.)
        let (addr, state, listener_task) =
            start_test_ssh_listener(std::time::Duration::from_secs(2)).await;
        let client = auth_test_client(addr).await;
        let mut channel = client.channel_open_session().await.unwrap();
        channel
            .exec(true, "tcp --proxy_name e2e-web --remote_port 0")
            .await
            .unwrap();
        let mut reader = channel.make_reader();
        let mut got = String::new();
        let mut buf = [0u8; 256];
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        use tokio::io::AsyncReadExt;
        loop {
            if got.contains("RemoteAddress: :") {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "banner not received within 5s, got so far: {got:?}"
            );
            let n =
                tokio::time::timeout(std::time::Duration::from_millis(500), reader.read(&mut buf))
                    .await
                    .expect("reading the exec channel must not stall")
                    .unwrap();
            if n == 0 {
                panic!("exec channel closed before the banner arrived; got: {got:?}");
            }
            got.push_str(std::str::from_utf8(&buf[..n]).unwrap());
        }
        assert!(
            got.contains("\nfrp (via SSH) (Ctrl+C to quit)\n"),
            "{got:?}"
        );
        assert!(got.contains("User: v0\n"), "{got:?}");
        assert!(got.contains("ProxyName: e2e-web\n"), "{got:?}");
        assert!(got.contains("Type: tcp\n"), "{got:?}");

        // The session stays open after the banner (no server disconnect).
        assert!(
            !client.is_closed(),
            "session must stay open after the banner"
        );
        // Dropping the Handle does not close the connection — russh keeps
        // the client task until an explicit disconnect (the integration-test
        // idiom). Without it the server session never ends and the
        // conn_semaphore permit below is never released.
        client
            .disconnect(russh::Disconnect::ByApplication, "test complete", "")
            .await
            .ok();
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
    async fn test_control_exit_terminates_session_and_releases_permit() {
        // Regression (M6): when the SSH virtual control handler exits — the
        // server's heartbeat-timeout cleanup kills it because the SSH
        // virtual client never sends Ping — the russh session must be torn
        // down deterministically. Before the fix the session stayed open,
        // holding the SSH fd + conn_semaphore permit and silently dropping
        // every later -R tcpip-forward work conn. Here the shutdown token
        // drives the control handler down the same exit path (break ->
        // cleanup) as a heartbeat timeout.
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
                if state.run_id_to_ctl_tx.len() == 1 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(state.run_id_to_ctl_tx.len(), 1);
        assert_eq!(
            state.conn_semaphore.as_ref().unwrap().available_permits(),
            0
        );

        // Kill the control handler the same way a heartbeat timeout does.
        state.shutdown_token.cancel();

        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while !client.is_closed() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("SSH session must be terminated when the control handler exits");
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
        assert!(state.run_id_to_ctl_tx.is_empty());
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
                if state.run_id_to_ctl_tx.len() == 1 {
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
    fn test_parse_ssh_args_missing_name_gets_default_ssh_tunnel_name() {
        // Go parity: an SSH-mode proxy without --proxy_name registers under
        // `sshtunnel-{type}-{8 lowercase hex}` (pkg/ssh server.go), not the
        // empty string.
        let args = parse_ssh_args("tcp --remote_port 9090").unwrap();
        assert!(args.proxy_name.starts_with("sshtunnel-tcp-"));
        let suffix = &args.proxy_name["sshtunnel-tcp-".len()..];
        assert_eq!(suffix.len(), 8);
        assert!(
            suffix
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "random suffix must be 8 lowercase hex chars, got: {suffix}"
        );
    }

    #[test]
    fn test_parse_ssh_args_default_name_per_type_and_explicit_override() {
        for (cmd, prefix) in [
            ("http --custom_domains a.example.com", "sshtunnel-http-"),
            ("stcp", "sshtunnel-stcp-"),
            ("tcpmux", "sshtunnel-tcpmux-"),
        ] {
            let args = parse_ssh_args(cmd).unwrap();
            assert!(
                args.proxy_name.starts_with(prefix),
                "cmd {cmd:?} → {}",
                args.proxy_name
            );
        }
        // Explicit names still win (including the --proxy_name=value form).
        let args = parse_ssh_args("tcp --proxy_name=web").unwrap();
        assert_eq!(args.proxy_name, "web");
        // And an explicitly empty name falls back to the default.
        let args = parse_ssh_args("tcp --proxy_name=").unwrap();
        assert!(args.proxy_name.starts_with("sshtunnel-tcp-"));
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

    // ── Malformed exec input hardening (Go frp v0.70.1: SSH gateway panic fix) ──
    // Go frp v0.70.1 fixed a panic when handling malformed exec requests
    // (pkg/ssh gateway indexing into an empty fields() slice). frp-rs parses
    // the SSH remote command in parse_ssh_args; every case below must be
    // tolerated without panicking (no unwrap, no index out of bounds) and
    // either rejected with an error or defaulted as documented.

    #[test]
    fn test_parse_ssh_args_truncated_flags_no_panic() {
        // Flag at end of command with no value.
        let args = parse_ssh_args("tcp --proxy_name web --sk").unwrap();
        assert_eq!(args.proxy_type, "tcp");
        assert_eq!(args.proxy_name, "web");
        assert!(args.sk.is_empty());

        // A run of value-requiring flags with no values at all.
        let args = parse_ssh_args("tcp --sk --group_key --http_pwd --remote_port").unwrap();
        assert_eq!(args.remote_port, 0);
        assert!(args.sk.is_empty());
        assert!(args.group_key.is_empty());
        assert!(args.http_pwd.is_empty());

        // Flag immediately after the type, nothing else — the truncated
        // value is tolerated (see parse_long_flag) and the empty name gets
        // the default.
        let args = parse_ssh_args("tcp --proxy_name").unwrap();
        assert!(args.proxy_name.starts_with("sshtunnel-tcp-"));
    }

    #[test]
    fn test_parse_ssh_args_invalid_ports_rejected() {
        // P10: Go parity — a value that fails to parse is an error written
        // to the SSH client, not a silent fallback to 0/auto-assign (which
        // could hand out an unintended random port).
        for bad in [
            "abc",
            "-1",
            "65536",
            "999999999",
            "3.14",
            "0x10",
            "12a34",
            "18446744073709551616", // overflows u64, let alone u16
        ] {
            let cmd = format!("tcp --proxy_name web --remote_port {bad}");
            let err = parse_ssh_args(&cmd).unwrap_err();
            let expected = format!("invalid argument \"{bad}\" for \"-r, --remote_port\" flag");
            assert!(
                err.contains(&expected),
                "cmd {cmd:?} must be rejected with {expected:?}, got: {err}"
            );
        }
        // An explicitly empty value is rejected too (Go runs strconv on it).
        let err = parse_ssh_args("tcp --remote_port=").unwrap_err();
        assert!(
            err.contains("invalid argument \"\" for \"-r, --remote_port\" flag"),
            "got: {err}"
        );
        // A truncated flag (no value at all) still tolerates → 0: the
        // deliberate truncation divergence, pinned by
        // test_parse_ssh_args_truncated_flags_no_panic.
        let args = parse_ssh_args("tcp --proxy_name web --remote_port").unwrap();
        assert_eq!(args.remote_port, 0);
    }

    #[test]
    fn test_parse_ssh_args_invalid_local_port_rejected() {
        let err = parse_ssh_args("tcp --proxy_name web --local_port not-a-port").unwrap_err();
        assert!(
            err.contains("invalid argument \"not-a-port\" for \"--local_port\" flag"),
            "got: {err}"
        );
    }

    #[test]
    fn test_parse_ssh_args_empty_or_blank_command_is_error() {
        for cmd in ["", "   ", "\t", " \n "] {
            let err = parse_ssh_args(cmd).unwrap_err();
            assert!(
                err.contains("missing proxy type"),
                "cmd {cmd:?} should be rejected, got: {err}"
            );
        }
    }

    #[test]
    fn test_parse_ssh_args_unterminated_quote_no_panic() {
        // Unterminated double quote: shell_split keeps the remainder as one
        // token and the parse loop skips the unknown positional.
        let args = parse_ssh_args(r#"tcp --proxy_name "web --remote_port 9090"#).unwrap();
        assert_eq!(args.proxy_type, "tcp");
        assert_eq!(args.remote_port, 0);
    }

    #[test]
    fn test_parse_ssh_args_excessive_whitespace_no_panic() {
        let args =
            parse_ssh_args("   tcp      --proxy_name    web     --remote_port       9090   ")
                .unwrap();
        assert_eq!(args.proxy_type, "tcp");
        assert_eq!(args.proxy_name, "web");
        assert_eq!(args.remote_port, 9090);
    }

    #[test]
    fn test_parse_ssh_args_very_long_argument_no_panic() {
        let long = "x".repeat(1_000_000);
        let cmd = format!("tcp --proxy_name {long} --remote_port 9090");
        let args = parse_ssh_args(&cmd).unwrap();
        assert_eq!(args.proxy_name.len(), 1_000_000);
        assert_eq!(args.remote_port, 9090);
    }

    #[test]
    fn test_parse_ssh_args_unknown_flag_rejected() {
        // P10: unknown flags are rejected with pflag's text instead of being
        // silently skipped — a typo'd flag used to register a proxy missing
        // that setting, with no error anywhere.
        let err = parse_ssh_args("tcp --bogus_flag value --proxy_name web").unwrap_err();
        assert_eq!(err, "unknown flag: --bogus_flag");
        // Dash-form unknowns keep their raw spelling in the message.
        let err = parse_ssh_args("tcp --bogus-flag value").unwrap_err();
        assert_eq!(err, "unknown flag: --bogus-flag");
    }

    #[test]
    fn test_parse_ssh_args_unknown_shorthand_rejected() {
        let err = parse_ssh_args("tcp -x").unwrap_err();
        assert_eq!(err, "unknown shorthand flag: 'x' in -x");
        // pflag reports the full remaining cluster, unknown char included
        // (parseSingleShortArg: `in -%s` gets the unconsumed shorthands).
        let err = parse_ssh_args("tcp -xn").unwrap_err();
        assert_eq!(err, "unknown shorthand flag: 'x' in -xn");
    }

    #[test]
    fn test_parse_ssh_args_flag_equals_value_forms() {
        let args =
            parse_ssh_args("tcp --proxy_name=web --remote_port=9090 --custom_domains=a.com,b.com")
                .unwrap();
        assert_eq!(args.proxy_name, "web");
        assert_eq!(args.remote_port, 9090);
        assert_eq!(args.custom_domains, vec!["a.com", "b.com"]);
        let args =
            parse_ssh_args("http --proxy_name=blog --use_encryption=true --subdomain=sub").unwrap();
        assert!(args.use_encryption);
        assert_eq!(args.subdomain, "sub");
        // The legacy --custom_domain alias works in both forms.
        let args = parse_ssh_args("http --custom_domain=a.example.com").unwrap();
        assert_eq!(args.custom_domains, vec!["a.example.com"]);
    }

    #[test]
    fn test_parse_ssh_args_dash_underscore_equivalence() {
        // pflag WordSepNormalizeFunc intent: --proxy_name and --proxy-name
        // are the same flag.
        let a = parse_ssh_args("tcp --proxy_name web --remote_port 9090").unwrap();
        let b = parse_ssh_args("tcp --proxy-name web --remote-port 9090").unwrap();
        assert_eq!(a, b);
        // The dash+`=` form is the same flag too (a includes --remote_port,
        // so the comparison parse must too).
        let c = parse_ssh_args("tcp --proxy-name=web --remote-port=9090").unwrap();
        assert_eq!(c, a);
    }

    #[test]
    fn test_parse_ssh_args_shorthand_forms() {
        // pflag shorthand value forms: `-n web`, `-n=web`, `-nweb`.
        let a = parse_ssh_args("tcp -n web -r 9090").unwrap();
        assert_eq!(a.proxy_name, "web");
        assert_eq!(a.remote_port, 9090);
        let b = parse_ssh_args("tcp -n=web -r=9090").unwrap();
        assert_eq!(b, a);
        let c = parse_ssh_args("tcp -nweb -r9090").unwrap();
        assert_eq!(c, a);
        // -d maps to custom_domains (Go shorthand).
        let d = parse_ssh_args("http -d a.com,b.com").unwrap();
        assert_eq!(d.custom_domains, vec!["a.com", "b.com"]);
        // A truncated shorthand stays at its default (name → default name).
        let e = parse_ssh_args("tcp -r").unwrap();
        assert_eq!(e.remote_port, 0);
        assert!(e.proxy_name.starts_with("sshtunnel-tcp-"));
    }

    #[test]
    fn test_parse_ssh_args_help_returns_usage() {
        // Go frp prints the command usage to the SSH client on ErrHelp
        // (--help / -h) and closes — the frp-rs equivalent returns the usage
        // text as the parse error.
        for cmd in [
            "tcp --help",
            "tcp -h",
            "http --proxy_name web --help",
            "stcp -h",
        ] {
            let err = parse_ssh_args(cmd).unwrap_err();
            assert!(
                err.contains("Usage:"),
                "cmd {cmd:?} must yield usage text, got: {err}"
            );
            assert!(err.contains("--proxy_name"), "cmd {cmd:?}");
        }
    }

    #[test]
    fn test_parse_ssh_args_bad_flag_syntax_rejected() {
        // pflag "bad flag syntax": a flag name starting with '-' or '=' is a
        // syntax error (`---x` names "-x"); a bare `--` is the terminator,
        // not an error (asserted in test_parse_ssh_args_double_dash...).
        for tok in ["---x", "--=x"] {
            let err = parse_ssh_args(&format!("tcp {tok}")).unwrap_err();
            assert_eq!(err, format!("bad flag syntax: {tok}"), "token {tok:?}");
        }
    }

    #[test]
    fn test_parse_ssh_args_double_dash_terminates_flags() {
        // pflag `--`: everything after it is positional and ignored. A bare
        // trailing `--` is legal (Go pflag terminates, no "bad flag syntax").
        let args = parse_ssh_args("tcp --proxy_name web -- --remote_port 9090").unwrap();
        assert_eq!(args.proxy_name, "web");
        assert_eq!(args.remote_port, 0);
        let args = parse_ssh_args("tcp --").unwrap();
        assert!(args.proxy_name.starts_with("sshtunnel-tcp-"));
    }

    #[test]
    fn test_parse_ssh_args_boolean_flags_unchanged() {
        // Value-taking bools keep their legacy grammar ("true"/"1") and gain
        // the = form.
        let args = parse_ssh_args("tcp --use_encryption true --use_compression=1").unwrap();
        assert!(args.use_encryption && args.use_compression);
        let args = parse_ssh_args("tcp --use_encryption false").unwrap();
        assert!(!args.use_encryption);
        // A bare bool followed by another flag stays false (truncation
        // tolerance — Go/pflag would swallow "--sk" as the bool's value).
        let args = parse_ssh_args("tcp --use_encryption --sk s").unwrap();
        assert!(!args.use_encryption);
        assert_eq!(args.sk, "s");
    }

    #[test]
    fn test_parse_ssh_args_truncated_boolean_and_list_flags() {
        let args = parse_ssh_args(
            "http --proxy_name blog --use_encryption --custom_domains --locations --group",
        )
        .unwrap();
        assert!(!args.use_encryption);
        assert!(args.custom_domains.is_empty());
        assert!(args.locations.is_empty());
        assert!(args.group.is_empty());
    }

    #[test]
    fn build_v1_frame_rejects_oversized_proxy_config() {
        // Audit finding 6e: a giant custom_domains entry (attacker's own
        // `ssh -R` command line, bounded only by the ~32 KiB SSH channel
        // window) used to build a >10 KiB V1 frame by hand, bypassing
        // write_v1_frame's length check and killing the SSH user's own
        // virtual control on read_v1_frame's "invalid V1 msg length".
        let long_domain = format!("{}.example.com", "x".repeat(20_000));
        let args = parse_ssh_args(&format!(
            "http --proxy_name h --custom_domains {long_domain}"
        ))
        .expect("parse oversized domain");
        let err = build_v1_frame_from_args(&args, 0)
            .expect_err("oversized proxy config must be rejected before framing");
        assert!(
            err.to_string().contains("too large"),
            "unexpected error: {err}"
        );

        // Control: a normal frame still builds and carries the V1 header
        // (type byte + declared payload length must match the frame size).
        let small = parse_ssh_args("tcp --proxy_name web --remote_port 9090").expect("parse small");
        let frame = build_v1_frame_from_args(&small, 9090).expect("small frame builds");
        assert_eq!(frame[0], frp_core::msg::TYPE_NEW_PROXY);
        let declared = i64::from_be_bytes(frame[1..9].try_into().expect("9-byte header")) as usize;
        assert!(declared <= frp_core::protocol::V1_MAX_MSG_LENGTH as usize);
        assert_eq!(frame.len(), 9 + declared);
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
    /// Authenticated-session idle timeout in seconds. 0 = disabled (default,
    /// Go frp parity — Go has no SSH idle timeout). Wired from
    /// `SshTunnelGatewayConfig.ssh_session_idle_timeout`.
    ssh_session_idle_timeout: u64,
}

/// Parse an authorized_keys file body into the gateway's allow-list.
///
/// Line grammar is OpenSSH's: `[options] keytype base64key [comment]` with
/// the keytype/base64 pair required. Options may hold quoted values with
/// embedded spaces or commas (`from="1.2.3.4, 5.6.7.8"`,
/// `command="echo hi"`), so locating the keytype needs a quote-aware
/// token scan: a token is a maximal run of characters outside double
/// quotes, and the FIRST adjacent `(t1, t2)` pair whose `t2` base64-
/// decodes to a key wins. Option tokens cannot produce a false pair —
/// they contain `=` or `,` (never true of a keytype) or are bare words
/// whose neighbor fails to decode. Each line is trimmed; blank lines and
/// `#` comments are skipped; a line with no parseable pair is dropped.
///
/// Certificate entries (`*-cert-v01@openssh.com` keytypes) are DROPPED
/// whole even when the blob decodes: frp-rs compares raw client public
/// keys against this list and has no CA trust store, so a cert line
/// cannot be honored with Go's certificate semantics — accepting the
/// embedded raw key without any CA validation would be worse than
/// dropping the line. Go `ssh.ParseAuthorizedKey` accepts cert entries
/// and validates them at auth time.
///
/// DELIBERATE DIVERGENCE from Go frp v0.71.0 (pkg/ssh/gateway.go
/// `loadAuthorizedKeysFromFile`): Go aborts on the FIRST line that fails
/// `ssh.ParseAuthorizedKey` (`return nil, err` → PublicKeyCallback answers
/// every pubkey attempt with "internal error" — fail-closed), so one
/// malformed line voids the whole file. frp-rs drops only the bad line and
/// keeps the rest. Also note Go re-reads the file on EVERY auth attempt,
/// while frp-rs caches it once at `SshListener::new` (load-once).
///
/// The leading `type` field is NOT cross-checked against the decoded key
/// (the blob itself carries the type); OpenSSH authorized_keys files with
/// a wrong-but-parseable type field are still accepted, mirroring the
/// russh decode used here — EXCEPT cert keytypes, which are dropped whole
/// (above).
///
/// Behavior-preserving extraction of the SshListener::new inline parse —
/// unit-tested (audit round-11 GAP5); options-prefix + cert-line handling
/// added in audit round-12 (A2/D6: the old parts[1]-as-base64 reader
/// silently dropped every options-prefixed line, and would have accepted
/// a cert anchor's embedded raw key with zero CA validation).
fn parse_authorized_keys(content: &str) -> Vec<russh::keys::PublicKey> {
    content
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(parse_authorized_key_line)
        .collect()
}

/// Parse one non-empty, non-comment authorized_keys line. `None` when the
/// line holds no supported key (bad line → dropped, per-line divergence;
/// cert-typed anchors → dropped whole; see `parse_authorized_keys`).
fn parse_authorized_key_line(line: &str) -> Option<russh::keys::PublicKey> {
    // Quote-aware tokenization with `\`-escape handling inside quotes, so
    // `from="a b,c",command="echo \"hi\""` tokens stay whole. Cheap: a
    // single pass, one small Vec, never more tokens than the line has
    // words — an authorized_keys line is operator-sized.
    let mut tokens: Vec<&str> = Vec::with_capacity(4);
    let mut start = None;
    let mut in_quote = false;
    let mut escaped = false;
    for (i, &b) in line.as_bytes().iter().enumerate() {
        if in_quote {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_quote = false;
            }
            continue;
        }
        match b {
            b'"' => in_quote = true,
            b if b.is_ascii_whitespace() => {
                if let Some(s) = start.take() {
                    tokens.push(&line[s..i]);
                }
            }
            _ => {
                if start.is_none() {
                    start = Some(i);
                }
            }
        }
    }
    if let Some(s) = start {
        tokens.push(&line[s..]);
    }
    for pair in tokens.windows(2) {
        // Certificate anchors are dropped whole, before any decode.
        if pair[0].contains("-cert-v01@") {
            return None;
        }
        // Option tokens contain '=' or ',' — a keytype never does.
        if pair[0].contains(['=', ',']) {
            continue;
        }
        // Bare option words (e.g. `restrict`, `no-port-forwarding`)
        // reach here; their neighbor is the keytype and fails to
        // decode, so the scan falls through to the real pair.
        if let Ok(key) = russh::keys::parse_public_key_base64(pair[1]) {
            return Some(key);
        }
    }
    None
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
                let sem = per_ip_preauth
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
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
    let mut rng = rand::rng();
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
        let mut rng = rand::rng();
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
        let (mut vc, tx, _work_rx, _resp_rx, phase2) = VirtualControl::channel(enc_key);
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
        let (mut vc, tx, _work_rx, _resp_rx, phase2) = VirtualControl::channel(enc_key);

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

    #[tokio::test]
    async fn test_virtual_control_routes_new_proxy_resp_to_session() {
        // P6: NewProxyResp frames from the control handler must reach the
        // session's resp receiver so exec_request can wait on registration
        // (Go waitProxyStatusReady) — every non-ReqWorkConn frame used to be
        // silently dropped, leaving exec_request blind to register failures.
        use frp_core::cipher_stream::CipherStream;
        use tokio::io::AsyncWriteExt;
        let enc_key = frp_core::encryption::derive_key("test-token");
        let (mut vc, tx, _work_rx, mut resp_rx, phase2) = VirtualControl::channel(enc_key);
        feed_login_resp(&mut vc, phase2).await;

        // Simulate the control handler's side: wrap our end of the duplex in
        // a CipherStream (same key, same plaintext-first discipline) and
        // write an encrypted NewProxyResp frame, exactly as handle_control's
        // write_resp does after registering a proxy.
        let mut control_side = CipherStream::new(vc, enc_key).expect("rng");
        let msg = FrpMessage::NewProxyResp(NewProxyResp {
            proxy_name: "web".into(),
            remote_addr: Some(":9090".into()),
            error: None,
        });
        let payload = serde_json::to_vec(&msg).unwrap();
        let mut frame = Vec::with_capacity(9 + payload.len());
        frame.push(frp_core::msg::TYPE_NEW_PROXY_RESP);
        frame.extend_from_slice(&(payload.len() as i64).to_be_bytes());
        frame.extend_from_slice(&payload);
        control_side.write_all(&frame).await.unwrap();

        let resp = tokio::time::timeout(std::time::Duration::from_secs(1), resp_rx.recv())
            .await
            .expect("NewProxyResp must reach the session resp receiver")
            .expect("resp channel must stay open");
        assert_eq!(resp.proxy_name, "web");
        assert_eq!(resp.remote_addr.as_deref(), Some(":9090"));
        assert!(resp.error.is_none());

        // The error arm flows too (a rejected registration reports the
        // server's text verbatim).
        let msg = FrpMessage::NewProxyResp(NewProxyResp {
            proxy_name: "web".into(),
            remote_addr: None,
            error: Some("port already used".into()),
        });
        let payload = serde_json::to_vec(&msg).unwrap();
        let mut frame = Vec::with_capacity(9 + payload.len());
        frame.push(frp_core::msg::TYPE_NEW_PROXY_RESP);
        frame.extend_from_slice(&(payload.len() as i64).to_be_bytes());
        frame.extend_from_slice(&payload);
        control_side.write_all(&frame).await.unwrap();
        let resp = tokio::time::timeout(std::time::Duration::from_secs(1), resp_rx.recv())
            .await
            .expect("second NewProxyResp must arrive")
            .expect("resp channel must stay open");
        assert_eq!(resp.proxy_name, "web");
        assert_eq!(resp.error.as_deref(), Some("port already used"));

        // ReqWorkConn interception still works alongside (regression guard
        // for the load-bearing read-task behavior).
        let (mut vc2, tx2, mut work_rx, _resp_rx2, phase2_2) = VirtualControl::channel(enc_key);
        feed_login_resp(&mut vc2, phase2_2).await;
        let mut control2 = CipherStream::new(vc2, enc_key).expect("rng");
        let req_frame = vec![frp_core::msg::TYPE_REQ_WORK_CONN, 0, 0, 0, 0, 0, 0, 0, 0];
        control2.write_all(&req_frame).await.unwrap();
        let req = tokio::time::timeout(std::time::Duration::from_secs(1), work_rx.recv())
            .await
            .expect("ReqWorkConn must still be intercepted")
            .expect("work channel must stay open");
        assert!(req.proxy_name.is_empty());
        let _ = tx;
        let _ = tx2;
    }
}
