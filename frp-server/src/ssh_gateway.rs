//! SSH Tunnel Gateway — `ssh -R` reverse tunnel → frp proxy.
//!
//! Users connect with a standard SSH client:
//!   ssh -R :80:127.0.0.1:8080 v0@server -p 2200 tcp --proxy_name "web" --remote_port 9090
//!
//! The remote command string is parsed into a ProxyConfig.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use frp_core::config::ProxyConfig;
use frp_core::msg::TYPE_REQ_WORK_CONN;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;

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
            proxy_type, VALID_PROXY_TYPES.join(", ")
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
            "--proxy_name" => { i += 1; args.proxy_name = parts.get(i).cloned().unwrap_or_default(); }
            "--remote_port" => { i += 1; args.remote_port = parts.get(i).and_then(|s| s.parse().ok()).unwrap_or(0); }
            "--local_ip" => { i += 1; args.local_ip = parts.get(i).cloned().unwrap_or_default(); }
            "--local_port" => { i += 1; args.local_port = parts.get(i).and_then(|s| s.parse().ok()).unwrap_or(0); }
            "--custom_domains" | "--custom_domain" => { i += 1; args.custom_domains = parts.get(i).map(|s| s.split(',').map(|d| d.trim().to_string()).collect()).unwrap_or_default(); }
            "--subdomain" => { i += 1; args.subdomain = parts.get(i).cloned().unwrap_or_default(); }
            "--sk" => { i += 1; args.sk = parts.get(i).cloned().unwrap_or_default(); }
            "--multiplexer" => { i += 1; args.multiplexer = parts.get(i).cloned().unwrap_or_default(); }
            "--use_encryption" => { i += 1; args.use_encryption = parts.get(i).map(|s| s == "true" || s == "1").unwrap_or(false); }
            "--use_compression" => { i += 1; args.use_compression = parts.get(i).map(|s| s == "true" || s == "1").unwrap_or(false); }
            "--group" => { i += 1; args.group = parts.get(i).cloned().unwrap_or_default(); }
            "--group_key" => { i += 1; args.group_key = parts.get(i).cloned().unwrap_or_default(); }
            "--http_user" => { i += 1; args.http_user = parts.get(i).cloned().unwrap_or_default(); }
            "--http_pwd" => { i += 1; args.http_pwd = parts.get(i).cloned().unwrap_or_default(); }
            "--host_header_rewrite" => { i += 1; args.host_header_rewrite = parts.get(i).cloned().unwrap_or_default(); }
            "--locations" => { i += 1; args.locations = parts.get(i).map(|s| s.split(',').map(|d| d.trim().to_string()).collect()).unwrap_or_default(); }
            "--bandwidth_limit" => { i += 1; args.bandwidth_limit = parts.get(i).cloned().unwrap_or_default(); }
            "--bandwidth_limit_mode" => { i += 1; args.bandwidth_limit_mode = parts.get(i).cloned().unwrap_or_default(); }
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

/// Virtual control channel — an mpsc-based AsyncRead + AsyncWrite pair
/// that implements the FRP V1 protocol over channels instead of TCP.
///
/// The read side receives V1-encoded messages pushed from the SSH session
/// (e.g., NewProxy). The write side intercepts ReqWorkConn messages and
/// forwards them as WorkConnRequest to the SSH session.
pub struct VirtualControl {
    /// Inbound V1 frames from SSH session → read by handle_control().
    rx: mpsc::UnboundedReceiver<Vec<u8>>,
    /// Outbound work connection requests to SSH session.
    work_req_tx: mpsc::UnboundedSender<WorkConnRequest>,
    /// Write buffer for partial V1 frame assembly.
    write_buf: Vec<u8>,
    write_pos: usize,
}

/// A request from the control handler to the SSH session to open a
/// reverse-forward channel for a work connection.
#[derive(Debug)]
pub struct WorkConnRequest {
    pub proxy_name: String,
}

impl VirtualControl {
    pub fn new(
        rx: mpsc::UnboundedReceiver<Vec<u8>>,
        work_req_tx: mpsc::UnboundedSender<WorkConnRequest>,
    ) -> Self {
        Self {
            rx,
            work_req_tx,
            write_buf: Vec::new(),
            write_pos: 0,
        }
    }

    /// Create a paired (VirtualControl, tx, work_rx) where tx is the sender
    /// that the SSH session writes V1 frames into.
    pub fn channel() -> (Self, mpsc::UnboundedSender<Vec<u8>>, mpsc::UnboundedReceiver<WorkConnRequest>) {
        let (frame_tx, frame_rx) = mpsc::unbounded_channel();
        let (work_tx, work_rx) = mpsc::unbounded_channel();
        (Self::new(frame_rx, work_tx), frame_tx, work_rx)
    }
}

impl AsyncRead for VirtualControl {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // If we have buffered data from a previous frame, drain it first
        if self.write_pos < self.write_buf.len() {
            let available = &self.write_buf[self.write_pos..];
            let len = available.len().min(buf.remaining());
            buf.put_slice(&available[..len]);
            self.write_pos += len;
            if self.write_pos >= self.write_buf.len() {
                self.write_buf.clear();
                self.write_pos = 0;
            }
            return Poll::Ready(Ok(()));
        }

        // Poll the mpsc receiver for the next V1 frame
        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(frame)) => {
                let len = frame.len().min(buf.remaining());
                buf.put_slice(&frame[..len]);
                if len < frame.len() {
                    self.write_buf = frame;
                    self.write_pos = len;
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => {
                // Channel closed — EOF
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for VirtualControl {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // Accumulate bytes. When we have a complete V1 frame, check if it's
        // a ReqWorkConn. If so, intercept and send WorkConnRequest.
        // Otherwise, consume and ignore (heartbeats, ping responses, etc.).
        //
        // V1 frame: 1-byte type + 8-byte BE length + payload

        const HEADER_LEN: usize = 9;

        self.write_buf.extend_from_slice(buf);

        // Try to parse complete frames from the buffer
        while self.write_buf.len() >= HEADER_LEN {
            let payload_len = i64::from_be_bytes([
                self.write_buf[1], self.write_buf[2], self.write_buf[3],
                self.write_buf[4], self.write_buf[5], self.write_buf[6],
                self.write_buf[7], self.write_buf[8],
            ]) as usize;

            // Guard against excessive payload length (max V1 frame is 64KB)
            if payload_len > 65536 {
                // Corrupt frame — clear buffer to recover
                self.write_buf.clear();
                break;
            }

            if self.write_buf.len() < HEADER_LEN + payload_len {
                // Incomplete frame — wait for more bytes
                break;
            }

            // We have a complete frame
            let msg_type = self.write_buf[0];

            if msg_type == TYPE_REQ_WORK_CONN {
                // Intercept: send WorkConnRequest instead of writing to wire
                // ReqWorkConn has no fields — the control handler just needs
                // any ReqWorkConn to trigger work connection creation.
                let _ = self.work_req_tx.send(WorkConnRequest {
                    proxy_name: String::new(),
                });
            }
            // For all other message types (Pong, NewProxyResp, etc.), consume and ignore.

            // Remove the consumed frame from the buffer
            let consumed = HEADER_LEN + payload_len;
            self.write_buf.drain(..consumed);
        }

        // Report all bytes as written (they were consumed)
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ssh_args_tcp() {
        let args = parse_ssh_args(r#"tcp --proxy_name "web" --remote_port 9090"#).unwrap();
        assert_eq!(args.proxy_type, "tcp");
        assert_eq!(args.proxy_name, "web");
        assert_eq!(args.remote_port, 9090);
    }

    #[test]
    fn test_parse_ssh_args_http() {
        let args = parse_ssh_args(r#"http --proxy_name "blog" --custom_domains "a.example.com,b.example.com""#).unwrap();
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
        let args = parse_ssh_args(r#"tcpmux --proxy_name "mux" --multiplexer "httpconnect""#).unwrap();
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
        assert_eq!(tokens, vec!["tcp", "--proxy_name", "web", "--remote_port", "9090"]);
    }

    #[test]
    fn test_shell_split_quoted() {
        let tokens = shell_split(r#"tcp --proxy_name "my web""#);
        assert_eq!(tokens, vec!["tcp", "--proxy_name", "my web"]);
    }
}

use std::path::Path;

/// Load or auto-generate the SSH host key.
///
/// Priority:
/// 1. `private_key_file` if set and file exists
/// 2. `auto_gen_path` if file exists
/// 3. Generate new Ed25519 key, write to `auto_gen_path`
async fn load_or_generate_host_key(
    private_key_file: &str,
    auto_gen_path: &str,
) -> Result<russh_keys::PrivateKey, String> {
    // Try explicit key file first
    if !private_key_file.is_empty() && Path::new(private_key_file).exists() {
        return russh_keys::load_secret_key(private_key_file, None)
            .map_err(|e| format!("load key file {}: {}", private_key_file, e));
    }

    // Try auto-gen path
    if Path::new(auto_gen_path).exists() {
        return russh_keys::load_secret_key(auto_gen_path, None)
            .map_err(|e| format!("load auto-gen key {}: {}", auto_gen_path, e));
    }

    // Generate new Ed25519 key
    use russh_keys::ssh_key::rand_core::OsRng;
    let key = russh_keys::PrivateKey::random(&mut OsRng, russh_keys::Algorithm::Ed25519)
        .map_err(|e| format!("generate key: {}", e))?;
    let pem = key
        .to_openssh(russh_keys::ssh_key::LineEnding::default())
        .map_err(|e| format!("serialize key: {}", e))?;

    // Write to auto-gen path
    if let Some(parent) = Path::new(auto_gen_path).parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("create dir for key: {}", e))?;
    }
    std::fs::write(auto_gen_path, pem.as_bytes())
        .map_err(|e| format!("write auto-gen key {}: {}", auto_gen_path, e))?;

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
        assert!(matches!(key.algorithm(), russh_keys::Algorithm::Ed25519));
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
        assert!(matches!(key2.algorithm(), russh_keys::Algorithm::Ed25519));
        // Same key: fingerprints should match
        use russh_keys::ssh_key::HashAlg;
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
        let explicit = russh_keys::PrivateKey::random(
            &mut russh_keys::ssh_key::rand_core::OsRng,
            russh_keys::Algorithm::Ed25519,
        )
        .unwrap();
        let pem = explicit
            .to_openssh(russh_keys::ssh_key::LineEnding::default())
            .unwrap();
        std::fs::write(&explicit_path, pem.as_bytes()).unwrap();

        // Load with explicit path set -- should use explicit, not auto
        let loaded = load_or_generate_host_key(
            explicit_path.to_str().unwrap(),
            auto_path.to_str().unwrap(),
        )
        .await
        .unwrap();

        // Both are Ed25519 -- verify they're different keys
        use russh_keys::ssh_key::HashAlg;
        let loaded_fp = loaded.public_key().fingerprint(HashAlg::Sha256);
        let auto_fp = auto.public_key().fingerprint(HashAlg::Sha256);
        assert_ne!(loaded_fp.to_string(), auto_fp.to_string());
    }
}

#[cfg(test)]
mod virtual_ctrl_tests {
    use super::*;

    /// Helper: manually encode a V1 frame (type byte + 8-byte BE i64 length + payload).
    fn encode_v1_frame(msg: &frp_core::msg::FrpMessage) -> Vec<u8> {
        let type_byte = msg.v1_type_byte();
        let payload = serde_json::to_vec(msg).unwrap();
        let mut frame = Vec::with_capacity(9 + payload.len());
        frame.push(type_byte);
        frame.extend_from_slice(&(payload.len() as i64).to_be_bytes());
        frame.extend_from_slice(&payload);
        frame
    }

    #[tokio::test]
    async fn test_virtual_control_newproxy_roundtrip() {
        use frp_core::msg::{NewProxy, FrpMessage};

        let (mut vc, tx, _work_rx) = VirtualControl::channel();

        // Build a NewProxy message as V1 bytes
        let msg = FrpMessage::NewProxy(NewProxy {
            proxy_name: "test-proxy".into(),
            proxy_type: "tcp".into(),
            use_encryption: None,
            use_compression: None,
            group: None,
            group_key: None,
            local_str: None,
            remote_port: Some(9090),
            sk: None,
            custom_domains: None,
            subdomain: None,
            locations: None,
            http_user: None,
            http_pwd: None,
            host_header_rewrite: None,
            headers: None,
            response_headers: None,
            route_by_http_user: None,
            allow_users: None,
            bandwidth_limit: None,
            bandwidth_limit_mode: None,
            annotations: None,
            metas: None,
            multiplexer: None,
            virtual_net: None,
            proxy_protocol_version: None,
        });

        let v1_buf = encode_v1_frame(&msg);

        // Push frame into the channel
        tx.send(v1_buf.clone()).unwrap();
        drop(tx); // close the sender so poll_read returns Ready(None) after the frame

        // Read it back through VirtualControl
        let mut read_buf = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            use tokio::io::AsyncReadExt;
            match vc.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => read_buf.extend_from_slice(&buf[..n]),
                Err(e) => panic!("read error: {}", e),
            }
        }

        // Verify we got the V1 frame bytes back exactly
        assert_eq!(read_buf, v1_buf, "VirtualControl should return exact V1 frame bytes");

        // Verify the frame is a valid V1 NewProxy message
        assert_eq!(read_buf[0], frp_core::msg::TYPE_NEW_PROXY, "first byte should be TYPE_NEW_PROXY");
        // Payload length (next 8 bytes BE) should match JSON body
        let payload_len = i64::from_be_bytes(read_buf[1..9].try_into().unwrap()) as usize;
        assert!(payload_len > 0);
        // Payload should contain proxy_name
        let json = std::str::from_utf8(&read_buf[9..9 + payload_len]).unwrap();
        assert!(json.contains("test-proxy"), "JSON should contain proxy_name");
        assert!(json.contains("9090"), "JSON should contain remote_port");
    }

    #[tokio::test]
    async fn test_virtual_control_intercepts_req_work_conn() {
        use frp_core::msg::{ReqWorkConn, FrpMessage};

        // Create a VirtualControl that only tests the write side
        let (_frame_tx, frame_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let (work_tx, mut work_rx) = mpsc::unbounded_channel();
        let mut vc = VirtualControl::new(frame_rx, work_tx);

        // Build a ReqWorkConn V1 frame
        let msg = FrpMessage::ReqWorkConn(ReqWorkConn {});
        let v1_buf = encode_v1_frame(&msg);

        // Verify the frame header is correct
        assert_eq!(v1_buf[0], frp_core::msg::TYPE_REQ_WORK_CONN, "type byte should be TYPE_REQ_WORK_CONN");

        // Write the ReqWorkConn frame
        use tokio::io::AsyncWriteExt;
        vc.write_all(&v1_buf).await.unwrap();

        // The write buffer should be empty (frame consumed)
        assert!(vc.write_buf.is_empty());

        // A WorkConnRequest should have been sent
        let req = work_rx.try_recv().expect("should have received WorkConnRequest");
        assert!(req.proxy_name.is_empty(), "ReqWorkConn has no proxy_name field");
    }
}
