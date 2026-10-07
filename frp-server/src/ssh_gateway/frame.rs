//! Build V1 `NewProxy` frames from parsed SSH command args, plus the exec-
//! request logging helpers.
//!
//! Split out of `ssh_gateway.rs` as a pure text move; the parent re-imports
//! `build_v1_frame_from_args`/`log_exec_request` for its `exec_request` arm.

use anyhow::anyhow;
use frp_core::msg::{FrpMessage, NewProxy};

use super::ParsedProxyArgs;

/// Build a V1 frame from a parsed SSH command and allocated port.
pub(super) fn build_v1_frame_from_args(
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
        allow_users: non_empty_vec(args.allow_users.clone()),
        // Bandwidth fields are intentionally NOT wired: Go SSH mode does not
        // register the flags (see the FLAG_SPELLINGS doc), so no parsed arg
        // can ever reach them — frp-rs SSH-registered proxies are always
        // unlimited, exactly like Go's (Go omits nil bandwidth_limit fields
        // from the NewProxy message entirely).
        bandwidth_limit: None,
        bandwidth_limit_mode: None,
        annotations: pairs_to_map(&args.annotations),
        metas: pairs_to_map(&args.metadatas),
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
pub(super) fn exec_request_log_summary(args: &ParsedProxyArgs) -> String {
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
pub(super) fn log_exec_request(run_id: &str, args: &ParsedProxyArgs) {
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

/// Map accumulated `--metadatas`/`--annotations` k=v pairs (last-wins per
/// key, insertion order preserved) to the NewProxy wire map. None when no
/// pair was parsed — the field is then skipped on the wire like Go's
/// nil map.
fn pairs_to_map(pairs: &[(String, String)]) -> Option<std::collections::HashMap<String, String>> {
    if pairs.is_empty() {
        None
    } else {
        Some(pairs.iter().cloned().collect())
    }
}
