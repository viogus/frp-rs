use std::sync::Arc;
use std::time::Duration;

use tokio::sync::oneshot;
use tracing::{debug, info, instrument, warn};

use frp_core::msg::{self, FrpMessage};
use frp_core::protocol::write_msg;
use frp_core::transport::IoStream;

use crate::control;
use crate::lock::RwLockExt;
use crate::nathole::controller as nathole_ctrl;
use crate::nathole::{classify, NAT_HOLE_TIMEOUT};
use crate::state::{AppState, InternalMsg};

// ---------------------------------------------------------------
// STCP visitor connection handler
// ---------------------------------------------------------------

/// Handle an incoming STCP NewVisitorConn on the main accept port.
///
/// Supports two auth modes:
/// 1. Go-compatible: sign_key = MD5(proxy.sk + timestamp), lookup by proxy_name
///    then validate the hash against the registered sk.
/// 2. Legacy Rust: sign_key = raw sk value, looked up directly in sk_index.
pub(crate) async fn handle_visitor_conn_inner(
    mut stream: IoStream,
    msg: msg::NewVisitorConn,
    state: Arc<AppState>,
    v2: bool,
) {
    let sign_key = msg.sign_key.unwrap_or_default();
    let timestamp = msg.timestamp.unwrap_or(0);

    // Validate timestamp freshness to prevent replay attacks.
    // Uses the same authentication_timeout as control-channel Login
    // (Go frp compat: authentication_timeout config).
    let auth_timeout = state.reloadable.read_ok().auth_cfg.authentication_timeout;
    let ts_valid = frp_core::auth::validate_timestamp_freshness(timestamp, auth_timeout);

                    None
                } else if ts_valid.is_err() {
                    warn!(proxy_name = %msg.proxy_name, error = %ts_valid.as_ref().unwrap_err(), "STCP visitor: timestamp rejected for proxy '{}'", msg.proxy_name);
                    None
                } else if frp_core::auth::verify_token(sk, timestamp, &sign_key) {
                    debug!(proxy_name = %msg.proxy_name, "STCP visitor auth OK (Go-compat MD5, constant-time) for proxy '{}'", msg.proxy_name);
                    Some(msg.proxy_name.clone())
                } else {
                    warn!(proxy_name = %msg.proxy_name, "STCP visitor MD5 auth mismatch for proxy '{}'", msg.proxy_name);