//! Reverse-tunnel work-connection plumbing: the SSH-gateway background task
//! that turns `ReqWorkConn` signals into `forwarded-tcpip` channels, and the
//! pipe bridge that pumps data between the SSH channel and the control layer.
//!
//! Split out of `ssh_gateway.rs` as a pure text move; the parent re-imports
//! `handle_work_conn_requests` for its `auth_succeeded` arm.

use std::sync::Arc;

use tokio::sync::mpsc;

use crate::service::AppState;
use dashmap::DashMap;

use super::WorkConnRequest;

/// Background task: receives WorkConnRequest signals from VirtualControl
/// (which intercepted ReqWorkConn from the control handler). For each request,
/// opens a `forwarded-tcpip` channel back to the SSH client (Go frp's
/// virtual-client pipeConnector semantics), hands the pipe's work side to the
/// control layer as a work conn, and bridges the SSH channel with the pipe.
pub(super) async fn handle_work_conn_requests(
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
