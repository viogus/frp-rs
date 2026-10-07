//! Virtual control channel: an in-memory duplex bridging the SSH session to
//! the control handler (`handle_control`), with V1 frame encryption.
//!
//! Split out of `ssh_gateway.rs` as a pure text move; the parent re-exports
//! `VirtualControl`/`WorkConnRequest` for its session handler and the sibling
//! `virtual_ctrl_tests` module.

use frp_core::msg::NewProxyResp;
use tokio::sync::mpsc;

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
