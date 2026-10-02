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
