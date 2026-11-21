use super::*;
use rand::RngExt;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

// ── test helpers ─────────────────────────────────────────────────────

/// Collects each write_all call as one packet.
#[derive(Default)]
struct PacketWriter {
    packets: Vec<Vec<u8>>,
}

impl Write for PacketWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.packets.push(data.to_vec());
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl PacketWriter {
    fn drain(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.packets)
    }
}

/// Parse the 24-byte header of one packet.
#[allow(clippy::type_complexity)]
fn parse_packet(pkt: &[u8]) -> (u32, u8, u8, u16, u32, u32, u32, Vec<u8>) {
    assert!(pkt.len() >= KCP_OVERHEAD, "packet too short");
    let conv = u32::from_le_bytes(pkt[0..4].try_into().unwrap());
    let cmd = pkt[4];
    let frg = pkt[5];
    let wnd = u16::from_le_bytes(pkt[6..8].try_into().unwrap());
    let ts = u32::from_le_bytes(pkt[8..12].try_into().unwrap());
    let sn = u32::from_le_bytes(pkt[12..16].try_into().unwrap());
    let una = u32::from_le_bytes(pkt[16..20].try_into().unwrap());
    let len = u32::from_le_bytes(pkt[20..24].try_into().unwrap()) as usize;
    assert_eq!(len, pkt.len() - KCP_OVERHEAD, "payload length mismatch");
    (
        conv,
        cmd,
        frg,
        wnd,
        ts,
        sn,
        una,
        pkt[KCP_OVERHEAD..].to_vec(),
    )
}

/// Build a PUSH segment with a 24-byte header.
fn make_push(conv: u32, sn: u32, frg: u8, ts: u32, data: &[u8]) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(KCP_OVERHEAD + data.len());
    pkt.extend_from_slice(&conv.to_le_bytes());
    pkt.push(KCP_CMD_PUSH);
    pkt.push(frg);
    pkt.extend_from_slice(&128u16.to_le_bytes()); // wnd
    pkt.extend_from_slice(&ts.to_le_bytes());
    pkt.extend_from_slice(&sn.to_le_bytes());
    pkt.extend_from_slice(&0u32.to_le_bytes()); // una
    pkt.extend_from_slice(&(data.len() as u32).to_le_bytes());
    pkt.extend_from_slice(data);
    pkt
}

/// Build an ACK segment with a 24-byte header.
fn make_ack(conv: u32, sn: u32, wnd: u16, ts: u32) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(KCP_OVERHEAD);
    pkt.extend_from_slice(&conv.to_le_bytes());
    pkt.push(KCP_CMD_ACK);
    pkt.push(0);
    pkt.extend_from_slice(&wnd.to_le_bytes());
    pkt.extend_from_slice(&ts.to_le_bytes());
    pkt.extend_from_slice(&sn.to_le_bytes());
    pkt.extend_from_slice(&0u32.to_le_bytes()); // una
    pkt.extend_from_slice(&0u32.to_le_bytes()); // len
    pkt
}

/// Drive a fresh Kcp through two updates so queued data actually flushes
/// (the congestion window starts at 0, so the first flush only arms it).
/// Note: the caller must `set_nodelay(.., nc=true)` first — without
/// nocwnd the cwnd=0 gate below holds every segment in snd_queue until
/// the first ACK arrives.
fn send_and_flush(kcp: &mut Kcp<PacketWriter>, data: &[u8]) {
    kcp.send(data).unwrap();
    // update(0) arms the flush timer; update(200) is past the interval,
    // so the queued segment moves into snd_buf and hits the output.
    kcp.update(0).unwrap();
    kcp.update(200).unwrap();
}

// ── receive-side payload recycling (F3 mirror) ───────────────────────

#[test]
fn rcv_data_pool_recycles_consumed_segment_payloads() {
    let mut out = PacketWriter::default();
    let mut kcp = Kcp::new_stream(42, &mut out);

    // One PUSH segment: input() allocates the payload buffer, then
    // recv() hands it back to rcv_data_pool instead of freeing it.
    let payload = vec![0xAB; 100];
    kcp.input(&make_push(42, 0, 0, 0, &payload)).unwrap();
    assert_eq!(kcp.rcv_queue.len(), 1);

    let mut data = [0u8; 100];
    assert_eq!(kcp.recv(&mut data).unwrap(), 100);
    assert_eq!(&data[..], &payload[..]);
    assert_eq!(kcp.rcv_data_pool.len(), 1, "consumed payload recycled");
    assert_eq!(kcp.rcv_data_pool[0], payload);

    // Second segment: input() pops the pooled buffer instead of
    // allocating; the pool stays empty until recv() refills it.
    kcp.input(&make_push(42, 1, 0, 0, &payload)).unwrap();
    assert!(
        kcp.rcv_data_pool.is_empty(),
        "input() must reuse pooled buffers"
    );
    assert_eq!(kcp.rcv_queue.len(), 1);
    assert_eq!(kcp.recv(&mut data).unwrap(), 100);
    assert_eq!(kcp.rcv_data_pool.len(), 1);
}

#[test]
fn rcv_data_pool_respects_cap_under_segment_flood() {
    let mut out = PacketWriter::default();
    let mut kcp = Kcp::new_stream(9, &mut out);
    let payload = vec![0xEF; 60];
    let mut data = [0u8; 60];
    // Burst: 2× the cap in flight (rcv_wnd=128 admits them all). recv()
    // recycles one payload per consumed segment, so the pool must clamp
    // at KCP_SEGMENT_POOL_CAP, never grow (bounded like the send side).
    for sn in 0..(KCP_SEGMENT_POOL_CAP as u32 * 2) {
        kcp.input(&make_push(9, sn, 0, 0, &payload)).unwrap();
        assert!(kcp.rcv_data_pool.len() <= KCP_SEGMENT_POOL_CAP);
    }
    assert_eq!(
        kcp.rcv_data_pool.len(),
        0,
        "pool untouched by the burst: input() only pops (never pushes); \
         recycling happens solely in recv()"
    );
    for _ in 0..(KCP_SEGMENT_POOL_CAP as u32 * 2) {
        assert_eq!(kcp.recv(&mut data).unwrap(), 60);
        assert!(kcp.rcv_data_pool.len() <= KCP_SEGMENT_POOL_CAP);
    }
    assert_eq!(kcp.rcv_data_pool.len(), KCP_SEGMENT_POOL_CAP);
}

#[test]
fn dropped_push_paths_recycle_payloads() {
    let mut out = PacketWriter::default();
    let mut kcp = Kcp::new_stream(7, &mut out);
    let payload = vec![0xCD; 80];

    // In-window duplicate: the repeat arm drops the segment without
    // inserting it, but its payload returns to the pool (a retransmit
    // flood of a parked segment cannot drain or grow it — each duplicate
    // pops exactly the entry it recycles).
    kcp.input(&make_push(7, 5, 0, 0, &payload)).unwrap(); // out-of-order park
    kcp.input(&make_push(7, 5, 0, 0, &payload)).unwrap(); // duplicate
    assert_eq!(kcp.rcv_data_pool.len(), 1, "in-window duplicate recycled");
    assert_eq!(kcp.rcv_buf.len(), 1, "duplicate not stored twice");
    for _ in 0..(KCP_SEGMENT_POOL_CAP * 2) {
        kcp.input(&make_push(7, 5, 0, 0, &payload)).unwrap();
    }
    assert_eq!(
        kcp.rcv_data_pool.len(),
        1,
        "retransmit flood neither drains nor grows the pool"
    );
    assert_eq!(kcp.rcv_buf.len(), 1);

    // recv() consumes the queued sn0 and refills the pool from it.
    kcp.input(&make_push(7, 0, 0, 0, &payload)).unwrap(); // moves sn0 → queue
    let mut data = [0u8; 80];
    assert_eq!(kcp.recv(&mut data).unwrap(), 80);
    assert_eq!(&data[..], &payload[..]);
    assert_eq!(kcp.rcv_data_pool.len(), 1);
}

// ── send-side payload recycling (F3) ─────────────────────────────────

#[test]
fn snd_data_pool_recycles_acked_and_una_discarded_payloads() {
    let mut out = PacketWriter::default();
    // Message mode (Kcp::new): each send() produces exactly one segment,
    // so the pool accounting is unambiguous.
    let mut kcp = Kcp::new(0x4455_6677, &mut out);
    kcp.set_nodelay(true, 10, 2, true); // nocwnd: flush moves queued data immediately

    // Two segments in flight; nothing ACKed yet, so the pool is empty.
    kcp.send(vec![0xAA; 300]).unwrap();
    kcp.send(vec![0xBB; 300]).unwrap();
    kcp.update(0).unwrap();
    kcp.update(200).unwrap();
    assert_eq!(kcp.snd_buf.len(), 2, "both segments moved into snd_buf");
    assert!(kcp.snd_data_pool.is_empty(), "nothing ACKed yet");

    // ACK sn=0: parse_ack recycles the oldest segment's payload (F3).
    kcp.input(&make_ack(0x4455_6677, 0, 128, 0)).unwrap();
    assert_eq!(kcp.snd_data_pool.len(), 1);
    assert_eq!(kcp.snd_data_pool[0], vec![0xAA; 300]);

    // ACK sn=1: the pool now holds both retired payloads.
    kcp.input(&make_ack(0x4455_6677, 1, 128, 0)).unwrap();
    assert_eq!(kcp.snd_data_pool.len(), 2);
    assert_eq!(kcp.snd_data_pool[0], vec![0xAA; 300]);
    assert_eq!(kcp.snd_data_pool[1], vec![0xBB; 300]);

    // send() pops the last retired buffer (LIFO) instead of allocating:
    // the BB buffer is reused for the CC payload, and the pool shrinks.
    kcp.send(vec![0xCC; 300]).unwrap();
    kcp.update(400).unwrap();
    assert_eq!(
        kcp.snd_data_pool.len(),
        1,
        "send() reused the retired buffer instead of allocating"
    );
    assert_eq!(kcp.snd_data_pool[0], vec![0xAA; 300]);
    assert_eq!(kcp.snd_buf.len(), 1, "CC segment in flight (sn=2)");

    // UNA discard arm: an ACK header with una=3 (byte-patched — make_ack
    // hardcodes una=0) drops every segment with sn < una; parse_una
    // recycles the discarded CC payload too.
    let mut ack = make_ack(0x4455_6677, 0, 128, 0);
    ack[16..20].copy_from_slice(&3u32.to_le_bytes());
    kcp.input(&ack).unwrap();
    assert!(kcp.snd_buf.is_empty(), "una window cleared the buffer");
    assert_eq!(kcp.snd_data_pool.len(), 2);
    assert_eq!(kcp.snd_data_pool[0], vec![0xAA; 300]);
    assert_eq!(kcp.snd_data_pool[1], vec![0xCC; 300]);
}

// ── 1. 24-byte header encoding / decoding ────────────────────────────

#[test]
fn header_encode_little_endian() {
    let mut a = Kcp::new(0x1122_3344, PacketWriter::default());
    a.set_nodelay(true, 10, 2, true); // nocwnd: first flush sends data
    a.send(b"hello").unwrap();
    a.update(0).unwrap();

    let out = a.output_mut().drain();
    assert_eq!(out.len(), 1, "expected one packet");

    let (conv, cmd, frg, wnd, ts, sn, una, data) = parse_packet(&out[0]);
    assert_eq!(conv, 0x1122_3344);
    assert_eq!(cmd, KCP_CMD_PUSH);
    assert_eq!(frg, 0);
    assert_eq!(wnd, 128, "wnd = rcv_wnd(128) - empty queue");
    assert_eq!(ts, 0, "sent at current=0");
    assert_eq!(sn, 0);
    assert_eq!(una, 0);
    assert_eq!(data, b"hello");

    // Byte-exact little-endian layout.
    let expected: Vec<u8> = [
        0x44, 0x33, 0x22, 0x11, // conv LE
        0x51, // cmd = 81 (PUSH)
        0x00, // frg
        0x80, 0x00, // wnd = 128 LE
        0x00, 0x00, 0x00, 0x00, // ts
        0x00, 0x00, 0x00, 0x00, // sn
        0x00, 0x00, 0x00, 0x00, // una
        0x05, 0x00, 0x00, 0x00, // len = 5 LE
    ]
    .to_vec();
    let mut with_payload = expected.clone();
    with_payload.extend_from_slice(b"hello");
    assert_eq!(out[0], with_payload);
}

#[test]
fn input_decodes_multiple_segments_in_one_datagram() {
    let mut b = Kcp::new(0x1122_3344, PacketWriter::default());
    b.update(0).unwrap(); // arm updated

    // Two PUSH segments concatenated into a single datagram.
    let mut datagram = make_push(0x1122_3344, 0, 1, 5, b"aa");
    datagram.extend_from_slice(&make_push(0x1122_3344, 1, 0, 5, b"bb"));

    b.input(&datagram).unwrap();
    assert_eq!(b.peeksize().unwrap(), 4, "frg chain merged");
    let mut buf = [0u8; 16];
    assert_eq!(b.recv(&mut buf).unwrap(), 4);
    assert_eq!(&buf[..4], b"aabb");
}

#[test]
fn input_rejects_wrong_conv() {
    let mut b = Kcp::new(0x1111_1111, PacketWriter::default());
    let pkt = make_push(0x2222_2222, 0, 0, 0, b"x");
    match b.input(&pkt) {
        Err(Error::ConvInconsistent(0x1111_1111, 0x2222_2222)) => {}
        other => panic!("expected ConvInconsistent, got {:?}", other),
    }
}

#[test]
fn input_rejects_oversized_push_segment() {
    let mut b = Kcp::new(0x1122_3344, PacketWriter::default());
    let mss = b.mss;
    let big = vec![0xAB; mss + 1];
    let pkt = make_push(0x1122_3344, 0, 0, 0, &big);
    match b.input(&pkt) {
        Err(Error::InvalidSegmentDataSize(expected, actual)) => {
            assert_eq!(expected, mss);
            assert_eq!(actual, mss + 1);
        }
        other => panic!("expected InvalidSegmentDataSize, got {:?}", other),
    }
}

#[test]
fn input_accepts_zero_len_push_heartbeat() {
    let mut b = Kcp::new(0x1122_3344, PacketWriter::default());
    let pkt = make_push(0x1122_3344, 0, 0, 0, b"");
    b.input(&pkt).expect("zero-length PUSH must be accepted");
}

#[test]
fn input_validates_each_segment_in_multi_segment_datagram() {
    let mut b = Kcp::new(0x1122_3344, PacketWriter::default());
    let mss = b.mss;
    let mut pkt = make_push(0x1122_3344, 0, 0, 0, b"hello");
    pkt.extend(make_push(0x1122_3344, 1, 0, 0, &vec![0xCD; mss + 1]));
    match b.input(&pkt) {
        Err(Error::InvalidSegmentDataSize(expected, actual)) => {
            assert_eq!(expected, mss);
            assert_eq!(actual, mss + 1);
        }
        other => panic!(
            "expected InvalidSegmentDataSize from second segment, got {:?}",
            other
        ),
    }
}

#[test]
fn hostile_ack_ts_does_not_overflow_srtt() {
    // L7: an ACK's ts field is attacker-controlled; ts=0 against a large
    // `current` clock drives rtt toward 2^31-1 ms. The pre-fix smoothing
    // `(7 * rx_srtt + rtt) / 8` overflowed u32 on the SECOND ACK and
    // panicked (debug builds) — killing the whole driver task with two
    // packets. The clamp to KCP_RTO_MAX keeps every intermediate in
    // range; the session stays usable and rx_rto stays bounded.
    let mut kcp = Kcp::new(1, PacketWriter::default());
    kcp.update(0).unwrap();
    kcp.send(b"hello").unwrap();
    kcp.update(200).unwrap();
    // Move the session clock near the i32 positive ceiling.
    kcp.update(2_147_000_000).unwrap();
    // First hostile ACK: rtt = timediff(current, ts=0) ≈ 2.1e9 ms.
    kcp.input(&make_ack(1, 0, 128, 0)).unwrap();
    assert!(kcp.rx_srtt <= KCP_RTO_MAX, "rtt must be clamped");
    // Second ACK drives the smoothing arithmetic — pre-fix this
    // overflowed and panicked in debug builds.
    kcp.input(&make_ack(1, 0, 128, 0)).unwrap();
    assert!(kcp.rx_srtt <= KCP_RTO_MAX);
    assert!(kcp.rx_rttval <= KCP_RTO_MAX);
    assert!(kcp.rx_rto <= KCP_RTO_MAX);
    // Session is still functional: a conforming PUSH is processed.
    kcp.update(2_147_000_001).unwrap();
    kcp.input(&make_push(1, 0, 0, 0, b"ok")).unwrap();
    let mut buf = [0u8; 8];
    assert_eq!(kcp.recv(&mut buf).unwrap(), 2);
    assert_eq!(&buf[..2], b"ok");
}

#[test]
fn stream_mode_rejects_frg_positive_push_without_killing_session() {
    // L8: a hostile stream-mode peer sends an in-window PUSH with
    // frg=255. Pre-fix the segment landed at the front of rcv_queue
    // with its chain never completing → peeksize() returned
    // ExpectingFragment → recv_and_push errored → the driver removed
    // the session: one packet killed the session. Now the datagram is
    // rejected at input time (non-fatal), and the session survives.
    let mut kcp = Kcp::new_stream(1, PacketWriter::default());
    kcp.update(0).unwrap();
    let hostile = make_push(1, 0, 255, 0, b"x");
    match kcp.input(&hostile) {
        Err(Error::UnexpectedFragment(255)) => {}
        other => panic!("expected UnexpectedFragment(255), got {:?}", other),
    }
    // The session survives: a conforming PUSH is still processed.
    kcp.input(&make_push(1, 0, 0, 0, b"ok")).unwrap();
    let mut buf = [0u8; 8];
    assert_eq!(kcp.recv(&mut buf).unwrap(), 2);
    assert_eq!(&buf[..2], b"ok");
}

// ── 2. basic roundtrip ───────────────────────────────────────────────

#[test]
fn roundtrip_no_loss() {
    let mut a = Kcp::new(0x1122_3344, PacketWriter::default());
    let mut b = Kcp::new(0x1122_3344, PacketWriter::default());

    send_and_flush(&mut a, b"hello");
    for pkt in a.output_mut().drain() {
        b.input(&pkt).unwrap();
    }
    assert_eq!(b.peeksize().unwrap(), 5);
    let mut buf = [0u8; 16];
    assert_eq!(b.recv(&mut buf).unwrap(), 5);
    assert_eq!(&buf[..5], b"hello");

    // Reverse direction.
    send_and_flush(&mut b, b"world");
    for pkt in b.output_mut().drain() {
        a.input(&pkt).unwrap();
    }
    assert_eq!(a.peeksize().unwrap(), 5);
    assert_eq!(a.recv(&mut buf).unwrap(), 5);
    assert_eq!(&buf[..5], b"world");
}

#[test]
fn recv_empty_returns_recv_queue_empty() {
    let mut a = Kcp::new(1, PacketWriter::default());
    let mut buf = [0u8; 16];
    assert!(matches!(a.recv(&mut buf), Err(Error::RecvQueueEmpty)));
    assert!(matches!(a.peeksize(), Err(Error::RecvQueueEmpty)));
}

// ── 3. fragmentation and reassembly ──────────────────────────────────

#[test]
fn fragmentation_message_mode() {
    let mut a = Kcp::new(0x1122_3344, PacketWriter::default());
    let mut b = Kcp::new(0x1122_3344, PacketWriter::default());
    a.set_nodelay(true, 10, 2, true);

    // mss = 1400 - 24 = 1376, so 3000 bytes split into 3 fragments.
    let big = vec![0xabu8; 3000];
    a.send(big.clone()).unwrap();
    a.update(0).unwrap();

    let out = a.output_mut().drain();
    assert_eq!(out.len(), 3, "3000 bytes over mss=1376 -> 3 packets");

    // frg counts down across the fragments: 2, 1, 0.
    let mut frgs = Vec::new();
    let mut total = 0usize;
    for pkt in &out {
        let (_, _, frg, _, _, _, _, data) = parse_packet(pkt);
        frgs.push(frg);
        total += data.len();
    }
    assert_eq!(frgs, vec![2, 1, 0]);
    assert_eq!(total, 3000);

    for pkt in &out {
        b.input(pkt).unwrap();
    }
    assert_eq!(b.peeksize().unwrap(), 3000, "fragment chain reassembled");
    let mut buf = vec![0u8; 3000];
    assert_eq!(b.recv(&mut buf).unwrap(), 3000);
    assert_eq!(buf, big);
}

#[test]
fn stream_mode_merges_byte_stream() {
    let mut a = Kcp::new_stream(0x1122_3344, PacketWriter::default());
    let mut b = Kcp::new_stream(0x1122_3344, PacketWriter::default());
    a.set_nodelay(true, 10, 2, true);

    // Two small sends merge into the trailing segment.
    a.send(b"ab").unwrap();
    a.send(b"cde").unwrap();
    a.update(0).unwrap();

    let out = a.output_mut().drain();
    assert_eq!(out.len(), 1, "merged into one packet");
    let (_, _, _, _, _, _, _, data) = parse_packet(&out[0]);
    assert_eq!(data, b"abcde");

    b.input(&out[0]).unwrap();
    assert_eq!(b.peeksize().unwrap(), 5);
    let mut buf = [0u8; 16];
    assert_eq!(b.recv(&mut buf).unwrap(), 5);
    assert_eq!(&buf[..5], b"abcde");
}

#[test]
fn stream_mode_large_send_splits_with_frg_zero() {
    let mut a = Kcp::new_stream(0x1122_3344, PacketWriter::default());
    let mut b = Kcp::new_stream(0x1122_3344, PacketWriter::default());
    a.set_nodelay(true, 10, 2, true);

    // In stream mode every fragment carries frg=0; the receiver drains
    // them one recv at a time (byte-stream semantics).
    let big: Vec<u8> = (0..3000u32).map(|i| (i % 251) as u8).collect();
    a.send(big.clone()).unwrap();
    a.update(0).unwrap();

    let out = a.output_mut().drain();
    let total: usize = out.iter().map(|p| parse_packet(p).7.len()).sum();
    assert_eq!(total, 3000);
    assert!(out.iter().all(|p| parse_packet(p).2 == 0), "stream frg=0");

    for pkt in &out {
        b.input(pkt).unwrap();
    }

    let mut received = Vec::new();
    let mut buf = vec![0u8; 2000];
    loop {
        match b.peeksize() {
            Err(Error::RecvQueueEmpty) => break,
            Ok(size) => {
                assert!(size <= buf.len());
                let n = b.recv(&mut buf[..size]).unwrap();
                received.extend_from_slice(&buf[..n]);
            }
            Err(e) => panic!("peeksize error: {e:?}"),
        }
    }
    assert_eq!(received, big);
}

// ── 4. send window rejection ─────────────────────────────────────────

#[test]
fn send_rejects_message_larger_than_receive_window() {
    let mut a = Kcp::new(1, PacketWriter::default());
    // mss=1376; KCP_WND_RCV=128 => max message ~ 128 * 1376.
    let too_big = vec![0u8; 128 * 1376];
    assert!(matches!(a.send(too_big.clone()), Err(Error::UserBufTooBig)));
}

/// Message-mode segmentation walks the original buffer with one offset:
/// every byte lands in exactly one segment and the `frg` chain counts
/// down from (segments-1) to 0 in send order.
#[test]
fn message_mode_segments_frg_chain_and_data() {
    let mut a = Kcp::new(1, PacketWriter::default());
    a.set_mtu(50).unwrap(); // mss = 50 - KCP_OVERHEAD = 26
    let mss = 50usize - KCP_OVERHEAD;
    let buf: Vec<u8> = (0..(3 * mss + 7) as u32).map(|i| (i % 251) as u8).collect();

    let sent = a.send(buf.clone()).unwrap();
    assert_eq!(sent, buf.len());
    assert_eq!(a.snd_queue.len(), 4);

    let frgs: Vec<u8> = a.snd_queue.iter().map(|s| s.frg).collect();
    assert_eq!(frgs, vec![3, 2, 1, 0], "frg counts down to 0 in send order");

    let sizes: Vec<usize> = a.snd_queue.iter().map(|s| s.data.len()).collect();
    assert_eq!(sizes, vec![mss, mss, mss, 7]);

    let mut concat = Vec::new();
    for s in &a.snd_queue {
        concat.extend_from_slice(&s.data);
    }
    assert_eq!(concat, buf, "segment data reassembles the input exactly");
}

// ── 5. kcp-go v5.6.13 compat patches ─────────────────────────────────

/// Patch 1: with nodelay enabled, RTO backoff is LINEAR (rto += rx_rto/2),
/// not the original exponential rto += rto/2. rx_rto stays 200 because no
/// ACK ever arrives, so every retransmission adds exactly rx_rto/2 = 100.
#[test]
fn rto_linear_backoff_nodelay() {
    let mut a = Kcp::new(0x1122_3344, PacketWriter::default());
    a.set_nodelay(true, 10, 2, true); // nodelay + nc
    a.send(b"data").unwrap();

    // update(0) arms the window and flushes the segment (nocwnd).
    a.update(0).unwrap();
    assert_eq!(a.snd_buf.len(), 1);
    assert_eq!(a.snd_buf[0].xmit, 1);
    assert_eq!(a.snd_buf[0].rto, 200);
    assert_eq!(a.snd_buf[0].resendts, 200); // 0 + rto(200) + rtomin(0)

    // Drop the output packet (simulate loss), then hit the RTO deadline.
    let _dropped = a.output_mut().drain();
    a.update(200).unwrap(); // resendts reached -> RTO retransmit
    assert_eq!(a.snd_buf[0].xmit, 2);
    assert_eq!(a.snd_buf[0].rto, 300, "200 + rx_rto/2 = 300 (linear)");
    assert_eq!(a.snd_buf[0].resendts, 500); // 200 + 300

    let _dropped = a.output_mut().drain();
    a.update(500).unwrap(); // second RTO retransmit
    assert_eq!(a.snd_buf[0].xmit, 3);
    assert_eq!(a.snd_buf[0].rto, 400, "300 + rx_rto/2 = 400 (linear)");
    // Exponential backoff would have produced 200 -> 400 -> 800.
    assert!(a.snd_buf[0].rto < 800, "must not be exponential backoff");
}

/// Patch 3: early retransmit fires when fastack > 0 AND no new segments
/// were moved from snd_queue in this flush (fastresend is 0, so the fast
/// retransmit branch cannot claim the segment first).
#[test]
fn early_retransmit_trigger() {
    let mut a = Kcp::new(0x1122_3344, PacketWriter::default());
    let mut b = Kcp::new(0x1122_3344, PacketWriter::default());
    a.set_nodelay(true, 10, 2, true); // fastresend=2, nc
    b.set_nodelay(true, 10, 2, true);

    // Two segments in flight; sn=1 is delivered, sn=0 is lost.
    a.send(vec![0x11u8; 1000]).unwrap();
    a.send(vec![0x22u8; 1000]).unwrap();
    a.update(0).unwrap(); // nocwnd -> both segments flushed now

    let out = a.output_mut().drain();
    assert_eq!(out.len(), 2);
    let sn0_pkt = parse_packet(&out[0]).5;
    let sn1_pkt = parse_packet(&out[1]).5;
    assert_eq!((sn0_pkt, sn1_pkt), (0, 1));

    // Receiver sees sn=1 only; ACKs it (sn=0 stays in snd_buf with
    // fastack incremented via parse_fastack).
    b.input(&out[1]).unwrap();
    b.update(0).unwrap();
    let ack_pkt = b.output_mut().drain();
    assert_eq!(ack_pkt.len(), 1);
    let (_, cmd, _, _, _, ack_sn, _, _) = parse_packet(&ack_pkt[0]);
    assert_eq!(cmd, KCP_CMD_ACK);
    assert_eq!(ack_sn, 1);

    a.input(&ack_pkt[0]).unwrap();
    assert_eq!(a.snd_buf[0].sn, 0);
    assert_eq!(
        a.snd_buf[0].fastack, 1,
        "out-of-order ACK counts as fastack"
    );
    assert_eq!(a.snd_buf.len(), 1, "sn=1 was acked and removed");

    // Next flush: queue is empty (new_segs_count == 0) so early
    // retransmit re-sends sn=0 immediately, well before its RTO.
    a.update(10).unwrap();
    let out = a.output_mut().drain();
    let pushed: Vec<(u8, u32)> = out
        .iter()
        .map(|p| {
            let (_, cmd, _, _, _, sn, _, _) = parse_packet(p);
            (cmd, sn)
        })
        .collect();
    assert!(
        pushed.contains(&(KCP_CMD_PUSH, 0)),
        "expected retransmitted PUSH sn=0, got {pushed:?}"
    );
}

/// Patch 2: fast retransmit fires before RTO. With fastresend=1 the
/// segment is retransmitted on fastack>=1 even though its resend deadline
/// is still far in the future.
#[test]
fn fast_retransmit_before_rto() {
    let mut a = Kcp::new(0x1122_3344, PacketWriter::default());
    let mut b = Kcp::new(0x1122_3344, PacketWriter::default());
    a.set_nodelay(true, 10, 1, true); // fastresend=1, nc
    b.set_nodelay(true, 10, 1, true);

    a.send(vec![0x11u8; 1000]).unwrap();
    a.send(vec![0x22u8; 1000]).unwrap();
    a.update(0).unwrap();

    let out = a.output_mut().drain();
    // Deliver sn=1 only.
    b.input(&out[1]).unwrap();
    b.update(0).unwrap();
    let ack_pkt = b.output_mut().drain();
    assert_eq!(ack_pkt.len(), 1);

    a.input(&ack_pkt[0]).unwrap();
    assert_eq!(a.snd_buf[0].fastack, 1);

    // resend deadline for sn=0 is 0 + 200 = 200; current is 10, so RTO
    // has NOT fired. The fastack>=1 branch retransmits it anyway.
    assert!(a.snd_buf[0].resendts > 10);
    a.update(10).unwrap();
    let out = a.output_mut().drain();
    let pushed: Vec<(u8, u32)> = out
        .iter()
        .map(|p| {
            let (_, cmd, _, _, _, sn, _, _) = parse_packet(p);
            (cmd, sn)
        })
        .collect();
    assert!(
        pushed.contains(&(KCP_CMD_PUSH, 0)),
        "expected fast retransmit of PUSH sn=0, got {pushed:?}"
    );
}

/// Window probing: when rmt_wnd reaches 0, WASK is sent with exponential
/// backoff (7000ms -> +50% -> capped at 120s).
#[test]
fn window_probe_sends_wask() {
    let mut a = Kcp::new(0x1122_3344, PacketWriter::default());
    a.set_nodelay(true, 10, 2, true);
    a.send(b"x").unwrap();
    a.update(0).unwrap(); // flush sn=0
    let _dropped = a.output_mut().drain();

    // Fake ACK with window 0: remote cannot receive more data.
    let ack = make_ack(0x1122_3344, 0, 0, 0);
    a.input(&ack).unwrap();
    assert_eq!(a.rmt_wnd(), 0);

    // First probe schedules ts_probe = current + 7000 but sends nothing.
    a.update(7000).unwrap();
    let out = a.output_mut().drain();
    assert!(
        !out.iter().any(|p| parse_packet(p).1 == KCP_CMD_WASK),
        "first probe must only arm the timer"
    );

    // Second probe (wait already 7000ms) emits WASK and backs off.
    a.update(14_000).unwrap();
    let out = a.output_mut().drain();
    assert!(
        out.iter().any(|p| parse_packet(p).1 == KCP_CMD_WASK),
        "expected a WASK packet after the probe deadline"
    );
    assert_eq!(a.probe_wait, 10_500, "probe_wait += probe_wait/2");
}

// ── 6. lossy link model (ported from upstream tests/kcp.rs) ───────────

struct DelayPacket {
    buf: Vec<u8>,
    ts: u32,
}

/// Fisher-Yates pool of 0..size-1 used to decide packet drops.
struct Random {
    seeds: Vec<u32>,
    size: usize,
}

impl Random {
    fn new(size: usize) -> Self {
        Random {
            seeds: vec![0u32; size],
            size: 0,
        }
    }

    fn random(&mut self) -> u32 {
        if self.seeds.is_empty() {
            return 0;
        }
        if self.size == 0 {
            for (i, e) in self.seeds.iter_mut().enumerate() {
                *e = i as u32;
            }
            self.size = self.seeds.len();
        }
        let i = rand::rng().random_range(0..self.size);
        let x = self.seeds[i];
        self.size -= 1;
        self.seeds[i] = self.seeds[self.size];
        x
    }
}

/// Virtual network between two peers: per-direction loss, delay, and a
/// bounded queue. Timestamps are simulated milliseconds (monotonic).
struct LatencySimulator {
    lostrate: u32,
    rttmin: u32,
    rttmax: u32,
    nmax: usize,
    current: u32,
    p12: VecDeque<DelayPacket>,
    p21: VecDeque<DelayPacket>,
    r12: Random,
    r21: Random,
}

impl LatencySimulator {
    fn new(lostrate: u32, rttmin: u32, rttmax: u32, nmax: usize) -> Self {
        LatencySimulator {
            lostrate: lostrate / 2,
            rttmin: rttmin / 2,
            rttmax: rttmax / 2,
            nmax,
            current: 0,
            p12: VecDeque::new(),
            p21: VecDeque::new(),
            r12: Random::new(100),
            r21: Random::new(100),
        }
    }

    fn send(&mut self, peer: u32, data: &[u8]) -> usize {
        if peer == 0 {
            if self.r12.random() < self.lostrate {
                return data.len();
            }
            if self.p12.len() >= self.nmax {
                return data.len();
            }
        } else {
            if self.r21.random() < self.lostrate {
                return data.len();
            }
            if self.p21.len() >= self.nmax {
                return data.len();
            }
        }

        let mut delay = self.rttmin;
        if self.rttmax > self.rttmin {
            delay += rand::rng().random_range(0..(self.rttmax - self.rttmin));
        }

        let pkg = DelayPacket {
            buf: data.to_vec(),
            ts: self.current + delay,
        };

        if peer == 0 {
            self.p12.push_back(pkg);
        } else {
            self.p21.push_back(pkg);
        }
        data.len()
    }

    fn recv(&mut self, peer: u32, data: &mut [u8]) -> io::Result<usize> {
        let front = if peer == 0 {
            self.p12.front()
        } else {
            self.p21.front()
        };
        let pkg = match front {
            None => {
                return Err(io::Error::new(io::ErrorKind::WouldBlock, "No packet yet"));
            }
            Some(p) => p,
        };

        if self.current < pkg.ts {
            return Err(io::Error::new(io::ErrorKind::WouldBlock, "No packet yet"));
        }

        if data.len() < pkg.buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Buffer is too small",
            ));
        }

        let pkg = if peer == 0 {
            self.p12.pop_front().unwrap()
        } else {
            self.p21.pop_front().unwrap()
        };
        let n = pkg.buf.len();
        data[..n].copy_from_slice(&pkg.buf);
        Ok(n)
    }

    fn tick(&mut self, ms: u32) {
        self.current += ms;
    }
}

struct VnetOutput {
    sim: Rc<RefCell<LatencySimulator>>,
    peer: u32,
}

impl Write for VnetOutput {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        Ok(self.sim.borrow_mut().send(self.peer, data))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum Mode {
    Default,
    Normal,
    Fast,
}

/// End-to-end reliability test over a lossy/delayed virtual network:
/// kcp1 sends 8-byte messages every 20ms, kcp2 echoes them back, and
/// kcp1 verifies it receives each sequence number exactly once in order.
fn run_lossy(mode: Mode, msgcount: u32, lostrate: u32) {
    let sim = Rc::new(RefCell::new(LatencySimulator::new(lostrate, 60, 125, 1000)));

    let mut kcp1 = Kcp::new(
        0x1122_3344,
        VnetOutput {
            sim: sim.clone(),
            peer: 0,
        },
    );
    let mut kcp2 = Kcp::new(
        0x1122_3344,
        VnetOutput {
            sim: sim.clone(),
            peer: 1,
        },
    );

    kcp1.set_wndsize(128, 128);
    kcp2.set_wndsize(128, 128);

    match mode {
        Mode::Default => {
            kcp1.set_nodelay(false, 10, 0, false);
            kcp2.set_nodelay(false, 10, 0, false);
        }
        Mode::Normal => {
            kcp1.set_nodelay(false, 10, 0, true);
            kcp2.set_nodelay(false, 10, 0, true);
        }
        Mode::Fast => {
            kcp1.set_nodelay(true, 10, 2, true);
            kcp2.set_nodelay(true, 10, 2, true);
            kcp1.set_rx_minrto(10);
            kcp2.set_fast_resend(1);
        }
    }

    let interval = 10u32;
    let mut current = 0u32;
    let mut slap = current + 20;
    let mut index = 0u32;
    let mut next = 0u32;

    let mut buf = [0u8; 2000];
    let mut guard = 0u32;
    while next <= msgcount {
        guard += 1;
        assert!(guard < 2_000_000, "run_lossy did not converge");

        sim.borrow_mut().tick(interval);
        current += interval;
        kcp1.update(current).unwrap();
        kcp2.update(current).unwrap();

        // kcp1 sends one 8-byte message every 20ms.
        while current >= slap {
            let mut msg = Vec::with_capacity(8);
            msg.extend_from_slice(&index.to_le_bytes());
            msg.extend_from_slice(&current.to_le_bytes());
            kcp1.send(msg.clone()).unwrap();
            index += 1;
            slap += 20;
        }

        // Deliver vnet p1 -> p2.
        loop {
            let n = match sim.borrow_mut().recv(1, &mut buf) {
                Err(..) => break,
                Ok(n) => n,
            };
            kcp2.input(&buf[..n]).unwrap();
        }

        // Deliver vnet p2 -> p1.
        loop {
            let n = match sim.borrow_mut().recv(0, &mut buf) {
                Err(..) => break,
                Ok(n) => n,
            };
            kcp1.input(&buf[..n]).unwrap();
        }

        // kcp2 echoes everything it received back to kcp1.
        loop {
            match kcp2.recv(&mut buf) {
                Err(..) => break,
                Ok(n) => {
                    kcp2.send(&buf[..n]).unwrap();
                }
            }
        }

        // kcp1 verifies the echoed messages arrive exactly in order.
        loop {
            match kcp1.recv(&mut buf) {
                Err(..) => break,
                Ok(_) => {
                    let sn = u32::from_le_bytes(buf[..4].try_into().unwrap());
                    assert_eq!(sn, next, "received out-of-order or duplicated data");
                    next += 1;
                }
            }
        }
    }
}

#[test]
fn link_lossy_default() {
    run_lossy(Mode::Default, 1000, 10);
}

#[test]
fn link_lossy_normal() {
    run_lossy(Mode::Normal, 1000, 10);
}

#[test]
fn link_lossy_fast() {
    run_lossy(Mode::Fast, 1000, 10);
}

#[test]
fn link_massive_loss_default() {
    run_lossy(Mode::Default, 500, 50);
}

#[test]
fn link_massive_loss_normal() {
    run_lossy(Mode::Normal, 500, 50);
}

#[test]
fn link_massive_loss_fast() {
    run_lossy(Mode::Fast, 500, 50);
}

// ── 7. proptest fuzz of the input() state machine ────────────────────
//
// `Kcp::input` consumes untrusted wire bytes (24-byte little-endian
// header + multi-segment datagrams). The core fuzz invariant is that
// **no input may ever panic** — returning Ok or Err are both acceptable.
// A few targeted scenarios additionally pin the safe-error invariants:
//   * a mismatched conv      -> Err(ConvInconsistent)
//   * an oversized/truncated -> Err(InvalidSegmentDataSize)
mod proptest_fuzz {
    use super::*;
    use proptest::prelude::*;

    /// Fuzz harness: run `Kcp::input` under `catch_unwind`. A panic fails
    /// the test; a clean Ok/Err is the expected outcome for every input.
    fn input_no_panic(kcp: &mut Kcp<PacketWriter>, bytes: &[u8]) -> Result<usize> {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| kcp.input(bytes))) {
            Ok(r) => r,
            Err(_) => panic!("Kcp::input panicked on input of {} bytes", bytes.len()),
        }
    }

    // A valid PUSH packet truncated to a random prefix (0..=len).
    prop_compose! {
        fn arb_truncated_push()(
            conv in any::<u32>(),
            sn in any::<u32>(),
            data in prop::collection::vec(any::<u8>(), 0..256),
            cut in 0usize..KCP_OVERHEAD + 256usize,
        ) -> Vec<u8> {
            let pkt = make_push(conv, sn, 0, 0, &data);
            let n = cut.min(pkt.len());
            pkt[..n].to_vec()
        }
    }

    // A valid PUSH packet with 0..8 random byte overwrites (may corrupt
    // the conv, cmd, len field, payload ...).
    prop_compose! {
        fn arb_mutated_push()(
            conv in any::<u32>(),
            sn in any::<u32>(),
            data in prop::collection::vec(any::<u8>(), 0..128),
            flips in prop::collection::vec((any::<usize>(), any::<u8>()), 0..8),
        ) -> Vec<u8> {
            let mut pkt = make_push(conv, sn, 0, 0, &data);
            for (i, byte) in flips {
                let idx = i % pkt.len();
                pkt[idx] = byte;
            }
            pkt
        }
    }

    /// One KCP segment for multi-segment datagrams: a valid PUSH (with
    /// random fragment count — covers the frg-chain reassembly surface),
    /// a valid ACK, a random malformed blob, or a header claiming a huge
    /// data length.
    fn arb_segment() -> impl Strategy<Value = Vec<u8>> {
        prop_oneof![
            (
                any::<u32>(),
                any::<u32>(),
                any::<u8>(),
                prop::collection::vec(any::<u8>(), 0..128)
            )
                .prop_map(|(conv, sn, frg, data)| make_push(conv, sn, frg, 0, &data)),
            (any::<u32>(), any::<u32>(), any::<u16>())
                .prop_map(|(conv, sn, wnd)| make_ack(conv, sn, wnd, 0)),
            prop::collection::vec(any::<u8>(), 0..64),
            (any::<u32>(), any::<u32>(), any::<u32>()).prop_map(|(conv, sn, huge)| {
                let mut pkt = make_push(conv, sn, 0, 0, b"");
                pkt[KCP_OVERHEAD - 4..KCP_OVERHEAD].copy_from_slice(&huge.to_le_bytes());
                pkt
            }),
        ]
    }

    proptest! {
        /// Core invariant: arbitrary bytes (0..=2048) must never panic.
        #[test]
        fn fuzz_random_bytes_never_panics(
            conv in any::<u32>(),
            bytes in prop::collection::vec(any::<u8>(), 0..2048),
        ) {
            let mut kcp = Kcp::new(conv, PacketWriter::default());
            let _ = input_no_panic(&mut kcp, &bytes);
        }
    }

    proptest! {
        /// Any prefix of a valid PUSH or ACK packet must never panic.
        #[test]
        fn fuzz_truncated_packets_never_panics(
            push in arb_truncated_push(),
            ack_cut in 0usize..KCP_OVERHEAD + 1usize,
        ) {
            let mut kcp = Kcp::new(0x1122_3344, PacketWriter::default());
            let _ = input_no_panic(&mut kcp, &push);

            let ack = make_ack(0x1122_3344, 0, 0, 0);
            let n = ack_cut.min(ack.len());
            let _ = input_no_panic(&mut kcp, &ack[..n]);
        }
    }

    proptest! {
        /// Byte flips on a valid packet (including the len field) must never panic.
        #[test]
        fn fuzz_mutated_packets_never_panics(
            mutated in arb_mutated_push(),
        ) {
            let mut kcp = Kcp::new(0x1122_3344, PacketWriter::default());
            let _ = input_no_panic(&mut kcp, &mutated);
        }
    }

    proptest! {
        /// 1..4 concatenated valid/malformed segments in one datagram must never panic.
        #[test]
        fn fuzz_multi_segment_datagrams_never_panics(
            segments in prop::collection::vec(arb_segment(), 1..5),
        ) {
            let mut datagram = Vec::new();
            for seg in &segments {
                datagram.extend_from_slice(seg);
            }
            let mut kcp = Kcp::new(0x1122_3344, PacketWriter::default());
            let _ = input_no_panic(&mut kcp, &datagram);
        }
    }

    proptest! {
        /// Legal send→flush→input round trips interleaved with random
        /// garbage packets: never panic, and every legal payload still
        /// arrives intact and in order. Garbage packets get a non-matching
        /// conv so they are rejected as ConvInconsistent and can never be
        /// mistaken for legitimate data.
        #[test]
        fn fuzz_legal_traffic_with_garbage(
            payloads in prop::collection::vec(
                prop::collection::vec(any::<u8>(), 1..128), 1..16),
            garbage in prop::collection::vec(
                prop::collection::vec(any::<u8>(), 0..64), 0..16),
        ) {
            const CONV: u32 = 0x1122_3344;
            let mut a = Kcp::new(CONV, PacketWriter::default());
            let mut b = Kcp::new(CONV, PacketWriter::default());
            // nc=true: every queued segment flushes on the next update().
            a.set_nodelay(true, 10, 2, true);
            b.set_nodelay(true, 10, 2, true);

            let mut t = 0u32;
            let mut delivered: Vec<Vec<u8>> = Vec::new();
            let mut buf = vec![0u8; 2048];

            for (i, payload) in payloads.iter().enumerate() {
                // Sender: one message per round, flushed immediately.
                a.send(payload).unwrap();
                a.update(t).unwrap();
                let pushes = a.output_mut().drain();

                // Receiver: mix in a garbage packet (rejected by conv).
                if i % 2 == 0 {
                    if let Some(g) = garbage.get(i / 2) {
                        let mut junk = g.clone();
                        if junk.len() >= 4 {
                            junk[..4].copy_from_slice(&CONV.wrapping_add(1).to_le_bytes());
                        }
                        let _ = input_no_panic(&mut b, &junk);
                    }
                }

                for pkt in &pushes {
                    let _ = input_no_panic(&mut b, pkt);
                }

                // Receiver flushes ACKs back to the sender.
                b.update(t).unwrap();
                let acks = b.output_mut().drain();
                for pkt in &acks {
                    let _ = input_no_panic(&mut a, pkt);
                }

                // Drain whatever became deliverable.
                loop {
                    match b.recv(&mut buf) {
                        Ok(n) => delivered.push(buf[..n].to_vec()),
                        Err(Error::RecvQueueEmpty) => break,
                        Err(e) => panic!("recv failed on legal traffic: {e:?}"),
                    }
                }
                t += 10;
            }

            prop_assert_eq!(&delivered, &payloads,
                "legal payloads must arrive intact and in order");
        }
    }

    proptest! {
        /// Invariant: a datagram with a mismatched conv is rejected with
        /// Err(ConvInconsistent), never accepted.
        #[test]
        fn wrong_conv_returns_conv_inconsistent(
            expected in any::<u32>(),
            other in any::<u32>(),
            sn in any::<u32>(),
            data in prop::collection::vec(any::<u8>(), 0..64),
        ) {
            prop_assume!(expected != other);
            let mut kcp = Kcp::new(expected, PacketWriter::default());
            let pkt = make_push(other, sn, 0, 0, &data);
            let result = input_no_panic(&mut kcp, &pkt);
            let ok = matches!(&result, Err(Error::ConvInconsistent(e, o))
                if *e == expected && *o == other);
            prop_assert!(ok,
                "expected ConvInconsistent({expected}, {other}), got {result:?}");
        }
    }

    proptest! {
        /// Invariant: a PUSH payload beyond MSS is rejected with
        /// Err(InvalidSegmentDataSize) instead of growing the recv buffer.
        #[test]
        fn oversized_push_returns_invalid_segment_data_size(
            conv in any::<u32>(),
            // sn must be inside the initial recv window (rcv_wnd = 128);
            // out-of-window segments are skipped, not size-checked.
            sn in 0u32..128u32,
            extra in 1usize..4096usize,
        ) {
            let mut kcp = Kcp::new(conv, PacketWriter::default());
            let mss = kcp.mss;
            let big = vec![0xabu8; mss + extra];
            let pkt = make_push(conv, sn, 0, 0, &big);
            let result = input_no_panic(&mut kcp, &pkt);
            let ok = matches!(&result, Err(Error::InvalidSegmentDataSize(expected, actual))
                if *expected == mss && *actual == mss + extra);
            prop_assert!(ok,
                "expected InvalidSegmentDataSize({mss}, {}), got {result:?}",
                mss + extra);
        }
    }

    proptest! {
        /// Invariant: a header whose len field exceeds the remaining bytes
        /// (truncation attack) is rejected with Err(InvalidSegmentDataSize).
        #[test]
        fn truncated_len_field_returns_invalid_segment_data_size(
            conv in any::<u32>(),
            sn in any::<u32>(),
            data in prop::collection::vec(any::<u8>(), 0..64),
            claimed in 1u32..=u32::MAX,
        ) {
            prop_assume!((claimed as usize) > data.len());
            let mut pkt = make_push(conv, sn, 0, 0, &data);
            pkt[KCP_OVERHEAD - 4..KCP_OVERHEAD].copy_from_slice(&claimed.to_le_bytes());
            let mut kcp = Kcp::new(conv, PacketWriter::default());
            let result = input_no_panic(&mut kcp, &pkt);
            let ok = matches!(&result,
                Err(Error::InvalidSegmentDataSize(claimed_len, remaining))
                    if *claimed_len == claimed as usize && *remaining == data.len());
            prop_assert!(ok,
                "expected InvalidSegmentDataSize({claimed}, {}), got {result:?}",
                data.len());
        }
    }
}
