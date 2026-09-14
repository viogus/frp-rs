# frp-rs 性能专项审计报告

- 日期：2026-09-14
- 方法：4 路并行只读静态审计（热点分配/拷贝、tokio 异步效率、锁与数据结构、帧编解码与 mux 窗口）+ 3 路独立对抗验证（逐条反证，行号复核）
- 范围：数据面（bridge relay / cipher / UDP / WS / KCP / QUIC / yamux）与控制面高频路径（accept、vhost、nathole、dashboard）
- 状态：静态分析已完结；**Phase 1 全部 7 项已实现**（Wave 1 提交 `e7c6f0b`、Wave 2 提交 `8d2c201`），Phase 2 待门禁通过后实施；门禁基线 2078/0 + compat 86/86 + matrix 11/11

## 修订记录（对抗验证轮，2026-09-14）

全部 35 项发现经 3 个独立 verifier 逐条反证，机制无一被完全推翻；以下修正已并入正文：

1. **成本模型修正**：tokio 1.53 中 `Sleep` 的 timer 节点内联、`Timer` 首次 poll 才创建 —— "每迭代堆分配"类表述全部改为"时间轮注册/移除 + `Handle::current()` + `Instant::now()`，无堆分配"（TOP 2、xtcp_session、service.rs:3781、control/mod.rs:577）
2. **严重度修正**：`service.rs:3781`、`control/mod.rs:577`、`prom.rs:171`、`dashboard save_store` 降级 —— `select!` 求值但不 poll 禁用臂、prometheus/dashboard 为 opt-in 且无数据面写者
3. **机制修正**：yamux 窗口低期不是 ~10s —— 首个 PING 立即可发（`RttState::Waiting { next: Instant::now() }`，rtt.rs:36-38），样本 ~1 RTT 内到达；`mux.rs:856` 的 keepalive 重建不受 bulk 流量影响（`poll_next_inbound` 的 Ready 集不含数据帧）
4. **"有意设计"标注**：per-read UDP deadline 是 Go `SetReadDeadline` 对齐（bridge.rs:1560-1572）；384 MiB 连接窗口预算是文档化设计（mux.rs:295-318，cap 仅限窗口 GROWTH）
5. **行号勘误**：`vhost_h2c.rs` 8192 切片在 1813（非 1815）；`metrics.rs` 的 relay 记录点在 bridge.rs:2109/2121/2139/2607（非 3139，3139 是 `get_or_create`）
6. **细节勘误**：`TcpMuxRoute` 有 6 个 String 字段（非 5）；`vhost_h2c.rs:1851` 是 1 次分配（`Bytes::from` 对 capacity==len 的 Vec 走零拷贝 move）；`xtcp_p2p` 探针每包 ~6 次分配（非 4-5，含 uuid/sid/加密输出）

7. **实施修订（2026-09-15，"全修"授权后）**：Phase 1 落地过程中的审核修正 —— 看门狗 select 臂序必须把读臂放在 idle 臂之前（biased 顺序决定同时就绪时谁赢，旧 `timeout()` 先 poll 内层读）；`prom.rs` 落地形态由"快照后释放锁"改为 per-proxy remove+条件 insert（同锁单点）；`BytesMut` 零拷贝项经成本核算放弃；tcpmux/vhost/vhost_h2c 由 2b 提交的 fmt 未清由中央统一 `cargo fmt`

---

## 0. 已优化且验证干净的路径（避免重复劳动）

经过 15+ 轮加固，以下热点路径在本次审计中**没有发现新问题**，不要重做：

| 模块 | 状态 |
|------|------|
| `frp-core/src/bridge.rs` 明文/加密 relay 核心 | 干净：PoolGuard 32 KiB 缓冲池、splice(2) Linux 零拷贝、批量 flush、zero-copy write_all |
| `frp-core/src/cipher_stream.rs` | 干净：CipherReader 原地解密进 caller ReadBuf；CipherWriter 复用 scratch；`with_capacity` 在 `iv_sent` 门内（每连接一次） |
| `frp-core/src/buffer_pool.rs` | 干净：无锁 ArrayQueue |
| `frp-core/src/kcp/`（协议、socket driver） | 干净：单 `interval(10ms)` 在循环外创建，零锁，chunk pool + snd_data_pool 复用，单次拷贝分段 |
| `frp-server/src/service.rs` accept 循环 | 干净：`try_acquire_owned` + 提升到循环外的 rate-limit 标志，dispatch 走 DashMap 无锁读 |
| `frp-client/src/work_conn.rs` | 干净：interval 循环外创建、无每包 timeout、无跨 await 持锁 |
| `frp-server/src/control/pool.rs` | 干净：PendingRequest 携带 `Arc<ProxyInfo>`，bridge 时无 map 重锁 |
| `frp-core/src/mux.rs` `open_stream` | 干净：零锁，pending_opens 为 task 本地 VecDeque |
| `frp-core/src/msg.rs` untagged 枚举 | 无成本：V1/V2 按 type byte 分发到具名 struct，untagged 不在 wire decode 路径 |

---

## 1. Top Performance Bottlenecks（性能瓶颈排行榜）

### TOP 1 — QUIC 流接收窗口固定 1.25 MB，高 BDP 链路上限严重（HIGH，已完整验证）

- 位置：`frp-core/src/quic.rs:199-214`，函数 `build_quic_transport_config`
- 代码事实：

```rust
fn build_quic_transport_config(params: &QuicTransportParams) -> quinn::TransportConfig {
    let mut transport = quinn::TransportConfig::default();
    ...
    transport.max_concurrent_bidi_streams(...);
    transport   // ← 从未调用 stream_receive_window()
}
```

- 风险：quinn-proto 0.11.17 默认 `stream_receive_window = 1,250,000 B`（`config/transport.rs:363-370`：`STREAM_RWND = MAX_STREAM_BANDWIDTH/1000*EXPECTED_RTT`，按 100 Mbit/s @ 100 ms RTT 设计），**该值在 quinn-proto 内只读、无自动调优**（`connection/streams/recv.rs:112`）。单流吞吐上限 = 窗口/RTT：
  - 50 ms RTT → ≈ 200 Mbps 封顶
  - 100 ms RTT → ≈ 100 Mbps 封顶
- 对比：yamux 路径已对齐 Go 的 6 MiB/流（`mux.rs:333`），QUIC 路径无任何配置项可调
- 影响面：4 个 QUIC 面全部走此配置（quic.rs:279/437/508/561），XTCP tunnel 用 `QuicTransportParams::default()`（xtcp_p2p.rs:1349、xtcp_session.rs:1145）。注意默认 transport 是 TCP（config/client.rs:563 `default_transport_protocol() -> "tcp"`），仅显式配置 QUIC 的用户受影响 —— 但受影响即硬上限
- 验证动作：改窗口前后跑 `bash scripts/throughput-baseline.sh` + `tc netem` 模拟 RTT

### TOP 2 — V1 UDP 数据面：每包 `serde_json::to_vec` + base64 中间 String（HIGH，已完整验证）

- 位置：`frp-core/src/protocol.rs:18`（`write_v1_frame`）+ `frp-core/src/msg.rs:81-83`（`b64_ser`）
- 代码事实：

```rust
// protocol.rs:18
let buf = serde_json::to_vec(msg)   // 每帧 1 个 Vec 分配
    .map_err(...)?;

// msg.rs:81-83 — UDPPacket.content 每包走这里
fn b64_ser<S: Serializer>(data: &[u8], s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&crate::base64::encode(data))  // String::with_capacity (base64.rs:46) + 再拷入 JSON buf
}
```

- 风险：每个 V1/JSON UDP 包 ≈ 2-3 次堆分配 + 2 次全量 payload 拷贝（base64 膨胀 4/3，再被 `serialize_str` 拷进 JSON 缓冲区）。1 KB payload @ 10k pps ≈ 2 万次分配/秒 + ~28 MB/s 额外 memcpy
- 影响面：**V1 连接和未协商 binary codec 的 Go 对端**。调用点：bridge.rs:1852、work_conn.rs:1363、visitor.rs:2285/2383。Rust↔Rust 及 Go v0.71.0 协商 `binary-v1` 后走 V2 type-19 二进制路径（写入 caller scratch，protocol.rs:827-865），不受影响
- 对照：V2 写路径已有 scratch 参数（`write_msg_v2_inner`），V1 不对称

### TOP 3 — nathole 控制器：全局 sessions 写锁跨两层嵌套 await 持有（HIGH，已完整验证）

- 位置：`frp-server/src/nathole/controller.rs:318-333`，函数 `complete`
- 代码事实：

```rust
pub async fn complete(&self, sid: &str) -> Option<String> {
    let mut sessions = self.sessions.write().await;      // 全局写锁, 函数作用域绑定活到 :333
    if let Some(session) = sessions.remove(sid) {
        let mut guard = session.visitor_writer.lock().await;  // await #1，写锁仍持有
        drop(guard.take());
        drop(guard);
        if let Some(tx) = session.report_tx.lock().await.take() {  // await #2，写锁仍持有
            let _ = tx.send(...);
```

- 风险：`visitor_writer`（tokio Mutex）的其他持有者把锁跨网络写持有 —— `dispatch.rs:867-869` 每次 NatHoleVisitor 帧持锁写 `write_msg(...).await`，一个慢 visitor 即卡住 `complete`；`take_writer`（controller.rs:358）持 `sessions.read()` 期间取同一把锁，反向放大成整个 session 表的写饥饿。`expire_sessions`（343-349）同样持写锁做全表 `retain` + 每项 std Mutex（60s janitor，service.rs:1461-1469）
- 修复方向：先从 map `remove` 出 session、**释放写锁**，再逐项锁 per-session 字段

### TOP 4 — vnet visitor：每包每代理重建 RouteTable + CIDR 解析（HIGH，仅 vnet opt-in 构建）

- 位置：`frp-client/src/visitor.rs:2678`（`#[cfg(feature = "vnet")]`，每入站包进入，:1094）
- 代码事实：

```rust
subnets.get(proxy).is_some_and(|cidr| {
    let mut rt = frp_vnet::router::RouteTable::new();   // HashMap 分配 (router.rs:144-148)
    rt.insert("", proxy, cidr)                           // 每插入重跑 Net::parse + entry 分配
        .is_ok()
})
```

- 风险：每包 × 每注册 TUN 代理重建路由表只为测一个地址；命中后 `tx.try_send(packet.clone())`（2685）整包深拷、未命中路径每包 collect `Vec<&Sender>`（2705）。CIDR 在代理注册后不变，应预编译为 `Arc` 共享前缀集做 O(1) 查询
- 影响面：**仅 `vnet` feature 构建**（frpc/frps 默认二进制均不含 vnet）；vnet 用户下这是每包开销

### TOP 5 — yamux 每流窗口爬坡：新流前 ~1 RTT 钉在 256 KiB，增长需 RTT 样本（MED）

- 位置：`vendor/yamux/src/connection/stream/flow_control.rs:81-86` + `rtt.rs:36-38`
- 代码事实：

```rust
if self.rtt.get()
    .map(|rtt| self.last_window_update.elapsed() < rtt * 2)
    .unwrap_or(false)          // ← 无 RTT 样本期间永远 false, 窗口不增长
{ ... 翻倍窗口 ... }
// rtt.rs:36-38: 首个 PING 立即可发 (next: Instant::now()), 样本 ~1 RTT 内到达
```

- 风险（已按对抗验证修正幅度）：新流初始 credit = `DEFAULT_CREDIT` 256 KiB（vendor/yamux/src/lib.rs:45；frp-rs 只设增长 cap，mux.rs:333）。首 RTT 内单流吞吐 ≈ 256 KiB/RTT（100 ms RTT → ≈ 20 Mbps）；样本到达后翻倍仍要求发送端在 2 RTT 内耗尽半数 credit。**不是此前声称的 10s 低窗**（PING 立即可发），但高 BDP 大文件单流经 tcp-mux 仍有一段爬坡期
- 对比 Go：hashicorp yamux fork 直接钉 6 MiB/流，无此门控
- 候选修复（§3 Phase 2-2）需压测对比后再定

### 完整发现清单（按严重度排序，行号经 3 路独立复核）

#### HIGH（4 项）

| # | 位置 | 问题 |
|---|------|------|
| 1 | `frp-core/src/quic.rs:199` `build_quic_transport_config` | QUIC 流接收窗口固定 1.25 MB，quinn-proto 0.11.17 无调优、无配置项（TOP 1） |
| 2 | `frp-core/src/protocol.rs:18` + `msg.rs:81` `b64_ser` | V1 UDP 每包 `serde_json::to_vec` + base64 String，2-3 分配 + 2 次全量拷贝（TOP 2） |
| 3 | `frp-server/src/nathole/controller.rs:318` `complete` | 全局 sessions 写锁跨 `visitor_writer.lock().await` + `report_tx.lock().await` 持有；与 dispatch.rs:867 的跨写持锁互相放大（TOP 3） |
| 4 | `frp-client/src/visitor.rs:2678`（vnet） | 每包每代理重建 `RouteTable` + CIDR `Net::parse`，命中整包 clone（TOP 4） |

#### MED（12 项）

| # | 位置 | 问题 |
|---|------|------|
| 5 | `vendor/yamux/.../flow_control.rs:84` | 新流前 ~1 RTT 窗口钉 256 KiB，增长需 RTT 样本（TOP 5） |
| 6 | `frp-server/src/control/bridge.rs:1643` UDP reader | 每数据报重建 `timeout` future。**已核验无堆分配**（tokio 1.53 timer 节点内联、`Timer` 首次 poll 才建）——真实成本：时间轮 insert/remove + `Handle::current()` + `Instant::now()`/迭代，含被 cancel 臂虚假唤醒的迭代；客户端无此超时（work_conn.rs:858-879）。**这是 Go `SetReadDeadline` per-read 对齐的有意设计**（bridge.rs:1560-1572），修的是实现形态（看门狗化），不是语义 |
| 7 | `frp-core/src/xtcp_session.rs:711` | 每 tick 重建 `timeout(10ms)`：活跃 XTCP 会话 ~100 次/秒时间轮注册（无分配）；空闲自适应 1000ms（96-102, 667-677） |
| 8 | `frp-core/src/mux.rs:80` | `MAX_PENDING_OPEN_REQUESTS=64`，满则**拒绝**新 open（不排队）；慢对端下 >64 并发建流直接失败 |
| 9 | `frp-core/src/mux.rs:321` | 连接窗口 384 MiB vs 1024 流 × 6 MiB cap。**已文档化的有意预算**（mux.rs:295-318：256 MiB 保留 + 128 MiB 共享增长），cap 仅限窗口 GROWTH —— 超 ~23 流时每流增长被提前截断，属已知权衡，列为确认项而非缺陷 |
| 10 | `frp-server/src/handlers/dispatch.rs:867` | 每 NatHoleVisitor 帧 `visitor_writer.lock()` 持锁跨网络写 `write_msg(...).await`；一个 stall 的 visitor 卡住该 session 所有写者，并经 `take_writer`/`complete` 放大到 sessions 表（与 HIGH #3 联动） |
| 11 | `frp-server/src/control/nathole.rs:1265`（vnet） | 每 VnetPacket 对 vnet_routes 嵌套扫描 + 按过滤后候选 clone（O(m·n)，m = 同名路由数；非 O(n²)）；64 路由 cap 是 **per-run_id**（:1091-1109），全局 = 64 × 客户端数；read guard 在 1199 二次获取。vnet opt-in |
| 12 | `frp-server/src/vhost_h2c.rs:493` | 每 h2 DATA 帧 `format!("{:X}\r\n", len)` 堆 String（chunk-size 行）。门控：仅**无 Content-Length 的请求体**走 chunked 臂；请求腿冷于响应腿 |
| 13 | `frp-server/src/vhost_h2c.rs:1524/1830/1851` | 响应体中继每 64 KiB `Bytes::copy_from_slice`（chunked 路径）；CL 路径 8192 字节切片（**:1813**）使拷贝率 4×，且 `read_exact_into`（1343-1349）每切片 `clear+resize(n,0)` 多一次零填充 memset；close-delimited 路径（1851）`to_vec()`+`Bytes::from` = **1 次分配**（capacity==len 时 `Bytes::from` 走 `into_boxed_slice` 零拷贝 move）。`send_data(B)` 收 owned 值（h2 0.4.18 share.rs:334），`BytesMut` 读进 spare + `split_to().freeze()` 可免拷贝。整文件 `#[cfg(feature = "http-proxy")]`（默认 frps 含，tiny/micro 不含） |
| 14 | `frp-server/src/vhost.rs:2735` | 每非-CONNECT 请求 `peer.ip().to_string()` 堆 String 只为取字节（IP ≤ 45 字节）。门控：配置了 `x-forwarded-for` requestHeader 覆盖时跳过（2733） |
| 15 | `frp-server/src/vhost.rs:2330/2334` | `rewrite_host_header` 每请求 char 过滤 String + `format!` 发一行 header；`new_host` 是注册期固定的 `Arc<str>`（vhost.rs:53/80），消毒结果每注册不变、**可完全提升到请求路径外**。门控：仅配置了 `host_header_rewrite` 的路由（1431） |
| 16 | `frp-core/src/transport/websocket.rs:322/329` | 超 caller ReadBuf 的 WS 帧余量 `to_vec()` 换新缓冲丢容量；`MAX_WS_FRAME_PAYLOAD` 65,664（:27）vs bridge `BUFFER_SIZE` 32 KiB → 64 KiB 帧每读多一次整拷 |

#### LOW（17 项，随 Phase 1 顺带清理）

| 位置 | 问题 |
|------|------|
| `frp-server/src/vhost.rs:834` | 滴流 head 循环每读重跑全缓冲 O(n) `head_end`（O(n²)）；`HeadEndScanner` 已在 vhost_h2c.rs:937/bridge.rs:177/transport 使用（h2c 侧 929-941 注释明言 "round-18 C2 … O(n²)…scanner 已修"，此站漏修）。MED 偏宽：4096 上限内，问题在于不一致 |
| `frp-server/src/proxy.rs:598/657` | 每 TCP-group 连接 `group.to_string()` 在 std Mutex 内分配（no-health 快路径，pool.rs:701-713 调用） |
| `frp-server/src/state.rs:717-719` | 每 group HTTP 请求 `(group.to_string(), is_https)` 元组键分配 + 外读锁下嵌套 `members.read()`（vhost.rs:1373、tcpmux.rs:629 调用） |
| `frp-server/src/tcpmux.rs:265-270` | 每 tcpmux CONNECT `.cloned()` 深拷 **6** 个 String 字段（tcpmux.rs:14-29）；vhost 已用 `Arc<str>`（vhost.rs:78-105），tcpmux 应对齐 |
| `frp-server/src/vhost.rs:976/1015` | `count_host_headers` 每请求 2 次全量线性扫描（>1 检查 + ==0 门，非-CONNECT 头走两遍）；O(head)、无分配，第二遍可复用第一遍计数 |
| `frp-server/src/vhost.rs:1986-1993` | 每请求为 Host 值分配 owned String（值还被 class-3 校验消费，非仅 obs-fold；`Cow::Borrowed` 可免无 fold 场景分配） |
| `frp-server/src/vhost.rs:2418/2465` | `strip_vhost_hop_by_hop_headers` 每 Connection token `to_vec()`（后续比较全在 `&[u8]`，`Vec<&[u8]>` 可编译）。仅带 Connection 头的请求 |
| `frp-server/src/vhost.rs:719` | `buf[..n].to_vec()` 精确容量：1 字节首读 ≈ 12 次 amortized 倍增 realloc；正常 2 读头 = 1 次，常见单读 = 0 次 |
| `frp-server/src/control/bridge.rs:41/47` | 每桥接连接 2 次 `to_string()`（src/dst 地址，唯一调用点 :3083）；1717 是 zoned-IPv6 回退臂（正常路径 1711 零分配直发） |
| `frp-core/src/encryption.rs:496-507` | Snappy 解压帧 CRC 验证后 `extend_from_slice` 二拷；可直解压进 out 尾部 |
| `frp-core/src/bridge.rs:623-633` | 压缩臂每外层读迭代 flush 一次（明文臂只在短读时 flush）——缓冲传输上多一次 flush |
| `frp-core/src/msg.rs:86` `b64_de` | V1 UDP 解码每包 owned String 中间量 |
| `frp-core/src/udp_binary.rs:89-91` | 每数据报重解析 loop-invariant 的 local addr String（CPU only；work_conn.rs:1209 只预建 String 非 IpAddr） |
| `frp-core/src/xtcp_p2p.rs:205` | 每探针包 ~6 次分配（nonce String + uuid + sid + serde Vec + 加密输出）；仅 punch 阶段 ≤60s，2048 probe cap + 2ms 间隔，LOW 恰当 |
| `frp-core/src/metrics.rs:96/106` | `TrafficHistory.state` std Mutex —— **per-proxy**（`ProxyMetrics.daily`），竞争仅在同代理连接间；relay 记录点在 bridge.rs:2109/2121/2139/2607 + SUDP 每 64 包（2891/2896/2977/2982），非 3139（那是 `get_or_create`） |
| `frp-client/src/service.rs:3781` | 每控制帧重建心跳 `Sleep`。**无堆分配**（tokio 1.53：`select!` 求值但不 poll 禁用臂，`Timer` 首次 poll 才建）；成本 = `Instant::elapsed()` + `Handle` clone，LOW |
| `frp-server/src/control/mod.rs:577-647` | 主控制 select! 每轮重建 sleep_until/notified 臂。**无堆分配**（臂为 async block，poll 时才构造；Sleep 重注册 = 时间轮 shard 锁 + insert）；臂 1 deadline 停车期间不变可缓存 |
| `frp-core/src/mux.rs:856` | client yamux keepalive 用 `sleep` 非 `interval`：**被新流建立等臂胜出时**重建并推迟探测（"流量饿死检测"已反证 —— `poll_next_inbound` 的 Ready 集不含 bulk 数据帧）；server_mux 无 keepalive 臂（490/658） |
| `frp-server/src/metrics/prom.rs:171` | `LAST_TRAFFIC` 全局 tokio Mutex 持满 N-proxy 遍历（每 scrape 内再逐代理 read+Arc clone）。**opt-in**：dashboard feature + `enable_prometheus` + 可选 admin auth；唯一其他持有者是 `proxy_removed`（代理删除时），无数据面写者 —— 两个并发 scrape 才串行 |
| `frp-server/src/dashboard.rs:1101/1234/1317` + `store.rs:64` | `save_store`：同步 JSON 序列化 + `std::fs::write`+`rename`+`set_permissions` 直接在 async handler 上跑，前接全 map 深 clone。**opt-in** dashboard feature，每 admin 写操作一次（1036/1158/1252），非每代理增删；改 `spawn_blocking` 属整洁性 |
| `frp-client/src/service.rs:2931/2226`（vnet） | CloseProxy 臂 health_cancels+p2p_bridge_tokens 守卫跨 `cfg.read()` + `remove_vnet_tun(...).await`（到 3011）；proxy_info_map 写守卫跨 `open_vnet_tun_for_proxy(...).await`（TUN ioctl）。vnet opt-in，vnet 关闭时该尾段无 await |
| `frp-client/src/visitor.rs:1935`（vnet） | SUDP 本地收包每包 `to_vec()` + 源 IP String |

注：`frp-core/src/bandwidth.rs:73`（每 chunk 锁）为有意设计（reserve 在锁内、sleep 在锁外），不列为问题。

**严重度与门控说明**：HIGH #4、MED #11、LOW 末 3 项均被 `vnet` feature 门控（**所有出厂默认二进制均不含 vnet**）；LOW 的 prom/store 被 dashboard/prometheus opt-in 门控。按默认二进制命中面计算，真正无条件进入数据面的 HIGH 只有 #1-3。

---

## 2. Benchmarking & Profiling Strategy（基准测试与剖析）

### 2.1 现有基础设施（无需新造）

- **criterion 微基准**：`frp-core/benches/`（crypto_bridge.rs：密钥派生/压缩/cipher/bridge 各组合；nathole.rs；proxy_registration.rs）+ `frp-server/benches/`
- **e2e 基线与矩阵**：
  - `scripts/throughput-baseline.sh`（每 cipher/transport 组合 MB/s）
  - `scripts/latency-baseline.sh`（稳态 RTT + 建连分位）
  - `scripts/memory-baseline.sh`（idle-hold + churn，mem-profile CountingAlloc）
  - `scripts/protocol-matrix.sh`（11 行 transport 矩阵，mbps>0 断言）
  - `scripts/udp-pps-bench.sh`（UDP PPS——TOP 2/6 的直接验证工具）
  - `scripts/ab-matrix.sh` + `scripts/stress-test.sh`（周级 CI）

### 2.2 需要补充的基准（对应本报告 TOP 项）

1. **QUIC 窗口扫描（TOP 1）**：`throughput-baseline.sh` 基础上加 `tc netem` RTT 维度（10/30/100 ms），对比 `stream_receive_window` = 1.25 MB（现状）/ 6 MiB / 16 MiB。这是**落任何 QUIC 窗口改动的前置验证**
2. **UDP PPS 微基准（TOP 2）**：criterion 新增 `write_v1_frame` 单包串行化 bench（用 `mem-profile` CountingAlloc 统计每包分配数），V1 JSON vs V2 binary 并排。断言目标：修复后 V1 路径每包分配数从 3 降到 ≤1
3. **yamux 窗口爬坡（TOP 5）**：单流前 5s 吞吐时间序列，测从 256 KiB credit 爬到 6 MiB 的时间（`tc netem` 50ms + protocol-matrix 风格单流跑量）；对比 Go frp 同场景
4. **Timer churn 基准（MED #6/7）**：tokio select! 循环压 N 包，对比 per-read timeout vs 看门狗模式的时间轮操作数（可用 `tokio::time::pause()` 测试时钟在 criterion 里稳定复现）

### 2.3 Profiling 工具建议

| 工具 | 用途 | 备注 |
|------|------|------|
| `cargo flamegraph` / `samply` | 数据面 CPU 火焰图 | 跑 `udp-pps-bench.sh` 或 stress-test 场景采集；samply 对 tokio 任务栈解析更好 |
| `perf record -g` | 内核+用户态系统调用占比 | 验证 splice 命中率、timerfd 系统调用占比 |
| `valgrind --tool=massif` | 堆分配剖面 | 短时运行，定位每包分配峰值；与 CountingAlloc 计数交叉验证 |
| `tokio-console` | 任务唤醒/等待分析 | 需 `tokio_unstable` cfg 的单独构建（**不要**进默认 profile）；诊断 select! 虚假唤醒频率 |

采集原则：先 `RUST_LOG=off` + release 构建跑压测，再做剖析；每次改动前后双跑 `throughput/latency/memory` 三轴基线（门禁：任一轴 >5% 回退即否决）。

---

## 3. Actionable Refactoring Blueprint（重构路线图）

### Phase 1 — Low-hanging Fruit（小改动大收益，约 2-3 个工作日）

**落地状态（2026-09-15）**：7 项全部实现，两波提交：

| # | 项 | 提交 | 落地要点 |
|---|----|------|---------|
| 1 | V1 UDP 序列化去分配 | `e7c6f0b` | `write_v1_frame_scratch`（scratch 清空+序列化进尾，Err 路径再清，9 字节头不变，字节级 pin）+ `B64` 流式 base64（`collect_str`，零中间 String）+ Snappy 直解 caller 尾 |
| 2 | nathole 锁缩短 | `8d2c201` | `complete()` remove 后放锁再取 per-session 锁；`expire_sessions()` 读锁扫描收集过期 id、逐个 `remove`（sid 为客户端生成 UUID，scan-then-remove 复用窗口仅自伤，无跨客户端风险） |
| 3 | UDP reader 看门狗 | `8d2c201` | 持久 `UdpFrameReader`（reader+scratch 帧间驻留）+ 滑动 60s deadline；**biased 臂序保持旧 timeout 语义**（帧与 deadline 同时就绪 → 送帧不丢包）；回归测试 `udp_work_reader_frame_activity_slides_the_read_deadline` |
| 4 | vhost 每请求分配 | `8d2c201` | sanitize 提升到注册期（`Arc<str>`，请求期零分配）+ `HeadEndScanner` 增量扫描 + 单遍 `count_host_headers` + `Vec::with_capacity(4096)` + XFF 栈写 |
| 5 | vhost_h2c 帧路径 | `8d2c201` | chunk-size 行栈缓冲 `[u8;16]`（h2 DATA ≤ 2^24-1 → ≤6 hex digits，无溢出）+ `read_exact_into`；**`BytesMut split_to().freeze()` 经审核放弃**（split_to 仍 memcpy/memset，spare-fill 需首个 unsafe，收益不达门槛） |
| 6 | websocket read_buf 复用 | `e7c6f0b` | stash 路径 `clear()`+`extend_from_slice` |
| 7 | 零散 | 混合 | proxy 键 `get_mut`+entry 兜底、tcpmux `Arc<TcpMuxRoute>`、store `spawn_blocking`、prom per-proxy remove+条件 insert（消除重注册假 delta）+ 锁外累加、xtcp_session Sleep 复用、mux keepalive `interval_at`、control/mod 臂 1 deadline 缓存、dispatch take/write/return；**Wave 2d 追加**：`udp_binary` 新增 `PreEncodedUdpAddr`/`encode_udp_packet_binary_local_pre`/`encode_udp_packet_binary_socket_addr_local` —— 双侧 binary-v1 写循环每包 ip 解析归零（server 桥期 pre-encode，client 直用已解析 SocketAddr），字节等价 pin（v4/v6/mapped/zoned） |

按收益排序，每项独立可 PR：

1. **V1 UDP 序列化去分配（TOP 2）**：`write_v1_frame` 增加 scratch 参数（对齐 V2），`b64_ser` 改流式（`collect_str` + 增量 base64），`b64_de` 去中间 String。见 §4 示例 B
2. **nathole `complete` 锁缩短（TOP 3）**：`controller.rs:318-333` remove 后立即 drop 写锁再取 per-session 锁；`expire_sessions` 先读锁收集过期 id、再逐个删；`dispatch.rs:867` 写入先拷贝消息再放锁（消息小，拷贝 << 持锁写）
3. **UDP reader 看门狗化（MED #6）**：`bridge.rs:1634-1676` 把 per-read `timeout` 换成持久读 future + `sleep_until(last_activity + read_timeout)` 臂，仅真实收包时滑动 deadline。消灭虚假唤醒迭代的时间轮操作与 `Handle::current()`（无堆分配，收益在 PPS 极高时）
4. **vhost 每请求分配清理**：`vhost.rs:2735`（IP 用栈缓冲/预计算字节）、`2330`（消毒结果提升到注册期，请求期零分配）、`834`（换 `HeadEndScanner`，与 h2c 侧一致）、`976/1015`（单遍 count_host_headers）、`719`（容量提示 `Vec::with_capacity(4096)`）
5. **vhost_h2c 帧路径（MED #12/13）**：`493` chunk-size 行用栈缓冲 `[u8;16]` + `write!`；`1524/1830` 换 `BytesMut` 读进 spare + `split_to().freeze()`（免 memcpy 免 memset）；`1813` 8192→32 KiB 切片；`1851` 保持现状（已是 1 分配零拷贝 move）
6. **websocket read_buf 复用（MED #16）**：`322/329` 持久 `Vec` + `clear()`+`extend_from_slice`
7. **零散**：`proxy.rs:598` 键预计算（entry API）、`tcpmux.rs:265` 换 `Arc<TcpMuxRoute>`、`store.rs:64` 包 `spawn_blocking`、`prom.rs:171` 快照后释放锁再遍历、`xtcp_session.rs:711` 复用 Sleep（deadline 变化才 reset）、`mux.rs:856` 改 `interval`、`control/mod.rs` 臂 1 deadline 缓存

### Phase 2 — Architecture / I/O 重构（每个约 1-3 天，含基准验证）

1. **QUIC 窗口（TOP 1）**：`build_quic_transport_config` 接入 `stream_receive_window`（Go 对齐建议 6 MiB 起步，配置可调），同步检查 quinn connection_receive_window。**先跑 §2.2-1 窗口扫描再定值**；改动后走 protocol-matrix + compat 双门禁
2. **yamux 窗口暖启动（TOP 5）**：三选一，需压测对比：
   - a) 流建立时立即触发 PING 采样（首 RTT 即得样本，缩短爬坡）
   - b) 无样本时用保守种子值（如 100 ms）门控首次翻倍
   - c) 把 `DEFAULT_CREDIT` 提到 512 KiB/1 MiB（与 Go 6 MiB 目标的折中）
   - 同时评估 `mux.rs:321` 384 MiB 连接窗口是否需随 6 MiB×1024 上调（或降 `max_num_streams`）—— 当前 128 MiB 共享增长预算在多流场景先耗尽，属已知权衡
3. **vnet 每包开销（HIGH #4、MED #11）**：代理注册时预编译路由前缀集（`Arc` 共享，O(1) 查询），收包 fan-out 改 `Arc<[u8]>` 单次拷贝；`control/nathole.rs:1265` 按 virtual_net 预分组索引，消除嵌套扫描与每包 clone
4. **UDP 协议面瘦身**：评估在 V2 handshake 里默认强制 `udpPacketCodecs=binary-v1`（Go v0.71.0 已支持），让 JSON UDP 路径退居纯兼容位
5. **锁架构复查**：`nathole/controller.rs` sessions 表分片或读多写少化（complete/expire 改短写）；`metrics` LAST_TRAFFIC 改 per-proxy 原子快照

**每阶段完成后的门禁**（不满足即回退）：
1. `cargo clippy --workspace --all-targets --all-features -D warnings` 零警告
2. `cargo test --workspace --all-features` 全绿（当前 2078/0）
3. `bash scripts/compat-test.sh` 86/86 vs Go frp v0.71.0
4. `bash scripts/protocol-matrix.sh` 11/11
5. 三轴基线（throughput/latency/memory）无一轴 >5% 回退

---

## 4. Example Code Transformation（优化前后对比）

### 示例 A — UDP work-conn 读取：per-read timeout → 空闲看门狗

**Before（`frp-server/src/control/bridge.rs:1634-1676`，每迭代：时间轮 insert/remove + `Handle::current()` + `Instant::now()`；被 cancel/限流臂虚假唤醒的迭代同样全额支付）：**

```rust
let mut scratch: Vec<u8> = Vec::new();
loop {
    let result = tokio::select! {
        biased;
        _ = cancel_reader.cancelled() => break,
        changed = reader_cancel.changed() => { ... continue; }
        result = async {
            match tokio::time::timeout(read_timeout, async {
                if v2 { ... } else { read_msg_v1(&mut w_r).await ... }
            }).await { ... }
        } => result,
    };
    // ... dispatch result ...
}
```

**After（读 future 持久化 + deadline 仅在收包时滑动；语义不变，仍是 Go `SetReadDeadline` per-read 对齐）：**

```rust
let mut scratch: Vec<u8> = Vec::new();
// 持久化读 future: 虚假唤醒不再重建任何东西
let mut read_fut: Option<Pin<Box<dyn Future<Output = Result<UdpBinaryRead>> + Send>>> = None;
// 空闲看门狗: deadline = 上次活动 + read_timeout, 收包才 reset
let mut last_activity = Instant::now();
let mut idle = Box::pin(tokio::time::sleep_until(last_activity + read_timeout));
loop {
    let result = tokio::select! {
        biased;
        _ = cancel_reader.cancelled() => break,
        changed = reader_cancel.changed() => { ... continue; }
        _ = &mut idle => {
            return Err(... /* 60s 无帧 = Go read-deadline 对齐 */);
        }
        r = poll_read(&mut read_fut, &mut w_r, v2, udp_codec_opt, &mut scratch) => {
            // 仅真实包到达时滑动 deadline
            last_activity = Instant::now();
            idle.as_mut().reset(last_activity + read_timeout);
            r
        }
    };
    // ... dispatch result ...
}
```

**成本核算（对抗验证修正后）**：
- Before：每迭代时间轮 insert/remove + shard 锁 + `Handle::current()` clone；虚假唤醒迭代同样支付
- After：仅真实收包时 `sleep.reset()`（一次时间轮更新）；虚假唤醒零成本
- 明确预期：**无堆分配节省**（tokio 1.53 `Sleep` 本就无每迭代分配）；收益 = 极高 PPS 下时间轮操作数与时钟读取的减少，用 `udp-pps-bench.sh` 前后对比确认，未达标不值得做

### 示例 B — V1 UDP 序列化：scratch 复用 + 流式 base64

**Before（`protocol.rs:18` + `msg.rs:81-83`，每包 2-3 次堆分配 + 2 次全量拷贝，已对抗验证）：**

```rust
pub async fn write_v1_frame<W: AsyncWriteExt + Unpin>(
    writer: &mut W, msg: &FrpMessage,
) -> Result<(), crate::Error> {
    let type_byte = msg.v1_type_byte();
    let buf = serde_json::to_vec(msg)   // 分配 #1: JSON 缓冲区
        .map_err(...)?;
    // ... write_vectored(header, buf) ...
}

fn b64_ser<S: Serializer>(data: &[u8], s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&crate::base64::encode(data))
    // 分配 #2: base64 String (String::with_capacity, 4/3 膨胀); serialize_str 再拷入 JSON buf (拷贝 #2)
}
```

**After（scratch 对齐 V2 路径 + base64 直写 serde 输出）：**

```rust
/// 调用方持有一个跨包复用的 scratch (服务端 bridge.rs reader、客户端 work_conn.rs
/// 各在循环外持有), 与 V2 的 write_msg_v2_inner scratch 对称。
pub async fn write_v1_frame_scratch<W: AsyncWriteExt + Unpin>(
    writer: &mut W, msg: &FrpMessage, scratch: &mut Vec<u8>,
) -> Result<(), crate::Error> {
    let type_byte = msg.v1_type_byte();
    scratch.clear();
    serde_json::to_writer(&mut *scratch, msg)   // &mut Vec<u8> 即 io::Write, 零新分配
        .map_err(...)?;
    // ... 同前 write_vectored(header, &scratch[..]) ...
}

/// 流式 base64: 3 字节块 → 4 字节栈缓冲, 直接写入 serde formatter,
/// 无中间 String、无第二次全量拷贝。
struct B64<'a>(&'a [u8]);
impl core::fmt::Display for B64<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut out = [0u8; 4];
        for chunk in self.0.chunks(3) {
            // ... 编码到 out, f.write_str(from_utf8(&out[..n])) ...
        }
        Ok(())
    }
}
fn b64_ser<S: Serializer>(data: &[u8], s: S) -> Result<S::Ok, S::Error> {
    s.collect_str(&B64(data))
}
```

**成本核算**（1 KB payload @ 10k pps，仅非协商 V1 路径支付）：
- Before：~3 万次堆分配/秒（JSON buf 1 万 + base64 String 1 万 + 增长型 realloc），~28 MB/s 额外 memcpy（base64 膨胀 + 二次拷贝）
- After：0 次每包分配（scratch 复用，base64 单遍直写），memcpy 降为单遍编码
- 配套：`b64_de`（`msg.rs:86`）去中间 String，解码侧同样每包省 1 分配

---

## 5. 下一步

1. 评审本报告 TOP 5，按 §3 Phase 1 顺序拆分 PR（每项一个逻辑改动）
2. **最先做 TOP 1 的窗口扫描实验**（§2.2-1）——它不涉代码改动，纯配置验证即可确认收益量级
3. 每个 Phase 1 项落地前补 §2.2 对应的微基准（红-绿验证）

执行命令（首个动作）：
```bash
# 验证 TOP 1 收益量级（改 quic.rs 前先跑基线）
bash scripts/throughput-baseline.sh
```
