# XTCP QUIC SNI 兼容 — 方案与注意点

**Date:** 2026-08-04
**Status:** implemented (commit `f76aa42`, merged `6d21e30`)
**Related:** audit summary §6 of `2026-08-04-mimalloc-throughput-ab.md`; README "Go frp Compatibility Notes" XTCP bullet.

## 1. 问题背景

Go frp v0.70.1 的 XTCP QUIC visitor 在 QUIC TLS 握手里把**对端地址 `"ip:port"`** 作为 SNI hostname 发送（`client/visitor/xtcp.go` → `NewClientTLSConfig(..., raddr.String())`）。该字符串含 `:`，既不是合法 DNS 名也不是 IP 字面量：

- `pki_types::ServerName::try_from(b"1.2.3.4:7000")` 解析失败
- rustls 服务端 `msgs/handshake.rs` 把它归类为 `ServerNamePayload::Invalid`
- `server/hs.rs` 对 `Invalid` 分支**硬编码 fatal alert**（`illegal_parameter`，`PeerMisbehaved::ServerNameMustContainOneHostName`），拒绝握手

结果：**Go visitor（`protocol="quic"`）永远连不上 Rust provider**。rustls 0.23 全系无配置项可放宽；`ServerConfig::invalid_sni_policy`（`RejectAll` / `IgnoreIpAddresses`(默认) / `IgnoreAll`）只存在于未发布的 0.24-dev。Rust↔Rust 路径不受影响（frp-rs 自己 dial 时传纯 IP，`xtcp_p2p.rs`）。

## 2. 方案：vendored rustls + 一行 server 侧 patch

```
vendor/rustls/                      # rustls 0.23.41 源码（约 1.9M，src 占主体）
  src/server/hs.rs                  # 唯一改动点（grep "frp-rs vendored patch" 定位）
  Cargo.toml                        # 已移除 [[bench]]/[[example]] 段（对应目录已删）
Cargo.toml                          # [patch.crates-io] rustls = { path = "vendor/rustls" }
Cargo.lock                          # rustls 条目变为无 source/checksum（path 依赖）
frp-core/tests/xtcp_quic_sni.rs     # 回归测试（手工 TLS 1.3 ClientHello）
```

**patch 内容**（`vendor/rustls/src/server/hs.rs` 的 `ServerNamePayload::Invalid` 分支）：

```rust
Some(ServerNamePayload::Invalid) => {
    // frp-rs vendored patch: ... treat invalid SNI as "no SNI" (upstream
    // 0.24 `invalid_sni_policy = IgnoreAll`). Drop when moving past rustls 0.23.
    None
}
```

改动前是 `return Err(send_fatal_alert(IllegalParameter, ...))`。语义与上游对 `IpAddress` 的既有处理（hs.rs 注释：RFC 6066 违规客户端当作"没发 SNI"）一致，也与 0.24 `IgnoreAll` 等价。

## 3. 注意点（维护与后续）

### 3.1 版本冻结与安全更新（最重要）
- vendored 把 rustls 钉死在 **0.23.41**，上游 0.23.x 的**安全修复不会自动流入**（`[patch]` 没有版本更新机制）。
- **每次 rustls 发新版 0.23.x 时**：对比上游 diff → 同步 vendor 目录 → 复核 patch 仍适用（上游 `hs.rs` 的 `Invalid` 分支可能漂移）。
- **drop 时机**：workspace 整体升级到 rustls ≥ 0.24 稳定版（含 quinn 对 rustls 0.24 的支持）后，删除 `vendor/`、`[patch.crates-io]`、回归测试可改为用 `invalid_sni_policy = IgnoreAll` 原生配置。

### 3.2 patch 影响面
- `[patch.crates-io]` 替换的是**全 workspace 唯一**的 rustls 条目：quinn、quinn-proto、reqwest、hyper-rustls、rustls-platform-verifier 全部共享 vendored 版（Cargo.lock 里只有这一个 rustls）。
- patch **只改 server 侧** `hs.rs`；client 侧 `ServerName::try_from` 的严格校验不变（Rust 客户端仍无法构造非法 SNI）。grep 验证：vendor 全目录仅此一处改动。
- **安全评估结论**（详见 audit note §6）：SNI 在 frp 服务端仅用于单证书选择，无认证/授权含义；XTCP QUIC 是自签 + InsecureSkipVerify 场景；接受非法 SNI 当"无 SNI"不构成降级。vhost HTTPS 的 SNI 路由是 rustls 之外的自研解析（`vhost.rs`），不受影响。

### 3.3 vendor 目录卫生
- 只保留 `src/`、`Cargo.toml`、`build.rs`、LICENSE*、README.md；**删除了 `benches/`、`examples/` 及 Cargo.toml 对应声明**（不删会引入无用编译目标）。
- `Cargo.toml.orig` 已删——重跑 `cargo vendor` 会产生 git 噪音，手动同步时注意。
- `testdata/`、`tests/` 目录缺失无碍：rustls 内部对它们的 `include_bytes!` 引用都在 `#[cfg(test)]` / `#![cfg(bench)]` 门控下。

### 3.4 回归测试的构造要点（改测试时必读）
`frp-core/tests/xtcp_quic_sni.rs` 手工构造 RFC 8446 TLS 1.3 ClientHello，**不要**依赖 rustls client（client 侧无法构造非法 SNI）。要点：
- 必须带 `supported_groups` 扩展——rustls 用 `named_groups`（而非 key_share）选 kx group，缺失报 `NoKxGroupsInCommon`。
- `key_share` body 需 `client_shares` list 长度前缀（2 字节）+ entry（group + key_len + key）。
- `supported_versions` body 需 list 长度前缀（`01 03 04`）。
- server_name 扩展：`ServerNameList` = list 长度 + `{name_type(1)=0x00, len, hostname}`。
- X25519 公钥任意 32 字节即可（不完成握手，只读 server 首飞）。
- 断言：`process_new_packets` 不返回 SNI fatal + 输出首飞以 `0x16 0x03 0x03`（TLS 1.3 ServerHello）开头；fatal alert 记录是 `0x15`，可区分。
- 测试文件顶部 `#![cfg(feature = "tls")]`（`--no-default-features` 下不能编译，frp-core 的 `rustls` 是传递依赖）。

### 3.5 验证方法
- 单测：`cargo test -p frp-core --features quic,tls --test xtcp_quic_sni`（2 个用例：非法 SNI + 合法 SNI 对照）。
- 回归：patch 影响全 workspace TLS，改 vendor 后必须跑 `cargo test`（参考：本次 frp-core 433 / frp-client 108 / frp-server 135 全绿）。
- **遗留缺口**：当前验证止于 rustls 握手层（单元级）；真实 Go visitor → Rust provider 的 QUIC 数据平面 e2e 需要公网 NAT 环境——由 CI 的 XTCP compat 矩阵（VPS）覆盖，下次运行时确认。

### 3.6 Go 侧行为（兼容目标，勿改）
- Go visitor 发 `raddr.String()`（"ip:port"）是 v0.70.1 的既有行为，Go 服务端本身宽松（忽略非法 SNI），所以 Go↔Go 一直正常；只有 rustls 严格拒绝。
- 不要尝试让 Go 端改（已部署的 Go 客户端不受控）；本方案在 Rust 服务端兼容。
