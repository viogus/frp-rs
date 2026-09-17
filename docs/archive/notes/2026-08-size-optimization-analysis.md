# frp-rs 二进制体积优化分析(2026-08)

主机:macOS arm64,HEAD `e4815c0`。所有数字为宿主特定值,对比时须在同一台机器、同一代码状态重建基线。

## 当前体积基线(release,strip = "symbols",opt-level = "z",lto = "fat")

| 档位 | frps | frpc | 说明 |
|---|---|---|---|
| 默认(full) | 8.73 MB | 7.80 MB | SSH + QUIC + OIDC + WS + KCP + vnet + tls + tcp-mux + chacha20 + compression |
| tiny | 5.30 MB | 4.82 MB | 无 QUIC/KCP/WS/SSH/OIDC/compression,保留 TLS + http-proxy + tcp-mux |
| micro | 3.42 MB | 3.25 MB | 核心:无 TLS/压缩/chacha20/http-proxy/tcp-mux |

`__TEXT` 代码段占文件 ~92%,优化空间几乎全在依赖机器码;`strip = "symbols"` 已去符号,LTO fat + opt-z + panic=abort 已全开。

## 按 crate 的 .text 分布(cargo bloat --crates,strip=none)

frps(6.7 MiB .text):

| crate | 大小 | 归属 |
|---|---|---|
| std | 1.3 MiB | — |
| frp_server / frp_core | 972 / 605 KB | 自有代码 |
| rustls + ring | 362 + 138 KB | TLS |
| russh + ssh_key + crypto_bigint + primeorder + EC | ~850 KB | SSH feature |
| quinn_proto | 255 KB | QUIC feature |
| h2 | 245 KB | vhost h2c(server)/ https plugin(client) |
| regex_syntax + regex_automata | 196 KB | tracing-subscriber env-filter |
| serde_json | 160 KB | 必要 |
| time | 75 KB | rcgen + tracing-appender |
| yamux | 65 KB | tcp-mux |

frpc 额外:axum(admin API)129 KB、bpaf(CLI)~102 KB、hyper/reqwest(OIDC)~230 KB。

## 已探索并实证的方案

### 1. rcgen 从 frp-core 移出(实施后回滚)—— 零收益

背景:rcgen(证书生成)挂在 frp-core 的 `tls` feature 下,而运行时只有 frps 自动生成证书、以及 frp-core `xtcp_p2p_connect_quic`(QUIC XTCP P2P provider,Go frp `protocol=quic` 兼容)会生成自签名证书。理论收益:frpc-tiny(有 tls 无 quic)不再编译 rcgen 链。

实测(同 worktree、同缓存、stash 对照):
- **HEAD 的 frpc-tiny 里 rcgen 机器码本来就不存在**——LTO fat 全程序优化把无调用者的 rcgen 链完全 GC 掉,移动依赖零节省。
- 改动后 frpc-tiny 反而 +48 KB、frps-tiny +32 KB(frp_core .text +6.5 KB):删除函数改变了 LTO 内联决策,布局抖动反噬。
- frpc 默认档的 rcgen **不能移走**(QUIC XTCP provider 是生产路径);frps 移走也无收益(仍编译)。

结论:**依赖移动/删除前,先用 cargo bloat --crates 确认目标代码是否有真实调用者**(有调用者的才会产生机器码)。已回滚,无代码残留。

### 2. h2 门控到 http-proxy —— 语义不成立

`http-proxy` feature 只门控 `frp-server/src/plugin/`(server plugin);vhost(HTTP/HTTPS vhost listener,含 h2c)是**无条件编译的核心功能**,由 `vhost_http_port` 配置驱动。把 h2 门控到 http-proxy 会让 micro 档失去 vhost HTTP/2 能力(行为回归)。放弃。

### 3. env-filter 日志过滤(regex 196 KB)—— 用户决策保留

tracing-subscriber 的 `env-filter` feature 经 `matchers` 引入 regex(regex_syntax 115 KB + regex_automata 81 KB ≈ 196 KB,frps/frpc 各一份)。换成静态 `LevelFilter` 可省,但失去 `RUST_LOG` 复杂表达式(运维灵活性)。**用户明确决定保留 env-filter**。

## 未来可选方向(未实施)

| 方向 | 收益估计 | 代价/风险 |
|---|---|---|
| 默认 feature 调整(SSH ~850 KB、QUIC ~450 KB 改 opt-in) | frps 最多 -1.3 MB | 产品决策,用户已明确不动默认矩阵 |
| 手写 CLI 替换 bpaf | frpc ~100 KB | 需保持全部 flag 兼容,改动面大 |
| UPX 压缩 | 文件 60-70% | 仅 Linux ELF;macOS arm64 的 Mach-O 不支持;运行期解压 + AV 误报风险 |
| `-Zbuild-std` + `panic_immediate_abort` | std 1.3 MiB 的显著部分 | 需 nightly toolchain,CI 改造,工程成本高 |
| 检查 CI 构建增量(如上文的 17 KB 级 LTO 抖动) | 忽略 | 非可控 |

## 方法论备忘

- LTO fat 下"编译了但没有调用者"的代码不占体积;cargo bloat --crates 是评估依赖贡献的唯一可靠手段。
- 同一代码重复构建存在 ~17 KB(0.2%)级布局抖动;方案验证须用**同环境 stash 对照**(同一 worktree、同一 target 缓存,只差代码)。
- 体积对比基线必须在同一代码状态重建(main 分支上的陈旧二进制不可作基线)。
