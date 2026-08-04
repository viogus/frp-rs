# frp-rs Docker

多架构 Docker 镜像，内置 C 入口点支持环境变量生成 TOML 配置。

## 镜像

| 镜像 | 平台 |
|------|------|
| `ghcr.io/viogus/frps-rs:latest` | linux/amd64, linux/arm64, linux/arm/v7 |
| `ghcr.io/viogus/frpc-rs:latest` | linux/amd64, linux/arm64, linux/arm/v7 |
| `ghcr.io/viogus/frps-tiny-rs:latest` | linux/amd64, linux/arm64, linux/arm/v7 |
| `ghcr.io/viogus/frpc-tiny-rs:latest` | linux/amd64, linux/arm64, linux/arm/v7 |
| `ghcr.io/viogus/frps-micro-rs:latest` | linux/amd64, linux/arm64, linux/arm/v7 |
| `ghcr.io/viogus/frpc-micro-rs:latest` | linux/amd64, linux/arm64, linux/arm/v7 |

`:test` 标签 (源码构建) 和 `:vX.Y.Z` 版本标签同样覆盖 6 个变体；tiny/micro
变体使用带后缀的标签（`:testtiny`/`:testmicro`、`:vX.Y.Ztiny`/`:vX.Y.Zmicro`）。
`:latest` 只推送到 2 个主镜像（frps-rs、frpc-rs）。

## 构建方式

| Dockerfile | 用途 |
|------------|------|
| `Dockerfile.source` | 从源码编译（交叉编译），arm64 使用 `aarch64-unknown-linux-musl` |
| `build.sh` | 下载 GitHub release 二进制构建镜像（非源码编译的构建路径） |

## 用法

### 环境变量（无需配置文件）

**frps-rs：**

```yaml
services:
  frps-rs:
    image: ghcr.io/viogus/frps-rs:latest
    restart: unless-stopped
    network_mode: host
    environment:
      - FRP_BIND_PORT=7000
      - FRP_AUTH_TOKEN=your_token
```

**frpc-rs：**

```yaml
services:
  frpc-rs:
    image: ghcr.io/viogus/frpc-rs:latest
    restart: unless-stopped
    network_mode: host
    environment:
      - FRP_SERVER_ADDR=1.2.3.4
      - FRP_SERVER_PORT=7000
      - FRP_AUTH_TOKEN=your_token
      - FRP_TUNNEL_NAME=ssh
      - FRP_TUNNEL_LOCAL_PORT=22
      - FRP_TUNNEL_REMOTE_PORT=6022
```

### 挂载配置文件

```yaml
services:
  frps-rs:
    image: ghcr.io/viogus/frps-rs:latest
    restart: unless-stopped
    network_mode: host
    volumes:
      - ./frps.toml:/app/frp.toml
```

检测到已挂载非空配置文件时，跳过 env 生成。

## 环境变量

### frps-rs

| 变量 | 默认 | 说明 |
|------|------|------|
| `FRP_BIND_ADDR` | `0.0.0.0` | 监听地址 |
| `FRP_BIND_PORT` | `7000` | 监听端口 |
| `FRP_AUTH_TOKEN` | — | 认证 token |
| `FRP_SUBDOMAIN_HOST` | — | 子域名后缀 |
| `FRP_TLS_CERT_FILE` | — | TLS 证书文件 |
| `FRP_TLS_KEY_FILE` | — | TLS 私钥文件 |
| `FRP_DASHBOARD_PORT` | `0` | Dashboard 端口 (0 = 禁用) |
| `FRP_DASHBOARD_ADDR` | `0.0.0.0` | Dashboard 绑定地址 |
| `FRP_DASHBOARD_USER` | `""` | Dashboard 用户名 |
| `FRP_DASHBOARD_PWD` | `""` | Dashboard 密码 |

### frpc-rs

| 变量 | 默认 | 说明 |
|------|------|------|
| `FRP_SERVER_ADDR` | `127.0.0.1` | 服务器地址 |
| `FRP_SERVER_PORT` | `7000` | 服务器端口 |
| `FRP_AUTH_TOKEN` | — | 认证 token |
| `FRP_TUNNEL_NAME` | — | 隧道名称 |
| `FRP_TUNNEL_TYPE` | `tcp` | 隧道类型 |
| `FRP_TUNNEL_LOCAL_IP` | `127.0.0.1` | 本地 IP |
| `FRP_TUNNEL_LOCAL_PORT` | — | 本地端口 |
| `FRP_TUNNEL_REMOTE_PORT` | — | 远程端口 |

## 自动更新

Release 标签（`v*`）推送时自动构建 `latest` + 版本标签镜像。
Push 到 `main` 时自动构建 `test` 标签镜像（触发器为 `branches: [main]` +
`tags: v*`，无 `docker/**` 路径过滤）。
Pull Request 也会构建 `:pr-N` 标签镜像。
