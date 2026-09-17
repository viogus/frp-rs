# Go frp ↔ Rust frp-rs Cross-Compatibility Test Suite

Design for automated CI-based compatibility testing between Go frp (v0.69.1, configurable) and Rust frp-rs.

## Goal

Catch Go↔Rust protocol regressions on every PR. All tests must pass green — no `allow_failure` exceptions.

## Architecture

```
PR / push to main
  └─> ubuntu-latest runner
        ├─ Build frps + frpc (release, from source)
        ├─ Download Go frp binary (version from GO_FRP_VERSION env, default 0.69.1)
        ├─ Run compat-test.sh --ci
        └─ Pass/Fail gates PR
```

No Docker. No external services. Script handles port allocation, echo servers, cleanup.

## Files

| File | Purpose |
|------|---------|
| `.github/workflows/compat.yml` | CI workflow (new) |
| `scripts/download-go-frp.sh` | Download Go frp linux_amd64 release (new) |
| `scripts/compat-test.sh` | Existing test script, enhanced with `--ci` + `--go-version` |

## Test Matrix

### Existing (18 tests, already passing)

| # | Direction | Proxy | Transport variants |
|---|-----------|-------|--------------------|
| 1-4 | Go→Rust | TCP | plain, encrypted, TLS, TLS+encrypt |
| 5-8 | Rust→Go | TCP | plain, encrypted, TLS, TLS+encrypt |
| 9-10 | Both | UDP | plain |
| 11-12 | Both | HTTP (VHost) | plain |
| 13-14 | Both | STCP | plain |
| 15-16 | Both | Multi-proxy (2×TCP) | plain |
| 17-18 | Both | Compression (Snappy) | plain |

### To add (P0: block CI)

| # | Direction | Proxy | Transport |
|---|-----------|-------|-----------|
| 19-22 | Go→Rust | TCP+mux | plain, encrypted, TLS, TLS+encrypt |
| 23-26 | Rust→Go | TCP+mux | plain, encrypted, TLS, TLS+encrypt |
| 27-28 | Both | WebSocket | plain |

### To add (P1: add after CI green)

| # | Direction | Proxy | Transport |
|---|-----------|-------|-----------|
| 29 | Rust→Go | SOCKS5 plugin | TCP plain |

### Deferred (P2: follow-up)

| # | Direction | Proxy | Transport |
|---|-----------|-------|-----------|
| — | Both | WebSocket | encrypted, WSS |
| — | Both | KCP | plain |
| — | Both | QUIC | plain |

## CI Workflow (`compat.yml`)

```yaml
name: Cross-Compat
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  workflow_dispatch:
    inputs:
      go_frp_version:
        description: 'Go frp version (e.g. 0.69.1)'
        default: '0.69.1'

jobs:
  compat:
    runs-on: ubuntu-latest
    timeout-minutes: 15
    env:
      GO_FRP_VERSION: ${{ inputs.go_frp_version || '0.69.1' }}
    steps:
      - uses: actions/checkout@v4
      - uses: actions-rust-lang/setup-rust-toolchain@v1
      - name: Build frp-rs
        run: cargo build --release --bin frps --bin frpc
      - name: Download Go frp
        run: scripts/download-go-frp.sh "$GO_FRP_VERSION"
      - name: Run compat tests
        run: scripts/compat-test.sh --ci --go-version "$GO_FRP_VERSION"
```

## `download-go-frp.sh`

```bash
#!/usr/bin/env bash
# Downloads Go frp linux_amd64 release binary.
# Usage: download-go-frp.sh [version] [arch] [dest]
set -euo pipefail
VERSION="${1:-0.69.1}"
ARCH="${2:-linux_amd64}"
DEST="${3:-/tmp/frp_${VERSION}_linux_amd64}"
URL="https://github.com/fatedier/frp/releases/download/v${VERSION}/frp_${VERSION}_${ARCH}.tar.gz"

mkdir -p "$DEST"
# 3-retry download
for i in 1 2 3; do
  curl -fsSL --connect-timeout 10 --max-time 120 -o /tmp/frp.tar.gz "$URL" && break
  echo "attempt $i failed, retrying..." >&2
  sleep 5
done
[ -f /tmp/frp.tar.gz ] || { echo "download failed" >&2; exit 1; }

tar xzf /tmp/frp.tar.gz -C "$DEST" --strip-components=1
chmod +x "$DEST/frps" "$DEST/frpc"
rm /tmp/frp.tar.gz
echo "Go frp $VERSION installed to $DEST"
```

## `compat-test.sh` Changes

1. **`--ci` flag**: no ANSI colors, uses `::error file=scripts/compat-test.sh::<msg>` GitHub annotations on failure, exits non-zero on any failure
2. **`--go-version X.Y.Z`**: overrides `GO_FRP_VERSION` env var, defaults Go binary path to `/tmp/frp_X.Y.Z_linux_amd64`
3. **`GO_FRP_DIR` env var**: fallback for custom Go binary location (existing mac default: `/tmp/frp_0.69.1_darwin_arm64`)
4. **Auto-detect OS**: on linux → `linux_amd64` path, on darwin → `darwin_arm64` path
5. **Config helpers for mux**: `write_rust_frps_config_mux()`, `write_go_frps_config_mux()` — same as existing but `tcp_mux = true`
6. **Config helpers for WebSocket**: `write_rust_frps_config_ws()`, `write_go_frpc_config_ws()` — `transport.protocol = "websocket"`

## Transport Status (verified against code on 2026-06-26)

| Transport | Status | IoStream variant |
|-----------|--------|------------------|
| TCP | ✅ | `IoStream::Tcp` |
| TCP+TLS (rustls) | ✅ | `IoStream::Tls` |
| WebSocket | ✅ | `IoStream::WebSocket(WsByteStream)` |
| WSS (WebSocket+TLS) | ✅ | `IoStream::WebSocket` (via wss://) |
| KCP | ✅ | `IoStream::Kcp(KcpStream)` |
| QUIC | ✅ | `IoStream::Quic(QuicStream)` |
| Yamux (tcp_mux) | ✅ | `IoStream::Yamux(YamuxStream)` |
| AES-128-CFB encryption | ✅ | `IoStream::Cipher(CipherStream)` |
| Snappy compression | ✅ | implemented in `encryption.rs` |

## Risks

- **yamux compat**: Go uses `fatedier/yamux` fork of `hashicorp/yamux`. Rust uses `yamux-rs`. Protocol SHOULD match but unverified under load/edge cases.
- **Go binary download**: `github.com/fatedier/frp` releases — if GitHub is slow/blocked, CI fails. Mitigation: 3-retry loop, 120s timeout.
- **Port conflicts**: script uses `random_port()` (17000-27000). Unlikely on fresh CI runner but possible. Already has lsof check.
- **Race flakiness**: proxy startup uses `wait_for_port_safe()` (15s timeout). May need tuning for CI (slower VMs).

## What's NOT in scope

- Docker-based testing (chose hybrid approach)
- Go version matrix beyond configurable single version
- Performance/throughput testing
- Long-running stability tests
- KCP/QUIC compat tests (deferred P2)
