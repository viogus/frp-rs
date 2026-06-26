# Go↔Rust Cross-Compatibility CI Test Suite — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add CI-based Go↔Rust compatibility testing that gates PRs — 29 tests, all must pass.

**Architecture:** GitHub Actions workflow on ubuntu-latest. Builds frp-rs from source, downloads Go frp binary, runs compat-test.sh with `--ci` flag. Script already has OS auto-detect and 18 existing tests.

**Tech Stack:** Bash, GitHub Actions, Go frp v0.69.1 (configurable), cargo release build

**Spec:** `docs/superpowers/specs/2026-06-26-go-rust-compat-test-design.md`

---

### File Map

| File | Action | Purpose |
|------|--------|---------|
| `scripts/download-go-frp.sh` | Create | Download Go frp linux_amd64 binary |
| `.github/workflows/compat.yml` | Create | CI workflow |
| `scripts/compat-test.sh` | Modify | `--ci` flag, `--go-version`, 11 new tests |

---

### Task 1: Create download-go-frp.sh

**Files:**
- Create: `scripts/download-go-frp.sh`

- [ ] **Step 1: Write the script**

```bash
#!/usr/bin/env bash
# =============================================================================
# Download Go frp release binaries for compatibility testing.
# Usage: download-go-frp.sh [version] [arch] [dest]
# =============================================================================
set -euo pipefail

VERSION="${1:-0.69.1}"
ARCH="${2:-linux_amd64}"
DEST="${3:-/tmp/frp_${VERSION}_linux_${ARCH}}"

URL="https://github.com/fatedier/frp/releases/download/v${VERSION}/frp_${VERSION}_${ARCH}.tar.gz"

echo "Downloading Go frp v${VERSION} (${ARCH})..."
echo "  URL: ${URL}"
echo "  Dest: ${DEST}"

mkdir -p "$DEST"

# 3-retry download with backoff
TARBALL="/tmp/frp_${VERSION}_${ARCH}.tar.gz"
for i in 1 2 3; do
    if curl -fsSL --connect-timeout 10 --max-time 120 -o "$TARBALL" "$URL"; then
        break
    fi
    echo "attempt $i failed, retrying in 5s..." >&2
    sleep 5
done

if [[ ! -f "$TARBALL" ]]; then
    echo "ERROR: failed to download Go frp after 3 attempts" >&2
    exit 1
fi

tar xzf "$TARBALL" -C "$DEST" --strip-components=1
rm "$TARBALL"
chmod +x "$DEST/frps" "$DEST/frpc"

echo "Go frp v${VERSION} installed:"
echo "  frps: $DEST/frps"
echo "  frpc: $DEST/frpc"
"$DEST/frps" --version 2>&1 || true
```

- [ ] **Step 2: Make executable and test locally**

```bash
chmod +x scripts/download-go-frp.sh
bash scripts/download-go-frp.sh
```

Expected: downloads Go frp v0.69.1 to `/tmp/frp_0.69.1_linux_amd64/`, prints version.

- [ ] **Step 3: Test with explicit version**

```bash
bash scripts/download-go-frp.sh 0.69.1 linux_amd64 /tmp/test-go-frp
/tmp/test-go-frp/frps --version
```

Expected: `frps --version` prints Go frp version info.

- [ ] **Step 4: Commit**

```bash
git add scripts/download-go-frp.sh
git commit -m "feat: add download-go-frp.sh for CI compat testing"
```

---

### Task 2: Create CI workflow

**Files:**
- Create: `.github/workflows/compat.yml`

- [ ] **Step 1: Write CI workflow**

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
        required: false
        default: '0.69.1'

permissions:
  contents: read

env:
  CARGO_TERM_COLOR: always

jobs:
  compat:
    runs-on: ubuntu-latest
    timeout-minutes: 15
    strategy:
      fail-fast: false

    env:
      GO_FRP_VERSION: ${{ github.event.inputs.go_frp_version || '0.69.1' }}

    steps:
      - uses: actions/checkout@v4

      - uses: actions-rust-lang/setup-rust-toolchain@v1

      - name: Cache cargo build
        uses: actions/cache@v4
        with:
          path: |
            ~/.cargo/registry/cache/
            ~/.cargo/git/db/
            target/release/
          key: ${{ runner.os }}-cargo-compat-${{ hashFiles('Cargo.lock') }}
          restore-keys: ${{ runner.os }}-cargo-compat-

      - name: Build frp-rs (release)
        run: cargo build --release --bin frps --bin frpc

      - name: Download Go frp
        run: bash scripts/download-go-frp.sh "$GO_FRP_VERSION"

      - name: Run compat tests
        run: bash scripts/compat-test.sh --ci --go-version "$GO_FRP_VERSION"
```

- [ ] **Step 2: Commit**

```bash
git add .github/workflows/compat.yml
git commit -m "ci: add Go↔Rust cross-compat test workflow"
```

---

### Task 3: Add --ci and --go-version flags to compat-test.sh

**Files:**
- Modify: `scripts/compat-test.sh:1-60`

- [ ] **Step 1: Add --ci flag (GitHub annotations, no color)**

Add `CI=false` to state section (line ~38). Change arg parsing to handle `--ci`:

```bash
# --- State ---
PASS=0
FAIL=0
FAILURES=()
VERBOSE=false
SELECTED_TEST=""
KEEP_TMP=false
CI=false
PIDS=""

# --- Colors ---
if $CI; then
    RED='' GREEN='' YELLOW='' NC=''
else
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    NC='\033[0m'
fi

# --- Parse args ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        --test) SELECTED_TEST="$2"; shift 2 ;;
        --verbose|-v) VERBOSE=true; shift ;;
        --keep-tmp) KEEP_TMP=true; shift ;;
        --ci) CI=true; shift ;;
        --go-version) GO_FRP_VERSION="$2"; shift 2 ;;
        --help|-h)
            echo "Usage: $0 [options]"
            echo "  --test <name>     Run only the named test"
            echo "  --verbose         Show full logs on failure"
            echo "  --keep-tmp        Don't clean up test directory"
            echo "  --ci              CI mode: no color, GitHub annotations"
            echo "  --go-version VER  Go frp version (default: 0.69.1)"
            exit 0
            ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
done
```

- [ ] **Step 2: Wire GO_FRP_VERSION into Go binary path**

After arg parsing, before binary paths section, recalculate GO_FRP_DIR if `--go-version` given:

```bash
# --- Go version override ---
GO_FRP_VERSION="${GO_FRP_VERSION:-0.69.1}"
if [[ -n "${GO_FRP_DIR:-}" ]]; then
    GO_FRP_DIR="$GO_FRP_DIR"  # explicit override takes precedence
else
    _os=$(uname -s | tr '[:upper:]' '[:lower:]')
    _arch=$(uname -m)
    case "$_arch" in
        x86_64)  _arch="amd64" ;;
        aarch64|arm64) _arch="arm64" ;;
    esac
    GO_FRP_DIR="/tmp/frp_${GO_FRP_VERSION}_${_os}_${_arch}"
fi
```

- [ ] **Step 3: Change fail_test to emit GitHub annotations when --ci**

```bash
fail_test() {
    local name="$1" reason="$2"
    if $CI; then
        echo "::error file=scripts/compat-test.sh,title=$name::$reason"
    fi
    echo -e "${RED}[FAIL]${NC} $name: $reason"
    FAIL=$((FAIL + 1))
    FAILURES+=("$name: $reason")
    if $VERBOSE; then
        echo "--- logs for $name ---"
        for f in "$TEST_DIR"/*.log; do
            if [[ -f "$f" ]]; then
                echo "=== $(basename "$f") ==="
                tail -30 "$f"
            fi
        done
        echo "--- end logs ---"
    fi
}
```

- [ ] **Step 4: Change pass_test for CI-appropriate output**

```bash
pass_test() {
    local name="$1"
    if $CI; then
        echo "[PASS] $name"
    else
        echo -e "${GREEN}[PASS]${NC} $name"
    fi
    PASS=$((PASS + 1))
}
```

- [ ] **Step 5: Verify no ANSI color leaks in log function when --ci**

`log()` already uses `>&2` — change to respect CI:

```bash
log() {
    echo -e "${YELLOW}[LOG]${NC} $*" >&2
}
```

No change needed — `$YELLOW`/`$NC` are empty when `CI=true`.

- [ ] **Step 6: Commit**

```bash
git add scripts/compat-test.sh
git commit -m "feat: add --ci and --go-version flags to compat-test.sh"
```

---

### Task 4: Add tcp_mux config helpers and tests

**Files:**
- Modify: `scripts/compat-test.sh` (after existing config helpers, before main)

- [ ] **Step 1: Add tcp_mux config helper functions**

Insert after `write_rust_frpc_config_tls()` (~line 356):

```bash
# ── tcp_mux config helpers ──────────────────────────────

write_rust_frps_config_mux() {
    local port="$1" token="$2" out="$3"
    local extra="${4:-}"
    cat > "$out" <<TOML
bind_addr = "127.0.0.1"
bind_port = $port

[auth]
method = "token"
token = "$token"

[transport]
tcp_mux = true

$extra
TOML
}

write_rust_frps_config_mux_tls() {
    local port="$1" token="$2" out="$3"
    local extra="${4:-}"
    cat > "$out" <<TOML
bind_addr = "127.0.0.1"
bind_port = $port
tls_enable = true
tls_cert_file = "$CERT_DIR/server.crt"
tls_key_file = "$CERT_DIR/server.key"

[auth]
method = "token"
token = "$token"

[transport]
tcp_mux = true

$extra
TOML
}

write_go_frps_config_mux() {
    local port="$1" token="$2" out="$3"
    cat > "$out" <<TOML
bindAddr = "127.0.0.1"
bindPort = $port

auth.method = "token"
auth.token = "$token"

transport.tcpMux = true

log.to = "$TEST_DIR/go-frps.log"
log.level = "debug"
TOML
}

write_go_frps_config_mux_tls() {
    local port="$1" token="$2" out="$3"
    cat > "$out" <<TOML
bindAddr = "127.0.0.1"
bindPort = $port

auth.method = "token"
auth.token = "$token"

transport.tls.force = true
transport.tls.certFile = "$CERT_DIR/server.crt"
transport.tls.keyFile = "$CERT_DIR/server.key"
transport.tcpMux = true

log.to = "$TEST_DIR/go-frps.log"
log.level = "debug"
TOML
}

write_go_frpc_config_mux() {
    local server_port="$1" token="$2" echo_port="$3" proxy_port="$4" name="$5" out="$6"
    local extra="${7:-}"
    cat > "$out" <<TOML
serverAddr = "127.0.0.1"
serverPort = $server_port

auth.token = "$token"

transport.tls.enable = false
transport.tcpMux = true

log.to = "$TEST_DIR/go-frpc-$name.log"
log.level = "debug"

[[proxies]]
name = "$name"
type = "tcp"
localIP = "127.0.0.1"
localPort = $echo_port
remotePort = $proxy_port

$extra
TOML
}

write_go_frpc_config_mux_tls() {
    local server_port="$1" token="$2" echo_port="$3" proxy_port="$4" name="$5" out="$6"
    local extra="${7:-}"
    cat > "$out" <<TOML
serverAddr = "127.0.0.1"
serverPort = $server_port

auth.token = "$token"

transport.tls.enable = true
transport.tls.disableCustomTLSFirstByte = true
transport.tls.trustedCaFile = "$CERT_DIR/ca.crt"
transport.tls.serverName = "localhost"
transport.tcpMux = true

log.to = "$TEST_DIR/go-frpc-$name.log"
log.level = "debug"

[[proxies]]
name = "$name"
type = "tcp"
localIP = "127.0.0.1"
localPort = $echo_port
remotePort = $proxy_port

$extra
TOML
}

write_rust_frpc_config_mux() {
    local server_port="$1" token="$2" echo_port="$3" proxy_port="$4" name="$5" out="$6"
    local extra="${7:-}"
    cat > "$out" <<TOML
server_addr = "127.0.0.1"
server_port = $server_port
token = "$token"
tcp_mux = true
login_fail_exit = true
pool_count = 1

[[proxies]]
name = "$name"
type = "tcp"
local_ip = "127.0.0.1"
local_port = $echo_port
remote_port = $proxy_port

$extra
TOML
}

write_rust_frpc_config_mux_tls() {
    local server_port="$1" token="$2" echo_port="$3" proxy_port="$4" name="$5" out="$6"
    local extra="${7:-}"
    cat > "$out" <<TOML
server_addr = "127.0.0.1"
server_port = $server_port
token = "$token"
tcp_mux = true
login_fail_exit = true
pool_count = 1
tls_enable = true
tls_ca_file = "$CERT_DIR/ca.crt"
tls_server_name = "localhost"

[[proxies]]
name = "$name"
type = "tcp"
local_ip = "127.0.0.1"
local_port = $echo_port
remote_port = $proxy_port

$extra
TOML
}
```

- [ ] **Step 2: Add Go→Rust tcp_mux test functions**

Insert after `test_g2r_tcp_tls_encrypt()` (before line ~598):

```bash
# =============================================================================
# Test: Go frpc -> Rust frps, tcp_mux plain TCP
# =============================================================================
test_g2r_mux_plain() {
    local name="go-to-rust-mux-plain"
    should_run_test "$name" || return 0

    log "=== $name ==="
    local frps_port=$(random_port)
    local proxy_port=$(random_port)
    local echo_port=$(random_port)
    local token="test-token-g2r-mux"

    mkdir -p "$TEST_DIR/$name"

    start_echo_server "$echo_port"
    wait_for_port 127.0.0.1 "$echo_port" 3 || {
        fail_test "$name" "echo server did not start"
        return
    }

    write_rust_frps_config_mux "$frps_port" "$token" "$TEST_DIR/$name/frps.toml"
    RUST_LOG=info "$RUST_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Rust frps did not start"
        return
    }

    write_go_frpc_config_mux "$frps_port" "$token" "$echo_port" "$proxy_port" \
        "mux-plain" "$TEST_DIR/$name/frpc.toml"
    run_go "$GO_FRPC" -c "$TEST_DIR/$name/frpc.toml" \
        > "$TEST_DIR/$name/frpc.log" 2>&1 &
    track_pid $!

    if ! wait_for_port_safe 127.0.0.1 "$proxy_port" 15; then
        fail_test "$name" "proxy port $proxy_port not reachable"
        return
    fi

    local result
    result=$(send_and_expect "$proxy_port" "mux-plain-data" "mux-plain-data" 5)
    if [[ "$result" == OK:* ]]; then
        pass_test "$name"
    else
        fail_test "$name" "$result"
    fi
}

# =============================================================================
# Test: Go frpc -> Rust frps, tcp_mux encrypted TCP
# =============================================================================
test_g2r_mux_encrypted() {
    local name="go-to-rust-mux-encrypted"
    should_run_test "$name" || return 0

    log "=== $name ==="
    local frps_port=$(random_port)
    local proxy_port=$(random_port)
    local echo_port=$(random_port)
    local token="test-token-g2r-mux-enc"

    mkdir -p "$TEST_DIR/$name"

    start_echo_server "$echo_port"
    wait_for_port 127.0.0.1 "$echo_port" 3 || {
        fail_test "$name" "echo server did not start"
        return
    }

    write_rust_frps_config_mux "$frps_port" "$token" "$TEST_DIR/$name/frps.toml"
    RUST_LOG=info "$RUST_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Rust frps did not start"
        return
    }

    write_go_frpc_config_mux "$frps_port" "$token" "$echo_port" "$proxy_port" \
        "mux-enc" "$TEST_DIR/$name/frpc.toml" \
        "transport.useEncryption = true"
    run_go "$GO_FRPC" -c "$TEST_DIR/$name/frpc.toml" \
        > "$TEST_DIR/$name/frpc.log" 2>&1 &
    track_pid $!

    if ! wait_for_port_safe 127.0.0.1 "$proxy_port" 15; then
        fail_test "$name" "proxy port $proxy_port not reachable"
        return
    fi

    local result
    result=$(send_and_expect "$proxy_port" "mux-enc-data" "mux-enc-data" 5)
    if [[ "$result" == OK:* ]]; then
        pass_test "$name"
    else
        fail_test "$name" "$result"
    fi
}

# =============================================================================
# Test: Go frpc -> Rust frps, tcp_mux TLS
# =============================================================================
test_g2r_mux_tls() {
    local name="go-to-rust-mux-tls"
    should_run_test "$name" || return 0

    log "=== $name ==="
    local frps_port=$(random_port)
    local proxy_port=$(random_port)
    local echo_port=$(random_port)
    local token="test-token-g2r-mux-tls"

    mkdir -p "$TEST_DIR/$name"

    start_echo_server "$echo_port"
    wait_for_port 127.0.0.1 "$echo_port" 3 || {
        fail_test "$name" "echo server did not start"
        return
    }

    write_rust_frps_config_mux_tls "$frps_port" "$token" "$TEST_DIR/$name/frps.toml"
    RUST_LOG=info "$RUST_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Rust frps did not start"
        return
    }

    write_go_frpc_config_mux_tls "$frps_port" "$token" "$echo_port" "$proxy_port" \
        "mux-tls" "$TEST_DIR/$name/frpc.toml"
    run_go "$GO_FRPC" -c "$TEST_DIR/$name/frpc.toml" \
        > "$TEST_DIR/$name/frpc.log" 2>&1 &
    track_pid $!

    if ! wait_for_port_safe 127.0.0.1 "$proxy_port" 15; then
        fail_test "$name" "proxy port $proxy_port not reachable"
        return
    fi

    local result
    result=$(send_and_expect "$proxy_port" "mux-tls-data" "mux-tls-data" 5)
    if [[ "$result" == OK:* ]]; then
        pass_test "$name"
    else
        fail_test "$name" "$result"
    fi
}

# =============================================================================
# Test: Go frpc -> Rust frps, tcp_mux TLS + encryption
# =============================================================================
test_g2r_mux_tls_encrypt() {
    local name="go-to-rust-mux-tls-encrypt"
    should_run_test "$name" || return 0

    log "=== $name ==="
    local frps_port=$(random_port)
    local proxy_port=$(random_port)
    local echo_port=$(random_port)
    local token="test-token-g2r-mux-tls-enc"

    mkdir -p "$TEST_DIR/$name"

    start_echo_server "$echo_port"
    wait_for_port 127.0.0.1 "$echo_port" 3 || {
        fail_test "$name" "echo server did not start"
        return
    }

    write_rust_frps_config_mux_tls "$frps_port" "$token" "$TEST_DIR/$name/frps.toml"
    RUST_LOG=info "$RUST_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Rust frps did not start"
        return
    }

    write_go_frpc_config_mux_tls "$frps_port" "$token" "$echo_port" "$proxy_port" \
        "mux-tls-enc" "$TEST_DIR/$name/frpc.toml" \
        "transport.useEncryption = true"
    run_go "$GO_FRPC" -c "$TEST_DIR/$name/frpc.toml" \
        > "$TEST_DIR/$name/frpc.log" 2>&1 &
    track_pid $!

    if ! wait_for_port_safe 127.0.0.1 "$proxy_port" 15; then
        fail_test "$name" "proxy port $proxy_port not reachable"
        return
    fi

    local result
    result=$(send_and_expect "$proxy_port" "mux-tls-enc-data" "mux-tls-enc-data" 5)
    if [[ "$result" == OK:* ]]; then
        pass_test "$name"
    else
        fail_test "$name" "$result"
    fi
}
```

- [ ] **Step 3: Add Rust→Go tcp_mux test functions**

Insert after Step 2, same pattern reversed (Rust frpc → Go frps). Same 4 variants: plain, encrypted, TLS, TLS+encrypt. Each uses `write_go_frps_config_mux`/`write_go_frps_config_mux_tls` + `write_rust_frpc_config_mux`/`write_rust_frpc_config_mux_tls`.

```bash
# =============================================================================
# Test: Rust frpc -> Go frps, tcp_mux plain TCP
# =============================================================================
test_r2g_mux_plain() {
    local name="rust-to-go-mux-plain"
    should_run_test "$name" || return 0

    log "=== $name ==="
    local frps_port=$(random_port)
    local proxy_port=$(random_port)
    local echo_port=$(random_port)
    local token="test-token-r2g-mux"

    mkdir -p "$TEST_DIR/$name"

    start_echo_server "$echo_port"
    wait_for_port 127.0.0.1 "$echo_port" 3 || {
        fail_test "$name" "echo server did not start"
        return
    }

    write_go_frps_config_mux "$frps_port" "$token" "$TEST_DIR/$name/frps.toml"
    run_go "$GO_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Go frps did not start"
        return
    }

    write_rust_frpc_config_mux "$frps_port" "$token" "$echo_port" "$proxy_port" \
        "mux-plain" "$TEST_DIR/$name/frpc.toml"
    RUST_LOG=info "$RUST_FRPC" -c "$TEST_DIR/$name/frpc.toml" \
        > "$TEST_DIR/$name/frpc.log" 2>&1 &
    track_pid $!

    if ! wait_for_port_safe 127.0.0.1 "$proxy_port" 15; then
        fail_test "$name" "proxy port $proxy_port not reachable"
        return
    fi

    local result
    result=$(send_and_expect "$proxy_port" "r2g-mux-plain-data" "r2g-mux-plain-data" 5)
    if [[ "$result" == OK:* ]]; then
        pass_test "$name"
    else
        fail_test "$name" "$result"
    fi
}

# =============================================================================
# Test: Rust frpc -> Go frps, tcp_mux encrypted TCP
# =============================================================================
test_r2g_mux_encrypted() {
    local name="rust-to-go-mux-encrypted"
    should_run_test "$name" || return 0

    log "=== $name ==="
    local frps_port=$(random_port)
    local proxy_port=$(random_port)
    local echo_port=$(random_port)
    local token="test-token-r2g-mux-enc"

    mkdir -p "$TEST_DIR/$name"

    start_echo_server "$echo_port"
    wait_for_port 127.0.0.1 "$echo_port" 3 || {
        fail_test "$name" "echo server did not start"
        return
    }

    write_go_frps_config_mux "$frps_port" "$token" "$TEST_DIR/$name/frps.toml"
    run_go "$GO_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Go frps did not start"
        return
    }

    write_rust_frpc_config_mux "$frps_port" "$token" "$echo_port" "$proxy_port" \
        "mux-enc" "$TEST_DIR/$name/frpc.toml" \
        "use_encryption = true"
    RUST_LOG=info "$RUST_FRPC" -c "$TEST_DIR/$name/frpc.toml" \
        > "$TEST_DIR/$name/frpc.log" 2>&1 &
    track_pid $!

    if ! wait_for_port_safe 127.0.0.1 "$proxy_port" 15; then
        fail_test "$name" "proxy port $proxy_port not reachable"
        return
    fi

    local result
    result=$(send_and_expect "$proxy_port" "r2g-mux-enc-data" "r2g-mux-enc-data" 5)
    if [[ "$result" == OK:* ]]; then
        pass_test "$name"
    else
        fail_test "$name" "$result"
    fi
}

# =============================================================================
# Test: Rust frpc -> Go frps, tcp_mux TLS transport
# =============================================================================
test_r2g_mux_tls() {
    local name="rust-to-go-mux-tls"
    should_run_test "$name" || return 0

    log "=== $name ==="
    local frps_port=$(random_port)
    local proxy_port=$(random_port)
    local echo_port=$(random_port)
    local token="test-token-r2g-mux-tls"

    mkdir -p "$TEST_DIR/$name"

    start_echo_server "$echo_port"
    wait_for_port 127.0.0.1 "$echo_port" 3 || {
        fail_test "$name" "echo server did not start"
        return
    }

    write_go_frps_config_mux_tls "$frps_port" "$token" "$TEST_DIR/$name/frps.toml"
    run_go "$GO_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Go frps did not start"
        return
    }

    write_rust_frpc_config_mux_tls "$frps_port" "$token" "$echo_port" "$proxy_port" \
        "mux-tls" "$TEST_DIR/$name/frpc.toml"
    RUST_LOG=info "$RUST_FRPC" -c "$TEST_DIR/$name/frpc.toml" \
        > "$TEST_DIR/$name/frpc.log" 2>&1 &
    track_pid $!

    if ! wait_for_port_safe 127.0.0.1 "$proxy_port" 15; then
        fail_test "$name" "proxy port $proxy_port not reachable"
        return
    fi

    local result
    result=$(send_and_expect "$proxy_port" "r2g-mux-tls-data" "r2g-mux-tls-data" 5)
    if [[ "$result" == OK:* ]]; then
        pass_test "$name"
    else
        fail_test "$name" "$result"
    fi
}

# =============================================================================
# Test: Rust frpc -> Go frps, tcp_mux TLS + encryption
# =============================================================================
test_r2g_mux_tls_encrypt() {
    local name="rust-to-go-mux-tls-encrypt"
    should_run_test "$name" || return 0

    log "=== $name ==="
    local frps_port=$(random_port)
    local proxy_port=$(random_port)
    local echo_port=$(random_port)
    local token="test-token-r2g-mux-tls-enc"

    mkdir -p "$TEST_DIR/$name"

    start_echo_server "$echo_port"
    wait_for_port 127.0.0.1 "$echo_port" 3 || {
        fail_test "$name" "echo server did not start"
        return
    }

    write_go_frps_config_mux_tls "$frps_port" "$token" "$TEST_DIR/$name/frps.toml"
    run_go "$GO_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Go frps did not start"
        return
    }

    write_rust_frpc_config_mux_tls "$frps_port" "$token" "$echo_port" "$proxy_port" \
        "mux-tls-enc" "$TEST_DIR/$name/frpc.toml" \
        "use_encryption = true"
    RUST_LOG=info "$RUST_FRPC" -c "$TEST_DIR/$name/frpc.toml" \
        > "$TEST_DIR/$name/frpc.log" 2>&1 &
    track_pid $!

    if ! wait_for_port_safe 127.0.0.1 "$proxy_port" 15; then
        fail_test "$name" "proxy port $proxy_port not reachable"
        return
    fi

    local result
    result=$(send_and_expect "$proxy_port" "r2g-mux-tls-enc" "r2g-mux-tls-enc" 5)
    if [[ "$result" == OK:* ]]; then
        pass_test "$name"
    else
        fail_test "$name" "$result"
    fi
}
```

- [ ] **Step 4: Add test invocations to main**

Replace the main test invocation section (~lines 1560-1721) to include new tests:

```bash
# --- Run tests ---
# Phase 2: Go frpc -> Rust frps TCP data plane
test_g2r_tcp_plain
test_g2r_tcp_encrypted
test_g2r_tcp_tls
test_g2r_tcp_tls_encrypt

# Phase 2b: Go frpc -> Rust frps, tcp_mux
test_g2r_mux_plain
test_g2r_mux_encrypted
test_g2r_mux_tls
test_g2r_mux_tls_encrypt

# Phase 3: Rust frpc -> Go frps TCP data plane
test_r2g_tcp_plain
test_r2g_tcp_encrypted
test_r2g_tcp_tls
test_r2g_tcp_tls_encrypt

# Phase 3b: Rust frpc -> Go frps, tcp_mux
test_r2g_mux_plain
test_r2g_mux_encrypted
test_r2g_mux_tls
test_r2g_mux_tls_encrypt

# Phase 4: Other proxy types
test_g2r_udp
test_r2g_udp
test_g2r_http
test_r2g_http
test_g2r_stcp
test_r2g_stcp

# Phase 5: Multi-proxy and edge cases
test_multi_proxy
test_g2r_compression
test_r2g_compression
test_r2g_multi_proxy

# Phase 6: WebSocket transport
test_g2r_ws_plain
test_r2g_ws_plain
```

- [ ] **Step 5: Commit**

```bash
git add scripts/compat-test.sh
git commit -m "test: add tcp_mux (yamux) cross-compat tests (8 tests)"
```

---

### Task 5: Add WebSocket transport tests

**Files:**
- Modify: `scripts/compat-test.sh`

- [ ] **Step 1: Add WebSocket config helpers**

Insert config helpers after the tcp_mux config helpers:

```bash
# ── WebSocket transport config helpers ─────────────────────

write_go_frps_config_ws() {
    local port="$1" token="$2" out="$3"
    cat > "$out" <<TOML
bindAddr = "127.0.0.1"
bindPort = $port

auth.method = "token"
auth.token = "$token"

transport.tcpMux = false

log.to = "$TEST_DIR/go-frps.log"
log.level = "debug"
TOML
}

write_rust_frps_config_ws() {
    local port="$1" token="$2" out="$3"
    cat > "$out" <<TOML
bind_addr = "127.0.0.1"
bind_port = $port

[auth]
method = "token"
token = "$token"

[transport]
tcp_mux = false

TOML
}

write_go_frpc_config_ws() {
    local server_port="$1" token="$2" echo_port="$3" proxy_port="$4" name="$5" out="$6"
    local extra="${7:-}"
    cat > "$out" <<TOML
serverAddr = "127.0.0.1"
serverPort = $server_port

auth.token = "$token"

transport.protocol = "websocket"
transport.tls.enable = false
transport.tcpMux = false

log.to = "$TEST_DIR/go-frpc-$name.log"
log.level = "debug"

[[proxies]]
name = "$name"
type = "tcp"
localIP = "127.0.0.1"
localPort = $echo_port
remotePort = $proxy_port

$extra
TOML
}

write_rust_frpc_config_ws() {
    local server_port="$1" token="$2" echo_port="$3" proxy_port="$4" name="$5" out="$6"
    local extra="${7:-}"
    cat > "$out" <<TOML
server_addr = "127.0.0.1"
server_port = $server_port
token = "$token"
tcp_mux = false
login_fail_exit = true
pool_count = 1
transport_protocol = "websocket"

[[proxies]]
name = "$name"
type = "tcp"
local_ip = "127.0.0.1"
local_port = $echo_port
remote_port = $proxy_port

$extra
TOML
}
```

- [ ] **Step 2: Add Go→Rust WebSocket test**

```bash
# =============================================================================
# Test: Go frpc -> Rust frps, WebSocket transport
# =============================================================================
test_g2r_ws_plain() {
    local name="go-to-rust-ws-plain"
    should_run_test "$name" || return 0

    log "=== $name ==="
    local frps_port=$(random_port)
    local proxy_port=$(random_port)
    local echo_port=$(random_port)
    local token="test-token-g2r-ws"

    mkdir -p "$TEST_DIR/$name"

    start_echo_server "$echo_port"
    wait_for_port 127.0.0.1 "$echo_port" 3 || {
        fail_test "$name" "echo server did not start"
        return
    }

    write_rust_frps_config_ws "$frps_port" "$token" "$TEST_DIR/$name/frps.toml"
    RUST_LOG=info "$RUST_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Rust frps did not start"
        return
    }

    write_go_frpc_config_ws "$frps_port" "$token" "$echo_port" "$proxy_port" \
        "ws-plain" "$TEST_DIR/$name/frpc.toml"
    run_go "$GO_FRPC" -c "$TEST_DIR/$name/frpc.toml" \
        > "$TEST_DIR/$name/frpc.log" 2>&1 &
    track_pid $!

    if ! wait_for_port_safe 127.0.0.1 "$proxy_port" 15; then
        fail_test "$name" "proxy port $proxy_port not reachable"
        return
    fi

    local result
    result=$(send_and_expect "$proxy_port" "ws-test-data" "ws-test-data" 5)
    if [[ "$result" == OK:* ]]; then
        pass_test "$name"
    else
        fail_test "$name" "$result"
    fi
}
```

- [ ] **Step 3: Add Rust→Go WebSocket test**

Same pattern reversed:

```bash
# =============================================================================
# Test: Rust frpc -> Go frps, WebSocket transport
# =============================================================================
test_r2g_ws_plain() {
    local name="rust-to-go-ws-plain"
    should_run_test "$name" || return 0

    log "=== $name ==="
    local frps_port=$(random_port)
    local proxy_port=$(random_port)
    local echo_port=$(random_port)
    local token="test-token-r2g-ws"

    mkdir -p "$TEST_DIR/$name"

    start_echo_server "$echo_port"
    wait_for_port 127.0.0.1 "$echo_port" 3 || {
        fail_test "$name" "echo server did not start"
        return
    }

    write_go_frps_config_ws "$frps_port" "$token" "$TEST_DIR/$name/frps.toml"
    run_go "$GO_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Go frps did not start"
        return
    }

    write_rust_frpc_config_ws "$frps_port" "$token" "$echo_port" "$proxy_port" \
        "ws-plain" "$TEST_DIR/$name/frpc.toml"
    RUST_LOG=info "$RUST_FRPC" -c "$TEST_DIR/$name/frpc.toml" \
        > "$TEST_DIR/$name/frpc.log" 2>&1 &
    track_pid $!

    if ! wait_for_port_safe 127.0.0.1 "$proxy_port" 15; then
        fail_test "$name" "proxy port $proxy_port not reachable"
        return
    fi

    local result
    result=$(send_and_expect "$proxy_port" "r2g-ws-data" "r2g-ws-data" 5)
    if [[ "$result" == OK:* ]]; then
        pass_test "$name"
    else
        fail_test "$name" "$result"
    fi
}
```

- [ ] **Step 4: Commit**

```bash
git add scripts/compat-test.sh
git commit -m "test: add WebSocket transport cross-compat tests (2 tests)"
```

---

### Task 6: Add SOCKS5 plugin test (P1)

**Files:**
- Modify: `scripts/compat-test.sh`

- [ ] **Step 1: Add SOCKS5 plugin test (Rust frpc → Go frps)**

Insert before `test_multi_proxy`:

```bash
# =============================================================================
# Test: Rust frpc SOCKS5 plugin -> Go frps
# =============================================================================
test_r2g_socks5() {
    local name="rust-to-go-socks5"
    should_run_test "$name" || return 0

    log "=== $name ==="
    local frps_port=$(random_port)
    local proxy_port=$(random_port)
    local echo_port=$(random_port)
    local socks5_port=$(random_port)
    local token="test-token-r2g-socks5"

    mkdir -p "$TEST_DIR/$name"

    start_echo_server "$echo_port"
    wait_for_port 127.0.0.1 "$echo_port" 3 || {
        fail_test "$name" "echo server did not start"
        return
    }

    write_go_frps_config "$frps_port" "$token" "$TEST_DIR/$name/frps.toml"
    run_go "$GO_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Go frps did not start"
        return
    }

    # Start Rust frpc with SOCKS5 plugin
    cat > "$TEST_DIR/$name/frpc.toml" <<TOML
server_addr = "127.0.0.1"
server_port = $frps_port
token = "$token"
tcp_mux = false
login_fail_exit = true
pool_count = 1

[[proxies]]
name = "socks5-proxy"
type = "tcp"
remote_port = $proxy_port

[proxies.plugin]
type = "socks5"
TOML
    RUST_LOG=info "$RUST_FRPC" -c "$TEST_DIR/$name/frpc.toml" \
        > "$TEST_DIR/$name/frpc.log" 2>&1 &
    track_pid $!

    if ! wait_for_port_safe 127.0.0.1 "$proxy_port" 15; then
        fail_test "$name" "proxy port $proxy_port not reachable"
        return
    fi

    # Test data through SOCKS5 proxy (proxy_port is the SOCKS5 port)
    local result
    result=$(send_and_expect "$proxy_port" "socks5-test-data" "socks5-test-data" 5)
    if [[ "$result" == OK:* ]]; then
        pass_test "$name"
    else
        fail_test "$name" "$result"
    fi
}
```

- [ ] **Step 2: Add invocation to main**

In Phase 5 section, add `test_r2g_socks5`:

```bash
test_r2g_socks5
```

- [ ] **Step 3: Commit**

```bash
git add scripts/compat-test.sh
git commit -m "test: add SOCKS5 plugin cross-compat test"
```

---

### Task 7: Update CLAUDE.md to correct stale transport docs

**Files:**
- Modify: `CLAUDE.md`

- [ ] **Step 1: Update CLAUDE.md sections**

Replace the "Placeholder / Stub Code" section:

Old:
```
### Placeholder / Stub Code

- `TcpMux` (`frp-core/src/mux.rs`): empty struct, commented-out yamux dependency
- `dashboard.rs` and `vhost.rs` mods declared in `frp-server/src/lib.rs` but contain minimal scaffolding
- KCP, QUIC, WebSocket work connections: handled as match arms that log a warning and return
```

New:
```
### Placeholder / Stub Code

- `dashboard.rs` and `vhost.rs` mods declared in `frp-server/src/lib.rs` but contain minimal scaffolding
```

Also add transport status after the "Encryption" section:

```markdown
### Transport Support

All transports fully implemented in `IoStream` (`frp-core/src/transport.rs`):

| Transport | IoStream variant | File |
|-----------|------------------|------|
| TCP | `IoStream::Tcp` | — |
| TCP+TLS (rustls) | `IoStream::Tls` | — |
| WebSocket/WSS | `IoStream::WebSocket(WsByteStream)` | `transport.rs` |
| KCP | `IoStream::Kcp(KcpStream)` | `kcp.rs` |
| QUIC | `IoStream::Quic(QuicStream)` | `quic.rs` |
| Yamux (tcp_mux) | `IoStream::Yamux(YamuxStream)` | `mux.rs` |
| AES-128-CFB | `IoStream::Cipher(CipherStream)` | `cipher_stream.rs` |
```

- [ ] **Step 2: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: correct CLAUDE.md transport status — all transports implemented"
```

---

### Task 8: Final verification — run all tests locally

**Files:** None (verification only)

- [ ] **Step 1: Build frp-rs in release mode**

```bash
cargo build --release --bin frps --bin frpc
```

- [ ] **Step 2: Download Go frp (if not present)**

```bash
bash scripts/download-go-frp.sh
```

- [ ] **Step 3: Run full compat test suite**

```bash
bash scripts/compat-test.sh --verbose
```

Expected: all 29+ tests pass. If any fail, troubleshoot before pushing.

- [ ] **Step 4: Push branch and create PR**

```bash
git push origin <branch-name>
```

Verify CI workflow `Cross-Compat` runs and passes on the PR.

---

## Self-Review

**Spec coverage check:**
- ✅ CI workflow (`compat.yml`) → Task 2
- ✅ Download script (`download-go-frp.sh`) → Task 1
- ✅ `--ci` flag → Task 3
- ✅ `--go-version` flag → Task 3
- ✅ tcp_mux tests (8) → Task 4
- ✅ WebSocket tests (2) → Task 5
- ✅ SOCKS5 test (1) → Task 6
- ✅ CLAUDE.md update → Task 7
- ✅ Final verification → Task 8

**Placeholder scan:** No TBD/TODO/placeholder content. All steps have exact code. ✅

**Type consistency:** Config helper names match between definitions and calls. `write_*_config_mux` family consistent. `GO_FRP_VERSION` used consistently. ✅
