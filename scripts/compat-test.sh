#!/usr/bin/env bash
# =============================================================================
# frp-rs Cross-Compatibility Test Suite
# Tests Go frp v0.70.1 <-> Rust frp-rs interoperability
# =============================================================================
set -euo pipefail

# --- Paths ---
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
# Go version (overridable via env or --go-version flag)
GO_FRP_VERSION="${GO_FRP_VERSION:-0.70.1}"
# Auto-detect Go frp binary path. Override with GO_FRP_DIR env var.
GO_FRP_DIR_USER=""  # track if user provided explicit path
if [[ -n "${GO_FRP_DIR:-}" ]]; then
    GO_FRP_DIR_USER="$GO_FRP_DIR"
else
    _gos=$(uname -s | tr '[:upper:]' '[:lower:]')
    _goa=$(uname -m)
    case "$_goa" in
        x86_64)  _goa="amd64" ;;
        aarch64|arm64) _goa="arm64" ;;
    esac
    GO_FRP_DIR="/tmp/frp_${GO_FRP_VERSION}_${_gos}_${_goa}"
fi
GO_FRPS="$GO_FRP_DIR/frps"
GO_FRPC="$GO_FRP_DIR/frpc"
RUST_FRPS="$PROJECT_DIR/target/release/frps"
RUST_FRPC="$PROJECT_DIR/target/release/frpc"
CERT_DIR="$PROJECT_DIR/frp-core/tests/certs"
TEST_DIR="/tmp/frp-compat-test"

# --- State ---
PASS=0
FAIL=0
FAILURES=()
VERBOSE=false
SELECTED_TEST=""
KEEP_TMP=false
CI=false
DEBUG=false
PIDS=""
XTCP_FRPS_REMOTE=""
XTCP_ONLY=false
XTCP_SHARD=""   # "INDEX/TOTAL" e.g. "1/4"

# --- Colors (empty in CI mode) ---
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
        --debug|-x) DEBUG=true; shift ;;
        --frps-remote) XTCP_FRPS_REMOTE="$2"; shift 2 ;;
        --xtcp-only) XTCP_ONLY=true; shift ;;
        --shard) XTCP_SHARD="$2"; shift 2 ;;
        --list)
            awk '/^[[:space:]]*run_test test_[a-z]/ {print $2}' "$0" | sort
            exit 0
            ;;
        --help|-h)
            echo "Usage: $0 [options]"
            echo "  --test <name>    Run only the named test"
            echo "  --verbose         Show full logs on failure"
            echo "  --keep-tmp        Don't clean up test directory"
            echo "  --ci              CI mode: no color, GitHub annotations"
            echo "  --debug, -x       Enable bash trace (set -x) during test execution"
            echo "  --list            List all test names and exit"
            echo "  --frps-remote HOST  Remote VPS address for XTCP tests"
            echo "  --xtcp-only       Run only XTCP tests (skip all other phases)"
            echo "  --shard INDEX/TOTAL  Shard XTCP tests across N jobs (e.g. 0/4)"
            echo "  --go-version VER  Go frp version (default: 0.70.1)"
            exit 0
            ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
done

# --- Go version (recalculate path if --go-version changed it) ---
if [[ -z "$GO_FRP_DIR_USER" ]]; then
    _gos=$(uname -s | tr '[:upper:]' '[:lower:]')
    _goa=$(uname -m)
    case "$_goa" in
        x86_64)  _goa="amd64" ;;
        aarch64|arm64) _goa="arm64" ;;
    esac
    GO_FRP_DIR="/tmp/frp_${GO_FRP_VERSION}_${_gos}_${_goa}"
    GO_FRPS="$GO_FRP_DIR/frps"
    GO_FRPC="$GO_FRP_DIR/frpc"
fi

# Pass the resolved Go frp version/path to remote-frps.sh for VPS XTCP runs.
export GO_FRP_VERSION
export GO_FRP_DIR

# =============================================================================
# Helpers
# =============================================================================

track_pid() {
    PIDS="$PIDS $1"
}

# Run Go binary with proxy env vars cleared
# Surge/system proxies intercept localhost TCP otherwise.
run_go() {
    env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY \
        -u http_proxy -u https_proxy -u all_proxy \
        "$@"
}

# --- V2 test support ---
# Go frp v0.70.1+ pre-built binaries include V2 protocol support.
# V2 tests use the same pre-built binaries as V1 tests.
GO_FRPS_V2="$GO_FRP_DIR/frps"
GO_FRPC_V2="$GO_FRP_DIR/frpc"

ensure_go_frp_v2() {
    if [[ ! -x "$GO_FRPS_V2" ]] || [[ ! -x "$GO_FRPC_V2" ]]; then
        log "SKIP V2: Go frp pre-built binary not found"
        return 1
    fi
    local ver
    ver=$("$GO_FRPS_V2" --version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1) || true
    if [[ -z "$ver" ]]; then
        log "SKIP V2: cannot determine Go frp version"
        return 1
    fi
    # V2 is included in pre-built binaries since v0.70.1.
    return 0
}

cleanup() {
    for pid in $PIDS; do
        kill "$pid" 2>/dev/null || true
    done
    if ! $KEEP_TMP; then
        rm -rf "$TEST_DIR"
    fi
}

# Kill all tracked PIDs without removing test dir.
# Resets PIDS so subsequent tests start fresh.
cleanup_pids() {
    for pid in $PIDS; do
        kill "$pid" 2>/dev/null || true
    done
    wait 2>/dev/null || true
    PIDS=""
}
trap cleanup EXIT

random_port() {
    # Find an unused port in range (TCP + UDP).
    # Tries lsof first, then ss, then assumes port is free.
    local port check_tcp check_udp
    while true; do
        port=$(( (RANDOM % 10000) + 17000 ))
        check_tcp=false
        check_udp=false
        if command -v lsof >/dev/null 2>&1; then
            lsof -iTCP:"$port" -sTCP:LISTEN 2>/dev/null | grep -q LISTEN && continue
            lsof -iUDP:"$port" 2>/dev/null | grep -q . && continue
        elif command -v ss >/dev/null 2>&1; then
            ss -tln sport = :"$port" 2>/dev/null | grep -q ":$port " && continue
            ss -uln sport = :"$port" 2>/dev/null | grep -q ":$port " && continue
        fi
        echo "$port"
        return
    done
}

wait_for_port() {
    local host="$1" port="$2" timeout="${3:-10}"
    local deadline=$(($(date +%s) + timeout))
    while ! nc -z "$host" "$port" 2>/dev/null; do
        if [[ $(date +%s) -gt $deadline ]]; then
            return 1
        fi
        sleep 0.1
    done
    return 0
}

# Wait for a proxy port to be listening WITHOUT connecting to it.
# nc -z triggers ProxyUserConn in Rust frps, creating phantom work connections
# that can deadlock encrypted bridges. Use lsof instead (check LISTEN state).
wait_for_port_safe() {
    local host="$1" port="$2" timeout="${3:-15}"
    local deadline=$(($(date +%s) + timeout))
    if command -v lsof >/dev/null 2>&1; then
        while true; do
            if lsof -iTCP:"$port" -sTCP:LISTEN -t >/dev/null 2>&1; then
                return 0
            fi
            if [[ $(date +%s) -gt $deadline ]]; then
                return 1
            fi
            sleep 0.1
        done
    elif command -v ss >/dev/null 2>&1; then
        while true; do
            if ss -tln sport = :"$port" 2>/dev/null | grep -q ":$port "; then
                return 0
            fi
            if [[ $(date +%s) -gt $deadline ]]; then
                return 1
            fi
            sleep 0.1
        done
    elif command -v nc >/dev/null 2>&1; then
        while true; do
            if nc -z "$host" "$port" 2>/dev/null; then
                return 0
            fi
            if [[ $(date +%s) -gt $deadline ]]; then
                return 1
            fi
            sleep 0.1
        done
    else
        echo "WARNING: neither lsof, ss, nor nc available; sleeping ${timeout}s" >&2
        sleep "$timeout"
        return 0
    fi
}

wait_for_port_gone() {
    local host="$1" port="$2" timeout="${3:-5}"
    local deadline=$(($(date +%s) + timeout))
    while nc -z "$host" "$port" 2>/dev/null; do
        if [[ $(date +%s) -gt $deadline ]]; then
            return 1
        fi
        sleep 0.1
    done
    return 0
}

start_echo_server() {
    local port="$1"
    python3 -c "
import socket, sys, time
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', $port))
s.listen(5)
while True:
    try:
        conn, _ = s.accept()
        data = conn.recv(65536)
        if data:
            conn.sendall(data)
        # KCP: give kcp-go output goroutine time to flush pending writes
        # before Close(). Without this, Go frpc's libio.Join closes the
        # dialed KCP work conn immediately after echo server responds,
        # and kcp-go's Close() (flush=false) kills the output goroutine
        # before pending data reaches the wire.
        time.sleep(0.1)
        conn.close()
    except:
        break
" &
    track_pid $!
}

send_and_expect() {
    local port="$1" data="$2" expected="$3" timeout="${4:-10}"
    _SE_PORT="$port" _SE_DATA="$data" _SE_EXPECTED="$expected" _SE_TIMEOUT="$timeout" \
    python3 -c '
import os, socket, time
port = int(os.environ["_SE_PORT"])
data = os.environ["_SE_DATA"]
expected = os.environ["_SE_EXPECTED"]
timeout = float(os.environ["_SE_TIMEOUT"])
deadline = time.time() + timeout
# XTCP failover (STUN + NatHoleVisitor + TCP sim open + STCP fallback)
# takes ~20-25s with VPS latency. Use the full timeout on a single
# connection. Retrying creates a second visitor handler task whose
# XTCP cycle overlaps; first handler STCP data gets orphaned.
# For non-XTCP tests, cap per-attempt at 3s so retry logic can recover
# from transient races (e.g. KCP work conn pool not yet ready).
per_attempt = timeout if timeout >= 20 else min(timeout, 3.0)
while True:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(per_attempt)
        s.connect(("127.0.0.1", port))
        s.sendall(data.encode())
        reply = s.recv(4096).decode()
        s.close()
        if reply == expected:
            print("OK:" + repr(reply))
        elif reply == "" and time.time() < deadline:
            # Empty reply = encrypted bridge closed before data round-trip.
            # Retry after a short delay (common with TLS+encrypt on first
            # proxy connection before the work-conn IV exchange completes).
            time.sleep(0.5)
            continue
        else:
            print("FAIL:MISMATCH expected=" + repr(expected) + " got=" + repr(reply))
        raise SystemExit(0)
    except (ConnectionRefusedError, OSError) as e:
        try: s.close()
        except: pass
        if time.time() > deadline:
            print("FAIL:CONNECT_TIMEOUT")
            raise SystemExit(0)
        time.sleep(0.3)
    except socket.timeout:
        try: s.close()
        except: pass
        if time.time() > deadline:
            print("FAIL:TIMEOUT")
            raise SystemExit(0)
        time.sleep(0.3)
    except Exception as e:
        try: s.close()
        except: pass
        print("FAIL:ERROR " + str(e))
        raise SystemExit(0)
' || echo "FAIL:PYTHON_ERROR"
}
start_udp_echo_server() {
    local port="$1"
    SE_UDP_PORT="$port" python3 -c '
import os, socket
port = int(os.environ["SE_UDP_PORT"])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", port))
while True:
    try:
        data, addr = s.recvfrom(4096)
        s.sendto(data, addr)
    except:
        break
' &
    track_pid $!
}

send_and_expect_udp() {
    local proxy_port="$1"
    local test_data="$2"
    local timeout="${3:-15}"
    _USE_PORT="$proxy_port" _USE_DATA="$test_data" _USE_TO="$timeout" \
    python3 -c '
import os, socket, time
port = int(os.environ["_USE_PORT"])
test_data = os.environ["_USE_DATA"].encode()
timeout = float(os.environ["_USE_TO"])
deadline = time.time() + timeout
# Use short per-attempt timeout so retries actually work within the deadline
per_attempt = min(3.0, timeout / 3)
while True:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(per_attempt)
        s.sendto(test_data, ("127.0.0.1", port))
        data, addr = s.recvfrom(4096)
        s.close()
        if data == test_data:
            print("OK")
        else:
            print("FAIL:MISMATCH expected=" + repr(test_data) + " got=" + repr(data))
        raise SystemExit(0)
    except socket.timeout:
        try: s.close()
        except: pass
        if time.time() > deadline:
            print("FAIL:TIMEOUT")
            raise SystemExit(0)
        time.sleep(0.3)
    except Exception as e:
        try: s.close()
        except: pass
        if time.time() > deadline:
            print("FAIL:ERROR " + str(e))
            raise SystemExit(0)
        time.sleep(0.3)
' 2>&1 || echo "FAIL:PYTHON_ERROR"
}

start_http_echo_server() {
    local port="$1"
    local body_prefix="${2:-http-ok}"
    SE_HTTP_PORT="$port" SE_HTTP_PREFIX="$body_prefix" python3 -c '
import os, socket
port = int(os.environ["SE_HTTP_PORT"])
prefix = os.environ["SE_HTTP_PREFIX"]
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port))
s.listen(5)
while True:
    try:
        conn, _ = s.accept()
        data = b""
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data += chunk
            if b"\r\n\r\n" in data:
                hdr_end = data.index(b"\r\n\r\n") + 4
                hdrs = data[:hdr_end].decode("utf-8", errors="ignore").lower()
                cl = 0
                for line in hdrs.split("\r\n"):
                    if line.startswith("content-length:"):
                        try:
                            cl = int(line.split(":")[1].strip())
                        except: pass
                if len(data) - hdr_end >= cl:
                    break
        if data:
            body = prefix.encode() + (data.split(b"\r\n\r\n", 1)[-1] if b"\r\n\r\n" in data else b"")
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
        conn.close()
    except:
        break
' &
    track_pid $!
}

send_http_test() {
    local vhost_port="$1"
    local host="$2"
    local body_prefix="${3:-http-ok}"
    local timeout="${4:-5}"
    SE_VHOST="$vhost_port" SE_HOST="$host" SE_PREFIX="$body_prefix" SE_TO="$timeout" \
    python3 -c '
import os, socket
port = int(os.environ["SE_VHOST"])
host = os.environ["SE_HOST"]
prefix = os.environ["SE_PREFIX"]
timeout = float(os.environ["SE_TO"])
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(timeout)
s.connect(("127.0.0.1", port))
req = b"POST /test HTTP/1.1\r\nHost: " + host.encode() + b"\r\nContent-Length: 5\r\n\r\nhello"
s.sendall(req)
data = s.recv(4096)
s.close()
if (prefix.encode() + b"hello") in data:
    print("OK")
else:
    print("FAIL: unexpected response: " + repr(data[:200]))
' 2>&1
}

# HTTPS-vhost TLS echo server: terminates TLS locally (the backend behind an
# https proxy is a plain HTTP service reached AFTER frpc's TLS termination —
# Go frp semantics: frps/frpc pass TLS bytes through; the local service is
# whatever the user points at, and the compat test uses a TLS-terminating
# echo so the HTTPS proxy flow is exercised end to end.
start_tls_echo_server() {
    local port="$1"
    local body_prefix="${2:-https-ok}"
    SE_TLS_PORT="$port" SE_TLS_PREFIX="$body_prefix" SE_CERT="$CERT_DIR/server.crt" SE_KEY="$CERT_DIR/server.key" python3 -c '
import os, socket, ssl
port = int(os.environ["SE_TLS_PORT"])
prefix = os.environ["SE_TLS_PREFIX"]
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port))
s.listen(5)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(os.environ["SE_CERT"], os.environ["SE_KEY"])
while True:
    try:
        raw, _ = s.accept()
        conn = ctx.wrap_socket(raw, server_side=True)
        data = b""
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data += chunk
            if b"\r\n\r\n" in data:
                hdr_end = data.index(b"\r\n\r\n") + 4
                hdrs = data[:hdr_end].decode("utf-8", errors="ignore").lower()
                cl = 0
                for line in hdrs.split("\r\n"):
                    if line.startswith("content-length:"):
                        try:
                            cl = int(line.split(":")[1].strip())
                        except: pass
                if len(data) - hdr_end >= cl:
                    break
        body = prefix.encode() + (data.split(b"\r\n\r\n", 1)[-1] if b"\r\n\r\n" in data else b"")
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
        conn.close()
    except Exception:
        # Non-TLS probes (e.g. wait_for_port nc -z) fail the handshake;
        # keep serving rather than exiting.
        try:
            conn.close()
        except Exception:
            pass
' &
    track_pid $!
}

send_https_test() {
    local vhost_port="$1"
    local host="$2"
    local body_prefix="${3:-https-ok}"
    local timeout="${4:-5}"
    SE_VHOST="$vhost_port" SE_HOST="$host" SE_PREFIX="$body_prefix" SE_TO="$timeout" \
    python3 -c '
import os, socket, ssl
port = int(os.environ["SE_VHOST"])
host = os.environ["SE_HOST"]
prefix = os.environ["SE_PREFIX"]
timeout = float(os.environ["SE_TO"])
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(timeout)
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
ss = ctx.wrap_socket(s, server_hostname=host)
ss.connect(("127.0.0.1", port))
req = b"POST /test HTTP/1.1\r\nHost: " + host.encode() + b"\r\nContent-Length: 5\r\n\r\nhello"
ss.sendall(req)
data = ss.recv(4096)
ss.close()
if (prefix.encode() + b"hello") in data:
    print("OK")
else:
    print("FAIL: unexpected response: " + repr(data[:200]))
' 2>&1
}

send_tcpmux_test() {
    local tcpmux_port="$1"
    local domain="$2"
    local test_data="${3:-tcpmux-echo}"
    local timeout="${4:-10}"
    SE_PORT="$tcpmux_port" SE_DOMAIN="$domain" SE_DATA="$test_data" SE_TO="$timeout" \
    python3 -c '
import os, socket, time
port = int(os.environ["SE_PORT"])
domain = os.environ["SE_DOMAIN"]
test_data = os.environ["SE_DATA"].encode()
timeout = float(os.environ["SE_TO"])
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(timeout)
deadline = time.time() + timeout
while True:
    try:
        s.connect(("127.0.0.1", port))
        break
    except (ConnectionRefusedError, OSError):
        if time.time() > deadline:
            print("FAIL:CONNECT_TIMEOUT")
            raise SystemExit(0)
        time.sleep(0.5)
req = b"CONNECT " + domain.encode() + b":22 HTTP/1.1\r\nHost: " + domain.encode() + b":22\r\n\r\n"
s.sendall(req)
resp = b""
while b"\r\n\r\n" not in resp:
    chunk = s.recv(4096)
    if not chunk:
        break
    resp += chunk
if not resp.startswith(b"HTTP/1.1 200"):
    print("FAIL:CONNECT_RESPONSE " + repr(resp[:200]))
    s.close()
    raise SystemExit(0)
s.sendall(test_data)
reply = s.recv(4096)
s.close()
if reply == test_data:
    print("OK:tcpmux")
else:
    print("FAIL:MISMATCH expected=" + repr(test_data) + " got=" + repr(reply[:200]))
' 2>&1
}

send_socks5_test() {
    local proxy_port="$1"
    local echo_port="$2"
    local test_data="${3:-socks5-test}"
    local timeout="${4:-10}"
    SE_PROXY="$proxy_port" SE_ECHO="$echo_port" SE_DATA="$test_data" SE_TO="$timeout" \
    python3 -c '
import os, socket, struct
proxy_port = int(os.environ["SE_PROXY"])
echo_port = int(os.environ["SE_ECHO"])
test_data = os.environ["SE_DATA"].encode()
timeout = float(os.environ["SE_TO"])
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(timeout)
s.connect(("127.0.0.1", proxy_port))
# SOCKS5 handshake (no auth)
s.sendall(b"\x05\x01\x00")
reply = s.recv(2)
if reply != b"\x05\x00":
    print("FAIL:SOCKS5_HANDSHAKE " + str(reply))
    raise SystemExit(0)
# SOCKS5 CONNECT to echo server
host = b"\x7f\x00\x00\x01"
port_bytes = struct.pack(">H", echo_port)
s.sendall(b"\x05\x01\x00\x01" + host + port_bytes)
reply = s.recv(10)
if len(reply) < 10 or reply[0] != 0x05:
    print("FAIL:SOCKS5_CONNECT " + str(reply[:10]))
    raise SystemExit(0)
if reply[1] != 0x00:
    print("FAIL:SOCKS5_CONNECT_REFUSED code=" + str(reply[1]))
    raise SystemExit(0)
# Echo test through SOCKS5 tunnel
s.sendall(test_data)
data = s.recv(1024)
if data == test_data:
    print("OK:socks5")
else:
    print("FAIL:MISMATCH expected=" + repr(test_data) + " got=" + repr(data))
s.close()
' 2>&1
}

log() {
    echo -e "${YELLOW}[LOG]${NC} $*" >&2
}

pass_test() {
    local name="$1"
    if $CI; then
        echo "[PASS] $name"
    else
        echo -e "${GREEN}[PASS]${NC} $name"
    fi
    PASS=$((PASS + 1))
}

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
        # Collect logs from both top-level (Go frpc) and subdirectories (Rust frpc)
        for f in "$TEST_DIR"/*.log "$TEST_DIR"/*/*.log; do
            if [[ -f "$f" ]]; then
                echo "=== $(basename "$f") ==="
                tail -30 "$f"
            fi
        done
        echo "--- end logs ---"
    fi
}

should_run_test() {
    if [[ -z "$SELECTED_TEST" ]]; then
        return 0
    fi
    [[ "$SELECTED_TEST" == "$1" ]]
}

# Wrapper that enables set -x tracing in --debug mode.
# Uses a subshell so set -x doesn't leak across tests.
run_test() {
    if $DEBUG; then
        (set -x; "$@")
    else
        "$@"
    fi
}

# ── Unified config writers ─────────────────────────────────

write_frps_config() {
    local impl="$1" port="$2" token="$3" out="$4" features="${5:-}"
    local has_tls=false has_mux=false has_ws=false kcp_port="" quic_port="" tcpmux_port="" extra_line=""
    local vhost_wss_port=""
    for feat in $features; do
        case "$feat" in
            tls) has_tls=true ;;
            mux) has_mux=true ;;
            ws) has_ws=true ;;
            kcp=*) kcp_port="${feat#kcp=}" ;;
            quic=*) quic_port="${feat#quic=}"; has_tls=true ;;
            tcpmux=*) tcpmux_port="${feat#tcpmux=}" ;;
            vhost_wss=*) vhost_wss_port="${feat#vhost_wss=}" ;;
            extra=*) extra_line="${feat#extra=}" ;;
        esac
    done
    local mux_val="false"; $has_mux && mux_val="true"
    if [[ "$impl" == "go" ]]; then
        {
            printf 'bindAddr = "127.0.0.1"\nbindPort = %s\n' "$port"
            [[ -n "$kcp_port" ]] && printf 'kcpBindPort = %s\n' "$kcp_port"
            [[ -n "$quic_port" ]] && printf 'quicBindPort = %s\n' "$quic_port"
            [[ -n "$tcpmux_port" ]] && printf 'tcpmuxHTTPConnectPort = %s\n' "$tcpmux_port"
            printf '\nauth.method = "token"\nauth.token = "%s"\n\n' "$token"
            if [[ -n "$vhost_wss_port" ]]; then
                # WSS: separate vhostHTTPSPort (Go frp requires different port
                # from bindPort for WSS; same-port tls.force+vhostHTTPPort breaks frpMuxer).
                printf 'transport.tls.certFile = "%s/server.crt"\n' "$CERT_DIR"
                printf 'transport.tls.keyFile = "%s/server.key"\n' "$CERT_DIR"
            elif $has_tls; then
                printf 'transport.tls.force = true\n'
                printf 'transport.tls.certFile = "%s/server.crt"\n' "$CERT_DIR"
                printf 'transport.tls.keyFile = "%s/server.key"\n' "$CERT_DIR"
            fi
            printf 'transport.tcpMux = %s\n\n' "$mux_val"
            if [[ -n "$vhost_wss_port" ]]; then
                printf '# Separate WSS port — HandleMux HTTPS listener\n'
                printf 'vhostHTTPSPort = %s\n\n' "$vhost_wss_port"
            elif $has_ws; then
                printf '# Same port as bindPort — enables HandleMux WS→VHost internal proxy\n'
                printf 'vhostHTTPPort = %s\n\n' "$port"
            fi
            printf 'log.to = "%s/go-frps.log"\nlog.level = "debug"\n' "$TEST_DIR"
            [[ -n "$extra_line" ]] && printf '%s\n' "$extra_line" || true
        } > "$out"
    else
        {
            printf 'bind_addr = "127.0.0.1"\nbind_port = %s\n' "$port"
            [[ -n "$kcp_port" ]] && printf 'kcp_bind_port = %s\n' "$kcp_port"
            [[ -n "$quic_port" ]] && printf 'quic_bind_port = %s\n' "$quic_port"
            [[ -n "$tcpmux_port" ]] && printf 'tcpmux_httpconnect_port = %s\n' "$tcpmux_port"
            if $has_tls; then
                [[ -n "$quic_port" ]] && printf '\n# QUIC requires TLS\n'
                printf 'tls_enable = true\n'
                printf 'tls_cert_file = "%s/server.crt"\n' "$CERT_DIR"
                printf 'tls_key_file = "%s/server.key"\n' "$CERT_DIR"
            fi
            printf '\n[auth]\nmethod = "token"\ntoken = "%s"\n\n[transport]\ntcp_mux = %s\n\n' "$token" "$mux_val"
            [[ -n "$extra_line" ]] && printf '%s\n' "$extra_line" || true
        } > "$out"
    fi
}

write_frpc_config() {
    local impl="$1" server_port="$2" token="$3" echo_port="$4" proxy_port="$5" \
          name="$6" out="$7" features="${8:-}"
    local has_tls=false has_mux=false has_ws=false has_wss=false has_kcp=false has_quic=false
    local has_enc=false has_comp=false extra_line=""
    for feat in $features; do
        case "$feat" in
            tls) has_tls=true ;;
            mux) has_mux=true ;;
            ws) has_ws=true ;;
            wss) has_wss=true; has_tls=true ;;
            kcp) has_kcp=true ;;
            quic) has_quic=true; has_tls=true ;;
            enc) has_enc=true ;;
            compression) has_comp=true ;;
            extra=*) extra_line="${feat#extra=}" ;;
        esac
    done
    local mux_val="false"; $has_mux && mux_val="true"
    if [[ "$impl" == "go" ]]; then
        {
            printf 'serverAddr = "127.0.0.1"\nserverPort = %s\n\n' "$server_port"
            printf 'auth.token = "%s"\n\n' "$token"
            if $has_ws || $has_wss || $has_kcp || $has_quic; then
                local proto=""
                $has_ws && proto="websocket"
                $has_wss && proto="wss"
                $has_kcp && proto="kcp"
                $has_quic && proto="quic"
                printf 'transport.protocol = "%s"\n' "$proto"
            fi
            if $has_tls; then
                printf 'transport.tls.enable = true\n'
                printf 'transport.tls.disableCustomTLSFirstByte = true\n'
                printf 'transport.tls.trustedCaFile = "%s/ca.crt"\n' "$CERT_DIR"
                printf 'transport.tls.serverName = "localhost"\n'
            else
                printf 'transport.tls.enable = false\n'
            fi
            printf 'transport.tcpMux = %s\n\n' "$mux_val"
            printf 'log.to = "%s/go-frpc-%s.log"\nlog.level = "debug"\n\n' "$TEST_DIR" "$name"
            printf '[[proxies]]\nname = "%s"\ntype = "tcp"\nlocalIP = "127.0.0.1"\n' "$name"
            printf 'localPort = %s\nremotePort = %s\n' "$echo_port" "$proxy_port"
            if $has_enc; then printf '\ntransport.useEncryption = true\n'; fi
            if $has_comp; then printf 'transport.useCompression = true\n'; fi
            [[ -n "$extra_line" ]] && printf '%s\n' "$extra_line" || true
        } > "$out"
    else
        {
            printf 'server_addr = "127.0.0.1"\nserver_port = %s\n' "$server_port"
            printf 'token = "%s"\n' "$token"
            printf 'tcp_mux = %s\n' "$mux_val"
            printf 'login_fail_exit = true\npool_count = 1\n'
            if $has_ws || $has_wss || $has_kcp || $has_quic; then
                local proto=""
                $has_ws && proto="websocket"
                $has_wss && proto="wss"
                $has_kcp && proto="kcp"
                $has_quic && proto="quic"
                printf 'transport_protocol = "%s"\n' "$proto"
            fi
            if $has_tls; then
                printf 'tls_enable = true\n'
                printf 'tls_ca_file = "%s/ca.crt"\n' "$CERT_DIR"
                printf 'tls_server_name = "localhost"\n'
                printf 'disable_custom_tls_first_byte = true\n'
            else
                printf 'tls_enable = false\n'
            fi
            printf '\n[[proxies]]\nname = "%s"\ntype = "tcp"\nlocal_ip = "127.0.0.1"\n' "$name"
            printf 'local_port = %s\nremote_port = %s\n' "$echo_port" "$proxy_port"
            if $has_enc; then printf 'use_encryption = true\n'; fi
            if $has_comp; then printf 'use_compression = true\n'; fi
            [[ -n "$extra_line" ]] && printf '%s\n' "$extra_line" || true
        } > "$out"
    fi
}

write_frpc_config_udp() {
    local impl="$1" server_port="$2" token="$3" echo_port="$4" proxy_port="$5" \
          name="$6" out="$7" features="${8:-}"
    local has_tls=false has_mux=false has_enc=false has_comp=false extra_line=""
    for feat in $features; do
        case "$feat" in
            tls) has_tls=true ;;
            mux) has_mux=true ;;
            enc) has_enc=true ;;
            compression) has_comp=true ;;
            extra=*) extra_line="${feat#extra=}" ;;
        esac
    done
    local mux_val="false"; $has_mux && mux_val="true"
    if [[ "$impl" == "go" ]]; then
        {
            printf 'serverAddr = "127.0.0.1"\nserverPort = %s\n' "$server_port"
            printf 'auth.token = "%s"\n' "$token"
            if $has_tls; then
                printf 'transport.tls.enable = true\n'
                printf 'transport.tls.disableCustomTLSFirstByte = true\n'
                printf 'transport.tls.trustedCaFile = "%s/ca.crt"\n' "$CERT_DIR"
                printf 'transport.tls.serverName = "localhost"\n'
            else
                printf 'transport.tls.enable = false\n'
            fi
            printf 'transport.tcpMux = %s\n' "$mux_val"
            printf 'log.to = "%s/go-frpc-%s.log"\nlog.level = "debug"\n\n' "$TEST_DIR" "$name"
            printf '[[proxies]]\nname = "%s"\ntype = "udp"\nlocalIP = "127.0.0.1"\n' "$name"
            printf 'localPort = %s\nremotePort = %s\n' "$echo_port" "$proxy_port"
            if $has_enc; then printf 'transport.useEncryption = true\n'; fi
            [[ -n "$extra_line" ]] && printf '%s\n' "$extra_line" || true
        } > "$out"
    else
        {
            printf 'server_addr = "127.0.0.1"\nserver_port = %s\n' "$server_port"
            printf 'token = "%s"\n' "$token"
            printf 'tcp_mux = %s\n' "$mux_val"
            printf 'tls_enable = false\n'
            printf 'login_fail_exit = true\npool_count = 1\n'
            printf '\n[[proxies]]\nname = "%s"\ntype = "udp"\nlocal_ip = "127.0.0.1"\n' "$name"
            printf 'local_port = %s\nremote_port = %s\n' "$echo_port" "$proxy_port"
            if $has_enc; then printf 'use_encryption = true\n'; fi
            [[ -n "$extra_line" ]] && printf '%s\n' "$extra_line" || true
        } > "$out"
    fi
}

write_frpc_config_tcpmux() {
    local impl="$1" server_port="$2" token="$3" echo_port="$4" \
          name="$5" domain="$6" out="$7" features="${8:-}"
    local has_tls=false has_mux=false extra_line=""
    for feat in $features; do
        case "$feat" in
            tls) has_tls=true ;;
            mux) has_mux=true ;;
            extra=*) extra_line="${feat#extra=}" ;;
        esac
    done
    local mux_val="false"; $has_mux && mux_val="true"
    if [[ "$impl" == "go" ]]; then
        {
            printf 'serverAddr = "127.0.0.1"\nserverPort = %s\n' "$server_port"
            printf 'auth.token = "%s"\n' "$token"
            if $has_tls; then
                printf 'transport.tls.enable = true\n'
                printf 'transport.tls.disableCustomTLSFirstByte = true\n'
                printf 'transport.tls.trustedCaFile = "%s/ca.crt"\n' "$CERT_DIR"
                printf 'transport.tls.serverName = "localhost"\n'
            else
                printf 'transport.tls.enable = false\n'
            fi
            printf 'transport.tcpMux = %s\n' "$mux_val"
            printf 'log.to = "%s/go-frpc-%s.log"\nlog.level = "debug"\n\n' "$TEST_DIR" "$name"
            printf '[[proxies]]\nname = "%s"\ntype = "tcpmux"\nmultiplexer = "httpconnect"\n' "$name"
            printf 'localIP = "127.0.0.1"\nlocalPort = %s\ncustomDomains = ["%s"]\n' "$echo_port" "$domain"
            [[ -n "$extra_line" ]] && printf '%s\n' "$extra_line" || true
        } > "$out"
    else
        {
            printf 'server_addr = "127.0.0.1"\nserver_port = %s\n' "$server_port"
            printf 'token = "%s"\n' "$token"
            printf 'tcp_mux = %s\n' "$mux_val"
            printf 'tls_enable = false\n'
            printf 'login_fail_exit = true\npool_count = 1\n'
            printf '\n[[proxies]]\nname = "%s"\ntype = "tcpmux"\nmultiplexer = "httpconnect"\n' "$name"
            printf 'local_ip = "127.0.0.1"\nlocal_port = %s\ncustom_domains = ["%s"]\n' "$echo_port" "$domain"
            [[ -n "$extra_line" ]] && printf '%s\n' "$extra_line" || true
        } > "$out"
    fi
}

write_frpc_config_xtcp_provider() {
    local impl="$1" server_host="$2" server_port="$3" token="$4" echo_port="$5" \
          name="$6" sk="$7" out="$8" features="${9:-}"
    local has_enc=false has_comp=false
    for feat in $features; do
        case "$feat" in enc) has_enc=true ;; compression) has_comp=true ;; esac
    done
    if [[ "$impl" == "go" ]]; then
        {
            printf 'serverAddr = "%s"\nserverPort = %s\n\n' "$server_host" "$server_port"
            printf 'auth.token = "%s"\n\n' "$token"
            printf 'transport.tls.enable = false\n'
            printf 'transport.tcpMux = false\n\n'
            printf 'log.to = "%s/go-frpc-provider-%s.log"\nlog.level = "debug"\n\n' "$TEST_DIR" "$name"
            printf '[[proxies]]\nname = "%s"\ntype = "xtcp"\n' "$name"
            printf 'secretKey = "%s"\n' "$sk"
            printf 'localIP = "127.0.0.1"\nlocalPort = %s\n' "$echo_port"
                        if $has_enc; then printf 'transport.useEncryption = true\n'; fi
            if $has_comp; then printf 'transport.useCompression = true\n'; fi
            printf '\n[[proxies]]\nname = "%s-stcp"\ntype = "stcp"\n' "$name"
            printf 'secretKey = "%s"\n' "$sk"
            printf 'localIP = "127.0.0.1"\nlocalPort = %s\n' "$echo_port"
            # STCP fallback proxy is always plain relay — encryption is P2P-only
        } > "$out"
    else
        {
            printf 'server_addr = "%s"\nserver_port = %s\n' "$server_host" "$server_port"
            printf 'token = "%s"\n' "$token"
            printf 'tcp_mux = false\n'
            printf 'tls_enable = false\n'
            printf 'login_fail_exit = true\npool_count = 1\n'
            printf 'nat_hole_stun_server = "stun.l.google.com:19302"\n'
            printf '\n[[proxies]]\nname = "%s"\ntype = "xtcp"\n' "$name"
            printf 'sk = "%s"\n' "$sk"
            printf 'local_ip = "127.0.0.1"\nlocal_port = %s\n' "$echo_port"
            if $has_enc; then printf 'use_encryption = true\n'; fi
            if $has_comp; then printf 'use_compression = true\n'; fi
            printf '\n[[proxies]]\nname = "%s-stcp"\ntype = "stcp"\n' "$name"
            printf 'sk = "%s"\n' "$sk"
            printf 'local_ip = "127.0.0.1"\nlocal_port = %s\n' "$echo_port"
            # STCP fallback proxy is always plain relay — encryption is P2P-only
        } > "$out"
    fi
}

write_frpc_config_xtcp_visitor() {
    local impl="$1" server_host="$2" server_port="$3" token="$4" visitor_port="$5" \
          server_name="$6" sk="$7" out="$8" features="${9:-}"
    local has_enc=false has_comp=false has_kcp=false has_quic=false
    for feat in $features; do
        case "$feat" in enc) has_enc=true ;; compression) has_comp=true ;; kcp) has_kcp=true ;; quic) has_quic=true ;; esac
    done
    if [[ "$impl" == "go" ]]; then
        {
            printf 'serverAddr = "%s"\nserverPort = %s\n\n' "$server_host" "$server_port"
            printf 'auth.token = "%s"\n\n' "$token"
            printf 'transport.tls.enable = false\n'
            printf 'transport.tcpMux = false\n\n'
            printf 'log.to = "%s/go-frpc-visitor-%s.log"\nlog.level = "debug"\n\n' "$TEST_DIR" "$server_name"
            printf '[[visitors]]\nname = "%s-visitor"\ntype = "xtcp"\n' "$server_name"
            printf 'serverName = "%s"\n' "$server_name"
            printf 'secretKey = "%s"\n' "$sk"
            printf 'bindAddr = "127.0.0.1"\nbindPort = %s\n' "$visitor_port"
            # No fallbackTo — P2P must succeed for the test to pass.
            # STCP fallback would mask XTCP failures (compat matrix P1).
            # Go frp v0.70 defaults to protocol="quic" for XTCP P2P tunnel.
            # Force KCP (or explicitly QUIC) per the scenario's features so the
            # Go↔Rust data plane matches the Rust implementation.
            if $has_quic; then printf 'protocol = "quic"\n'; fi
            if $has_kcp; then printf 'protocol = "kcp"\n'; fi
            if $has_enc; then printf 'transport.useEncryption = true\n'; fi
            if $has_comp; then printf 'transport.useCompression = true\n'; fi
        } > "$out"
    else
        {
            printf 'server_addr = "%s"\nserver_port = %s\n' "$server_host" "$server_port"
            printf 'token = "%s"\n' "$token"
            printf 'tcp_mux = false\n'
            printf 'tls_enable = false\n'
            printf 'login_fail_exit = true\npool_count = 1\n'
            printf 'nat_hole_stun_server = "stun.l.google.com:19302"\n'
            printf '\n[[visitors]]\nname = "%s-visitor"\ntype = "xtcp"\n' "$server_name"
            printf 'server_name = "%s"\n' "$server_name"
            printf 'sk = "%s"\n' "$sk"
            printf 'bind_addr = "127.0.0.1"\nbind_port = %s\n' "$visitor_port"
            # No fallback_to — P2P must succeed for the test to pass.
            # STCP fallback would mask XTCP failures (compat matrix P1).
            # XTCP P2P tunnel protocol: kcp (default) or quic per features.
            if $has_quic; then printf 'protocol = "quic"\n'; else printf 'protocol = "kcp"\n'; fi
            if $has_enc; then printf 'use_encryption = true\n'; fi
            if $has_comp; then printf 'use_compression = true\n'; fi
        } > "$out"
    fi
}

# =============================================================================
# Test: Go frpc -> Rust frps, OIDC auth with HTTP CONNECT proxy (auth.oidc.proxyURL)
# =============================================================================
# The mock OIDC provider and the CONNECT proxy are only reachable on
# 127.0.0.1, so a successful login also proves the OIDC HTTP requests were
# routed through the proxy (proxy.log records the CONNECT), i.e. that Go
# frp's proxyURL is honored end-to-end.
test_g2r_oidc_proxy() {
    local name="go-to-rust-oidc-proxy"
    should_run_test "$name" || return 0

    log "=== $name ==="
    local frps_port=$(random_port)
    local oidc_port=$(random_port)
    local proxy_port=$(random_port)
    local oidc_issuer="http://127.0.0.1:$oidc_port"
    local oidc_secret="mock-oidc-secret"
    local oidc_aud="frp-test-aud"

    mkdir -p "$TEST_DIR/$name"

    # Mock OIDC provider (discovery + token + JWKS, HS256) and CONNECT proxy
    python3 "$SCRIPT_DIR/mock_oidc.py" "$oidc_port" "$oidc_issuer" "$oidc_secret" "$oidc_aud" \
        > "$TEST_DIR/$name/oidc.out" 2>&1 &
    track_pid $!
    python3 "$SCRIPT_DIR/connect_proxy.py" "$proxy_port" "$TEST_DIR/$name/proxy.log" \
        > "$TEST_DIR/$name/proxy.out" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$oidc_port" 3 || {
        fail_test "$name" "OIDC provider did not start"
        return
    }
    wait_for_port 127.0.0.1 "$proxy_port" 3 || {
        fail_test "$name" "CONNECT proxy did not start"
        return
    }

    # Rust frps with OIDC auth (verifies the token's iss/aud/exp against JWKS)
    cat > "$TEST_DIR/$name/frps.toml" <<TOML
bind_addr = "127.0.0.1"
bind_port = $frps_port

[auth]
method = "oidc"

[auth.oidc]
issuer = "$oidc_issuer"
audience = "$oidc_aud"
TOML
    RUST_LOG=info "$RUST_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Rust frps did not start"
        return
    }

    # Go frpc with OIDC auth + proxyURL pointing at the local CONNECT proxy
    # (v0.70.1 client OIDC fields: clientID/clientSecret/tokenEndpointURL/
    # audience/proxyURL — no "issuer"; the mock provider serves the token
    # endpoint directly and the JWT's iss/aud are checked by Rust frps)
    cat > "$TEST_DIR/$name/frpc.toml" <<TOML
serverAddr = "127.0.0.1"
serverPort = $frps_port

auth.method = "oidc"
auth.oidc.clientID = "test-client"
auth.oidc.clientSecret = "test-secret"
auth.oidc.tokenEndpointURL = "$oidc_issuer/token"
auth.oidc.audience = "$oidc_aud"
auth.oidc.proxyURL = "http://127.0.0.1:$proxy_port"

[[proxies]]
name = "oidc-proxy-test"
type = "tcp"
localIP = "127.0.0.1"
localPort = 1
remotePort = $(random_port)
TOML
    # Use run_go so a proxy set via HTTP_PROXY/HTTPS_PROXY in the caller's
    # environment cannot hijack the OIDC HTTP requests away from our local
    # proxy (run_go clears proxy env vars for Go binaries).
    run_go "$GO_FRPC" -c "$TEST_DIR/$name/frpc.toml" \
        > "$TEST_DIR/$name/frpc.log" 2>&1 &
    track_pid $!

    # Login must succeed AND the proxy must have seen the OIDC traffic
    # (Go's oauth2 client uses HTTP CONNECT for https targets and
    # absolute-form forwarding for http targets — match either).
    local ok=false
    for _ in $(seq 1 15); do
        if grep -q "logged in with run_id" "$TEST_DIR/$name/frps.log" 2>/dev/null; then
            ok=true
            break
        fi
        sleep 1
    done
    if $ok && grep -qE "CONNECT 127\.0\.0\.1:$oidc_port|FORWARD (POST|GET) 127\.0\.0\.1:$oidc_port" "$TEST_DIR/$name/proxy.log" 2>/dev/null; then
        pass_test "$name"
    else
        fail_test "$name" \
            "login_ok=$ok frps_tail=[$(tail -3 "$TEST_DIR/$name/frps.log" 2>/dev/null | tr '\n' ' ')] proxy=[$(cat "$TEST_DIR/$name/proxy.log" 2>/dev/null | tr '\n' ' ')]"
    fi
}

# =============================================================================
# Test: Go frpc -> Rust frps, plain TCP
# =============================================================================
test_g2r_tcp_plain() {
    local name="go-to-rust-tcp-plain"
    should_run_test "$name" || return 0

    log "=== $name ==="
    local frps_port=$(random_port)
    local proxy_port=$(random_port)
    local echo_port=$(random_port)
    local token="test-token-g2r"

    mkdir -p "$TEST_DIR/$name"

    # Start echo server
    start_echo_server "$echo_port"
    wait_for_port 127.0.0.1 "$echo_port" 3 || {
        fail_test "$name" "echo server did not start"
        return
    }

    # Start Rust frps
    write_frps_config rust "$frps_port" "$token" "$TEST_DIR/$name/frps.toml" ""
    RUST_LOG=info "$RUST_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Rust frps did not start"
        return
    }

    # Start Go frpc
    write_frpc_config go "$frps_port" "$token" "$echo_port" "$proxy_port" "tcp-plain" "$TEST_DIR/$name/frpc.toml" ""
    run_go "$GO_FRPC" -c "$TEST_DIR/$name/frpc.toml" \
        > "$TEST_DIR/$name/frpc.log" 2>&1 &
    track_pid $!

    # Wait for proxy port
    if ! wait_for_port_safe 127.0.0.1 "$proxy_port" 10; then
        fail_test "$name" "proxy port $proxy_port not reachable"
        return
    fi

    # Test data round-trip
    local result
    result=$(send_and_expect "$proxy_port" "hello-frp-test" "hello-frp-test" 5)
    if [[ "$result" == OK:* ]]; then
        pass_test "$name"
    else
        fail_test "$name" "$result"
    fi
}

# =============================================================================
# Test: Go frpc -> Rust frps, encrypted TCP
# =============================================================================
test_g2r_tcp_encrypted() {
    local name="go-to-rust-tcp-encrypted"
    should_run_test "$name" || return 0

    log "=== $name ==="
    local frps_port=$(random_port)
    local proxy_port=$(random_port)
    local echo_port=$(random_port)
    local token="test-token-g2r-enc"

    mkdir -p "$TEST_DIR/$name"

    start_echo_server "$echo_port"
    wait_for_port 127.0.0.1 "$echo_port" 3 || {
        fail_test "$name" "echo server did not start"
        return
    }

    write_frps_config rust "$frps_port" "$token" "$TEST_DIR/$name/frps.toml" ""
    RUST_LOG=info "$RUST_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Rust frps did not start"
        return
    }

    write_frpc_config go "$frps_port" "$token" "$echo_port" "$proxy_port" "tcp-enc" "$TEST_DIR/$name/frpc.toml" "enc"
    run_go "$GO_FRPC" -c "$TEST_DIR/$name/frpc.toml" \
        > "$TEST_DIR/$name/frpc.log" 2>&1 &
    track_pid $!

    if ! wait_for_port_safe 127.0.0.1 "$proxy_port" 10; then
        fail_test "$name" "proxy port $proxy_port not reachable"
        return
    fi

    local result
    result=$(send_and_expect "$proxy_port" "encrypted-data-test" "encrypted-data-test" 5)
    if [[ "$result" == OK:* ]]; then
        pass_test "$name"
    else
        fail_test "$name" "$result"
    fi
}

# =============================================================================
# Test: Go frpc -> Rust frps, TLS transport
# =============================================================================
test_g2r_tcp_tls() {
    local name="go-to-rust-tcp-tls"
    should_run_test "$name" || return 0

    log "=== $name ==="
    local frps_port=$(random_port)
    local proxy_port=$(random_port)
    local echo_port=$(random_port)
    local token="test-token-g2r-tls"

    mkdir -p "$TEST_DIR/$name"

    start_echo_server "$echo_port"
    wait_for_port 127.0.0.1 "$echo_port" 3 || {
        fail_test "$name" "echo server did not start"
        return
    }

    write_frps_config rust "$frps_port" "$token" "$TEST_DIR/$name/frps.toml" "tls"
    RUST_LOG=info "$RUST_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Rust frps did not start"
        return
    }

    write_frpc_config go "$frps_port" "$token" "$echo_port" "$proxy_port" "tcp-tls" "$TEST_DIR/$name/frpc.toml" "tls"
    run_go "$GO_FRPC" -c "$TEST_DIR/$name/frpc.toml" \
        > "$TEST_DIR/$name/frpc.log" 2>&1 &
    track_pid $!

    if ! wait_for_port_safe 127.0.0.1 "$proxy_port" 15; then
        fail_test "$name" "proxy port $proxy_port not reachable"
        return
    fi

    local result
    result=$(send_and_expect "$proxy_port" "tls-data-test" "tls-data-test" 5)
    if [[ "$result" == OK:* ]]; then
        pass_test "$name"
    else
        fail_test "$name" "$result"
    fi
}

# =============================================================================
# Test: Go frpc -> Rust frps, TLS + encryption
# =============================================================================
test_g2r_tcp_tls_encrypt() {
    local name="go-to-rust-tcp-tls-encrypt"
    should_run_test "$name" || return 0

    log "=== $name ==="
    local frps_port=$(random_port)
    local proxy_port=$(random_port)
    local echo_port=$(random_port)
    local token="test-token-g2r-tls-enc"

    mkdir -p "$TEST_DIR/$name"

    start_echo_server "$echo_port"
    wait_for_port 127.0.0.1 "$echo_port" 3 || {
        fail_test "$name" "echo server did not start"
        return
    }

    write_frps_config rust "$frps_port" "$token" "$TEST_DIR/$name/frps.toml" "tls"
    RUST_LOG=info "$RUST_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Rust frps did not start"
        return
    }

    write_frpc_config go "$frps_port" "$token" "$echo_port" "$proxy_port" "tcp-tls-enc" "$TEST_DIR/$name/frpc.toml" "tls enc"
    run_go "$GO_FRPC" -c "$TEST_DIR/$name/frpc.toml" \
        > "$TEST_DIR/$name/frpc.log" 2>&1 &
    track_pid $!

    if ! wait_for_port_safe 127.0.0.1 "$proxy_port" 15; then
        fail_test "$name" "proxy port $proxy_port not reachable"
        return
    fi

    local result
    result=$(send_and_expect "$proxy_port" "tls-enc-data" "tls-enc-data" 5)
    if [[ "$result" == OK:* ]]; then
        pass_test "$name"
    else
        fail_test "$name" "$result"
    fi
}

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

    write_frps_config rust "$frps_port" "$token" "$TEST_DIR/$name/frps.toml" "mux"
    RUST_LOG=info "$RUST_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Rust frps did not start"
        return
    }

    write_frpc_config go "$frps_port" "$token" "$echo_port" "$proxy_port" "mux-plain" "$TEST_DIR/$name/frpc.toml" "mux"
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

    write_frps_config rust "$frps_port" "$token" "$TEST_DIR/$name/frps.toml" "mux"
    RUST_LOG=info "$RUST_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Rust frps did not start"
        return
    }

    write_frpc_config go "$frps_port" "$token" "$echo_port" "$proxy_port" "mux-enc" "$TEST_DIR/$name/frpc.toml" "mux enc"
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

    write_frps_config rust "$frps_port" "$token" "$TEST_DIR/$name/frps.toml" "tls mux"
    RUST_LOG=info "$RUST_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Rust frps did not start"
        return
    }

    write_frpc_config go "$frps_port" "$token" "$echo_port" "$proxy_port" "mux-tls" "$TEST_DIR/$name/frpc.toml" "tls mux"
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

    write_frps_config rust "$frps_port" "$token" "$TEST_DIR/$name/frps.toml" "tls mux"
    RUST_LOG=info "$RUST_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Rust frps did not start"
        return
    }

    write_frpc_config go "$frps_port" "$token" "$echo_port" "$proxy_port" "mux-tls-enc" "$TEST_DIR/$name/frpc.toml" "tls mux enc"
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

# =============================================================================
# Test: Rust frpc -> Go frps, plain TCP
# =============================================================================
test_r2g_tcp_plain() {
    local name="rust-to-go-tcp-plain"
    should_run_test "$name" || return 0

    log "=== $name ==="
    local frps_port=$(random_port)
    local proxy_port=$(random_port)
    local echo_port=$(random_port)
    local token="test-token-r2g"

    mkdir -p "$TEST_DIR/$name"

    start_echo_server "$echo_port"
    wait_for_port 127.0.0.1 "$echo_port" 3 || {
        fail_test "$name" "echo server did not start"
        return
    }

    # Start Go frps
    write_frps_config go "$frps_port" "$token" "$TEST_DIR/$name/frps.toml" ""
    run_go "$GO_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Go frps did not start"
        return
    }

    # Start Rust frpc
    write_frpc_config rust "$frps_port" "$token" "$echo_port" "$proxy_port" "tcp-plain" "$TEST_DIR/$name/frpc.toml" ""
    RUST_LOG=info "$RUST_FRPC" -c "$TEST_DIR/$name/frpc.toml" \
        > "$TEST_DIR/$name/frpc.log" 2>&1 &
    track_pid $!

    if ! wait_for_port_safe 127.0.0.1 "$proxy_port" 10; then
        fail_test "$name" "proxy port $proxy_port not reachable"
        return
    fi

    local result
    result=$(send_and_expect "$proxy_port" "r2g-hello" "r2g-hello" 5)
    if [[ "$result" == OK:* ]]; then
        pass_test "$name"
    else
        fail_test "$name" "$result"
    fi
}

# =============================================================================
# Test: Rust frpc -> Go frps, encrypted TCP
# =============================================================================
test_r2g_tcp_encrypted() {
    local name="rust-to-go-tcp-encrypted"
    should_run_test "$name" || return 0

    log "=== $name ==="
    local frps_port=$(random_port)
    local proxy_port=$(random_port)
    local echo_port=$(random_port)
    local token="test-token-r2g-enc"

    mkdir -p "$TEST_DIR/$name"

    start_echo_server "$echo_port"
    wait_for_port 127.0.0.1 "$echo_port" 3 || {
        fail_test "$name" "echo server did not start"
        return
    }

    write_frps_config go "$frps_port" "$token" "$TEST_DIR/$name/frps.toml" ""
    run_go "$GO_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Go frps did not start"
        return
    }

    write_frpc_config rust "$frps_port" "$token" "$echo_port" "$proxy_port" "tcp-enc" "$TEST_DIR/$name/frpc.toml" "enc"
    RUST_LOG=info "$RUST_FRPC" -c "$TEST_DIR/$name/frpc.toml" \
        > "$TEST_DIR/$name/frpc.log" 2>&1 &
    track_pid $!

    if ! wait_for_port_safe 127.0.0.1 "$proxy_port" 10; then
        fail_test "$name" "proxy port $proxy_port not reachable"
        return
    fi

    local result
    result=$(send_and_expect "$proxy_port" "r2g-encrypted" "r2g-encrypted" 5)
    if [[ "$result" == OK:* ]]; then
        pass_test "$name"
    else
        fail_test "$name" "$result"
    fi
}

# =============================================================================
# Test: Rust frpc -> Go frps, TLS transport
# =============================================================================
test_r2g_tcp_tls() {
    local name="rust-to-go-tcp-tls"
    should_run_test "$name" || return 0

    log "=== $name ==="
    local frps_port=$(random_port)
    local proxy_port=$(random_port)
    local echo_port=$(random_port)
    local token="test-token-r2g-tls"

    mkdir -p "$TEST_DIR/$name"

    start_echo_server "$echo_port"
    wait_for_port 127.0.0.1 "$echo_port" 3 || {
        fail_test "$name" "echo server did not start"
        return
    }

    write_frps_config go "$frps_port" "$token" "$TEST_DIR/$name/frps.toml" "tls"
    run_go "$GO_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Go frps did not start"
        return
    }

    write_frpc_config rust "$frps_port" "$token" "$echo_port" "$proxy_port" "tcp-tls" "$TEST_DIR/$name/frpc.toml" "tls"
    RUST_LOG=info "$RUST_FRPC" -c "$TEST_DIR/$name/frpc.toml" \
        > "$TEST_DIR/$name/frpc.log" 2>&1 &
    track_pid $!

    if ! wait_for_port_safe 127.0.0.1 "$proxy_port" 15; then
        fail_test "$name" "proxy port $proxy_port not reachable"
        return
    fi

    local result
    result=$(send_and_expect "$proxy_port" "r2g-tls-data" "r2g-tls-data" 5)
    if [[ "$result" == OK:* ]]; then
        pass_test "$name"
    else
        fail_test "$name" "$result"
    fi
}

# =============================================================================
# Test: Rust frpc -> Go frps, TLS + encryption
# =============================================================================
test_r2g_tcp_tls_encrypt() {
    local name="rust-to-go-tcp-tls-encrypt"
    should_run_test "$name" || return 0

    log "=== $name ==="
    local frps_port=$(random_port)
    local proxy_port=$(random_port)
    local echo_port=$(random_port)
    local token="test-token-r2g-tls-enc"

    mkdir -p "$TEST_DIR/$name"

    start_echo_server "$echo_port"
    wait_for_port 127.0.0.1 "$echo_port" 3 || {
        fail_test "$name" "echo server did not start"
        return
    }

    write_frps_config go "$frps_port" "$token" "$TEST_DIR/$name/frps.toml" "tls"
    run_go "$GO_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Go frps did not start"
        return
    }

    write_frpc_config rust "$frps_port" "$token" "$echo_port" "$proxy_port" "tcp-tls-enc" "$TEST_DIR/$name/frpc.toml" "tls enc"
    RUST_LOG=info "$RUST_FRPC" -c "$TEST_DIR/$name/frpc.toml" \
        > "$TEST_DIR/$name/frpc.log" 2>&1 &
    track_pid $!

    if ! wait_for_port_safe 127.0.0.1 "$proxy_port" 15; then
        fail_test "$name" "proxy port $proxy_port not reachable"
        return
    fi

    local result
    result=$(send_and_expect "$proxy_port" "r2g-tls-enc" "r2g-tls-enc" 5)
    if [[ "$result" == OK:* ]]; then
        pass_test "$name"
    else
        fail_test "$name" "$result"
    fi
}

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

    write_frps_config go "$frps_port" "$token" "$TEST_DIR/$name/frps.toml" "mux"
    run_go "$GO_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Go frps did not start"
        return
    }

    write_frpc_config rust "$frps_port" "$token" "$echo_port" "$proxy_port" "mux-plain" "$TEST_DIR/$name/frpc.toml" "mux"
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

    write_frps_config go "$frps_port" "$token" "$TEST_DIR/$name/frps.toml" "mux"
    run_go "$GO_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Go frps did not start"
        return
    }

    write_frpc_config rust "$frps_port" "$token" "$echo_port" "$proxy_port" "mux-enc" "$TEST_DIR/$name/frpc.toml" "mux enc"
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

    write_frps_config go "$frps_port" "$token" "$TEST_DIR/$name/frps.toml" "tls mux"
    run_go "$GO_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Go frps did not start"
        return
    }

    write_frpc_config rust "$frps_port" "$token" "$echo_port" "$proxy_port" "mux-tls" "$TEST_DIR/$name/frpc.toml" "tls mux"
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

    write_frps_config go "$frps_port" "$token" "$TEST_DIR/$name/frps.toml" "tls mux"
    run_go "$GO_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Go frps did not start"
        return
    }

    write_frpc_config rust "$frps_port" "$token" "$echo_port" "$proxy_port" "mux-tls-enc" "$TEST_DIR/$name/frpc.toml" "tls mux enc"
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

# =============================================================================
# Test: Go frpc -> Rust frps, UDP proxy
# =============================================================================
test_g2r_udp() {
    local name="go-to-rust-udp"
    should_run_test "$name" || return 0

    log "=== $name ==="
    local frps_port=$(random_port)
    local proxy_port=$(random_port)
    local echo_port=$(random_port)
    local token="test-token-g2r-udp"

    mkdir -p "$TEST_DIR/$name"

    # Start UDP echo server
    start_udp_echo_server "$echo_port"

    # Start Rust frps
    write_frps_config rust "$frps_port" "$token" "$TEST_DIR/$name/frps.toml" ""
    RUST_LOG=info "$RUST_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Rust frps did not start"
        return
    }

    # Start Go frpc with UDP proxy
    write_frpc_config_udp go "$frps_port" "$token" "$echo_port" "$proxy_port" "udp-echo" "$TEST_DIR/$name/frpc.toml" ""
    run_go "$GO_FRPC" -c "$TEST_DIR/$name/frpc.toml" \
        > "$TEST_DIR/$name/frpc.log" 2>&1 &
    track_pid $!

    # UDP proxy needs a moment for work connection assignment
    sleep 1

    # Test UDP data round-trip
    local result
    result=$(send_and_expect_udp "$proxy_port" "udp-test-data" 15)
    if [[ "$result" == "OK" ]]; then
        pass_test "$name"
    else
        fail_test "$name" "$result"
    fi
}

# =============================================================================
# Test: Rust frpc -> Go frps, UDP proxy
# =============================================================================
test_r2g_udp() {
    local name="rust-to-go-udp"
    should_run_test "$name" || return 0

    log "=== $name ==="
    local frps_port=$(random_port)
    local proxy_port=$(random_port)
    local echo_port=$(random_port)
    local token="test-token-r2g-udp"

    mkdir -p "$TEST_DIR/$name"

    # Start UDP echo server
    start_udp_echo_server "$echo_port"

    # Start Go frps
    write_frps_config go "$frps_port" "$token" "$TEST_DIR/$name/frps.toml" ""
    run_go "$GO_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Go frps did not start"
        return
    }

    # Start Rust frpc with UDP proxy
    write_frpc_config_udp rust "$frps_port" "$token" "$echo_port" "$proxy_port" "udp-echo" "$TEST_DIR/$name/frpc.toml" ""
    RUST_LOG=info "$RUST_FRPC" -c "$TEST_DIR/$name/frpc.toml" \
        > "$TEST_DIR/$name/frpc.log" 2>&1 &
    track_pid $!

    local result
    result=$(send_and_expect_udp "$proxy_port" "r2g-udp-test" 15)
    if [[ "$result" == "OK" ]]; then
        pass_test "$name"
    else
        fail_test "$name" "$result"
    fi
}

# =============================================================================
# Test: Go frpc -> Rust frps, HTTP proxy (VHost)
# =============================================================================
test_g2r_http() {
    local name="go-to-rust-http"
    should_run_test "$name" || return 0

    log "=== $name ==="
    local frps_port=$(random_port)
    local vhost_port=$(random_port)
    local echo_port=$(random_port)
    local token="test-token-g2r-http"

    mkdir -p "$TEST_DIR/$name"

    # Start simple HTTP echo server (returns request body)
    start_http_echo_server "$echo_port" "http-ok:"
    wait_for_port 127.0.0.1 "$echo_port" 3 || {
        fail_test "$name" "HTTP echo server did not start"
        return
    }

    # Start Rust frps with VHost HTTP port
    cat > "$TEST_DIR/$name/frps.toml" <<TOML
bind_addr = "127.0.0.1"
bind_port = $frps_port
vhost_http_port = $vhost_port
subdomain_host = "test.local"

[auth]
method = "token"
token = "$token"

[transport]
tcp_mux = false
TOML
    RUST_LOG=info "$RUST_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Rust frps did not start"
        return
    }
    wait_for_port_safe 127.0.0.1 "$vhost_port" 5 || {
        fail_test "$name" "VHost HTTP port $vhost_port not reachable"
        return
    }

    # Start Go frpc with HTTP proxy
    cat > "$TEST_DIR/$name/frpc.toml" <<TOML
serverAddr = "127.0.0.1"
serverPort = $frps_port
auth.token = "$token"
transport.tls.enable = false
transport.tcpMux = false
log.to = "$TEST_DIR/go-frpc-$name.log"
log.level = "debug"

[[proxies]]
name = "http-web"
type = "http"
localIP = "127.0.0.1"
localPort = $echo_port
customDomains = ["http-test.local"]
TOML
    run_go "$GO_FRPC" -c "$TEST_DIR/$name/frpc.toml" \
        > "$TEST_DIR/$name/frpc.log" 2>&1 &
    track_pid $!

    # sleep 3: wait for HTTP proxy registration + VHost routing propagation
    sleep 3

    # Send HTTP request through VHost
    local result
    result=$(send_http_test "$vhost_port" "http-test.local" "http-ok:" 5)
    if [[ "$result" == "OK" ]]; then
        pass_test "$name"
    else
        fail_test "$name" "$result"
    fi
}

# =============================================================================
# Test: Rust frpc -> Go frps, HTTP proxy (VHost)
# =============================================================================
test_r2g_http() {
    local name="rust-to-go-http"
    should_run_test "$name" || return 0

    log "=== $name ==="
    local frps_port=$(random_port)
    local vhost_port=$(random_port)
    local echo_port=$(random_port)
    local token="test-token-r2g-http"

    mkdir -p "$TEST_DIR/$name"

    # Start HTTP echo server
    start_http_echo_server "$echo_port" "http-ok:"
    wait_for_port 127.0.0.1 "$echo_port" 3 || {
        fail_test "$name" "HTTP echo server did not start"
        return
    }

    # Start Go frps with VHost
    cat > "$TEST_DIR/$name/frps.toml" <<TOML
bindAddr = "127.0.0.1"
bindPort = $frps_port
vhostHTTPPort = $vhost_port
subDomainHost = "test.local"
auth.method = "token"
auth.token = "$token"
transport.tcpMux = false
log.to = "$TEST_DIR/go-frps.log"
log.level = "debug"
TOML
    run_go "$GO_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Go frps did not start"
        return
    }
    wait_for_port_safe 127.0.0.1 "$vhost_port" 5 || {
        fail_test "$name" "VHost HTTP port $vhost_port not reachable"
        return
    }

    # Start Rust frpc with HTTP proxy
    cat > "$TEST_DIR/$name/frpc.toml" <<TOML
server_addr = "127.0.0.1"
server_port = $frps_port
token = "$token"
tcp_mux = false
tls_enable = false
login_fail_exit = true
pool_count = 1

[[proxies]]
name = "http-web"
type = "http"
local_ip = "127.0.0.1"
local_port = $echo_port
custom_domains = ["http-test.local"]
TOML
    RUST_LOG=info "$RUST_FRPC" -c "$TEST_DIR/$name/frpc.toml" \
        > "$TEST_DIR/$name/frpc.log" 2>&1 &
    track_pid $!

    # sleep 3: wait for HTTP proxy registration + VHost routing propagation
    sleep 3

    local result
    result=$(send_http_test "$vhost_port" "http-test.local" "http-ok:" 5)
    if [[ "$result" == "OK" ]]; then
        pass_test "$name"
    else
        fail_test "$name" "$result"
    fi
}

# =============================================================================
# Test: Go frpc -> Rust frps, HTTP proxy with basic auth
# =============================================================================
test_g2r_http_basic_auth() {
    local name="go-to-rust-http-basic-auth"
    should_run_test "$name" || return 0

    log "=== $name ==="
    local frps_port=$(random_port)
    local vhost_port=$(random_port)
    local echo_port=$(random_port)
    local token="test-token-g2r-http-auth"

    mkdir -p "$TEST_DIR/$name"

    # Start HTTP echo server
    start_http_echo_server "$echo_port" "http-auth-ok:"
    wait_for_port 127.0.0.1 "$echo_port" 3 || {
        fail_test "$name" "HTTP echo server did not start"
        return
    }

    # Start Rust frps with VHost HTTP port + subdomain_host
    cat > "$TEST_DIR/$name/frps.toml" <<TOML
bind_addr = "127.0.0.1"
bind_port = $frps_port
vhost_http_port = $vhost_port
subdomain_host = "test.local"

[auth]
method = "token"
token = "$token"

[transport]
tcp_mux = false
TOML
    RUST_LOG=info "$RUST_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Rust frps did not start"
        return
    }
    wait_for_port_safe 127.0.0.1 "$vhost_port" 5 || {
        fail_test "$name" "VHost HTTP port $vhost_port not reachable"
        return
    }

    # Start Go frpc with HTTP proxy + basic auth
    cat > "$TEST_DIR/$name/frpc.toml" <<TOML
serverAddr = "127.0.0.1"
serverPort = $frps_port
auth.token = "$token"
transport.tls.enable = false
transport.tcpMux = false
log.to = "$TEST_DIR/go-frpc-$name.log"
log.level = "debug"

[[proxies]]
name = "http-auth"
type = "http"
localIP = "127.0.0.1"
localPort = $echo_port
customDomains = ["auth-test.local"]
httpUser = "admin"
httpPassword = "s3cret"
TOML
    run_go "$GO_FRPC" -c "$TEST_DIR/$name/frpc.toml" \
        > "$TEST_DIR/$name/frpc.log" 2>&1 &
    track_pid $!

    sleep 3

    # Test 1: request WITHOUT auth → expect 401
    local unauth_result
    unauth_result=$(python3 -c "
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
s.connect(('127.0.0.1', $vhost_port))
s.sendall(b'GET / HTTP/1.1\r\nHost: auth-test.local\r\nConnection: close\r\n\r\n')
resp = s.recv(4096).decode()
s.close()
if '401' in resp or 'Unauthorized' in resp or 'unauthorized' in resp.lower():
    print('OK')
else:
    print('FAIL: expected 401, got: ' + resp[:200])
" 2>&1)
    if [[ "$unauth_result" != "OK" ]]; then
        fail_test "$name" "unauth: $unauth_result"
        return
    fi

    # Test 2: request WITH auth → expect 200
    local auth_result
    auth_result=$(python3 -c "
import socket, sys
from base64 import b64encode
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
s.connect(('127.0.0.1', $vhost_port))
auth = b64encode(b'admin:s3cret').decode()
s.sendall(f'GET / HTTP/1.1\r\nHost: auth-test.local\r\nAuthorization: Basic {auth}\r\nConnection: close\r\n\r\n'.encode())
resp = s.recv(4096).decode()
s.close()
if '200 OK' in resp:
    print('OK')
else:
    print('FAIL: expected 200, got: ' + resp[:200])
" 2>&1)
    if [[ "$auth_result" == "OK" ]]; then
        pass_test "$name"
    else
        fail_test "$name" "auth: $auth_result"
    fi
}

# =============================================================================
# Test: Go frpc -> Rust frps, HTTP proxy with host header rewrite
# =============================================================================
test_g2r_http_host_header_rewrite() {
    local name="go-to-rust-http-host-header-rewrite"
    should_run_test "$name" || return 0

    log "=== $name ==="
    local frps_port=$(random_port)
    local vhost_port=$(random_port)
    local echo_port=$(random_port)
    local token="test-token-g2r-http-rewrite"

    mkdir -p "$TEST_DIR/$name"

    # Start HTTP echo server
    start_http_echo_server "$echo_port" "http-rewrite-ok:"
    wait_for_port 127.0.0.1 "$echo_port" 3 || {
        fail_test "$name" "HTTP echo server did not start"
        return
    }

    # Start Rust frps with VHost HTTP port
    cat > "$TEST_DIR/$name/frps.toml" <<TOML
bind_addr = "127.0.0.1"
bind_port = $frps_port
vhost_http_port = $vhost_port

[auth]
method = "token"
token = "$token"

[transport]
tcp_mux = false
TOML
    RUST_LOG=info "$RUST_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Rust frps did not start"
        return
    }
    wait_for_port_safe 127.0.0.1 "$vhost_port" 5 || {
        fail_test "$name" "VHost HTTP port $vhost_port not reachable"
        return
    }

    # Start Go frpc with HTTP proxy + host header rewrite
    cat > "$TEST_DIR/$name/frpc.toml" <<TOML
serverAddr = "127.0.0.1"
serverPort = $frps_port
auth.token = "$token"
transport.tls.enable = false
transport.tcpMux = false
log.to = "$TEST_DIR/go-frpc-$name.log"
log.level = "debug"

[[proxies]]
name = "http-rewrite"
type = "http"
localIP = "127.0.0.1"
localPort = $echo_port
customDomains = ["rewrite-test.local"]
hostHeaderRewrite = "backend.internal"
TOML
    run_go "$GO_FRPC" -c "$TEST_DIR/$name/frpc.toml" \
        > "$TEST_DIR/$name/frpc.log" 2>&1 &
    track_pid $!

    sleep 3

    # Send HTTP request; the proxy rewrites Host → backend.internal before
    # forwarding. The echo server returns 200 OK regardless. This test
    # validates that the Go frpc→Rust frps HTTP path works with
    # hostHeaderRewrite in the proxy config.
    local result
    result=$(send_http_test "$vhost_port" "rewrite-test.local" "http-rewrite-ok:" 5)
    if [[ "$result" == "OK" ]]; then
        pass_test "$name"
    else
        fail_test "$name" "$result"
    fi
}

# =============================================================================
# Test: Go frpc -> Rust frps, HTTP proxy with subdomain routing
# =============================================================================
test_g2r_http_subdomain() {
    local name="go-to-rust-http-subdomain"
    should_run_test "$name" || return 0

    log "=== $name ==="
    local frps_port=$(random_port)
    local vhost_port=$(random_port)
    local echo_port=$(random_port)
    local token="test-token-g2r-http-subdomain"

    mkdir -p "$TEST_DIR/$name"

    # Start HTTP echo server
    start_http_echo_server "$echo_port" "http-subdomain-ok:"
    wait_for_port 127.0.0.1 "$echo_port" 3 || {
        fail_test "$name" "HTTP echo server did not start"
        return
    }

    # Start Rust frps with VHost HTTP port + subdomain_host
    cat > "$TEST_DIR/$name/frps.toml" <<TOML
bind_addr = "127.0.0.1"
bind_port = $frps_port
vhost_http_port = $vhost_port
subdomain_host = "test.local"

[auth]
method = "token"
token = "$token"

[transport]
tcp_mux = false
TOML
    RUST_LOG=info "$RUST_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Rust frps did not start"
        return
    }
    wait_for_port_safe 127.0.0.1 "$vhost_port" 5 || {
        fail_test "$name" "VHost HTTP port $vhost_port not reachable"
        return
    }

    # Start Go frpc with HTTP proxy using subdomain (NOT customDomains)
    cat > "$TEST_DIR/$name/frpc.toml" <<TOML
serverAddr = "127.0.0.1"
serverPort = $frps_port
auth.token = "$token"
transport.tls.enable = false
transport.tcpMux = false
log.to = "$TEST_DIR/go-frpc-$name.log"
log.level = "debug"

[[proxies]]
name = "http-sub"
type = "http"
localIP = "127.0.0.1"
localPort = $echo_port
subdomain = "mysub"
TOML
    run_go "$GO_FRPC" -c "$TEST_DIR/$name/frpc.toml" \
        > "$TEST_DIR/$name/frpc.log" 2>&1 &
    track_pid $!

    sleep 3

    # Send HTTP request with Host: mysub.test.local (subdomain + subdomain_host)
    local result
    result=$(send_http_test "$vhost_port" "mysub.test.local" "http-subdomain-ok:" 5)
    if [[ "$result" == "OK" ]]; then
        pass_test "$name"
    else
        fail_test "$name" "$result"
    fi
}

# =============================================================================
# Test: Go frpc -> Rust frps, HTTP proxy with response headers
# =============================================================================
test_g2r_http_response_headers() {
    local name="go-to-rust-http-response-headers"
    should_run_test "$name" || return 0

    log "=== $name ==="
    local frps_port=$(random_port)
    local vhost_port=$(random_port)
    local echo_port=$(random_port)
    local token="test-token-g2r-http-headers"

    mkdir -p "$TEST_DIR/$name"

    # Start HTTP echo server
    start_http_echo_server "$echo_port" "http-headers-ok:"
    wait_for_port 127.0.0.1 "$echo_port" 3 || {
        fail_test "$name" "HTTP echo server did not start"
        return
    }

    # Start Rust frps with VHost HTTP port
    cat > "$TEST_DIR/$name/frps.toml" <<TOML
bind_addr = "127.0.0.1"
bind_port = $frps_port
vhost_http_port = $vhost_port
subdomain_host = "test.local"

[auth]
method = "token"
token = "$token"

[transport]
tcp_mux = false
TOML
    RUST_LOG=info "$RUST_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Rust frps did not start"
        return
    }
    wait_for_port_safe 127.0.0.1 "$vhost_port" 5 || {
        fail_test "$name" "VHost HTTP port $vhost_port not reachable"
        return
    }

    # Start Go frpc with HTTP proxy + responseHeaders.set
    cat > "$TEST_DIR/$name/frpc.toml" <<TOML
serverAddr = "127.0.0.1"
serverPort = $frps_port
auth.token = "$token"
transport.tls.enable = false
transport.tcpMux = false
log.to = "$TEST_DIR/go-frpc-$name.log"
log.level = "debug"

[[proxies]]
name = "http-headers"
type = "http"
localIP = "127.0.0.1"
localPort = $echo_port
customDomains = ["headers-test.local"]

[proxies.responseHeaders.set]
X-Frame-Options = "DENY"
TOML
    run_go "$GO_FRPC" -c "$TEST_DIR/$name/frpc.toml" \
        > "$TEST_DIR/$name/frpc.log" 2>&1 &
    track_pid $!

    sleep 3

    # Send HTTP request and verify X-Frame-Options: DENY header is present
    local result
    result=$(python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
s.connect(('127.0.0.1', $vhost_port))
req = b'POST /test HTTP/1.1\r\nHost: headers-test.local\r\nContent-Length: 5\r\n\r\nhello'
s.sendall(req)
resp = b''
while True:
    chunk = s.recv(4096)
    if not chunk:
        break
    resp += chunk
    if b'\r\n\r\n' in resp:
        hdr_end = resp.index(b'\r\n\r\n') + 4
        hdrs_text = resp[:hdr_end].decode('utf-8', errors='ignore')
        cl = 0
        for line in hdrs_text.split('\r\n'):
            if line.lower().startswith('content-length:'):
                try: cl = int(line.split(':')[1].strip())
                except: pass
        if len(resp) - hdr_end >= cl:
            break
s.close()
if b'HTTP/1.1 200 OK' in resp and b'X-Frame-Options: DENY' in resp:
    print('OK')
else:
    print('FAIL: response=' + repr(resp[:500]))
" 2>&1)
    if [[ "$result" == "OK" ]]; then
        pass_test "$name"
    else
        fail_test "$name" "$result"
    fi
}

# =============================================================================
# Test: Rust frpc -> Go frps, HTTP proxy with response headers
# =============================================================================
test_r2g_http_response_headers() {
    local name="rust-to-go-http-response-headers"
    should_run_test "$name" || return 0

    log "=== $name ==="
    local frps_port=$(random_port)
    local vhost_port=$(random_port)
    local echo_port=$(random_port)
    local token="test-token-r2g-http-headers"

    mkdir -p "$TEST_DIR/$name"

    # Start HTTP echo server
    start_http_echo_server "$echo_port" "http-headers-ok:"
    wait_for_port 127.0.0.1 "$echo_port" 3 || {
        fail_test "$name" "HTTP echo server did not start"
        return
    }

    # Start Go frps with VHost HTTP port
    cat > "$TEST_DIR/$name/frps.toml" <<TOML
bindAddr = "127.0.0.1"
bindPort = $frps_port
vhostHTTPPort = $vhost_port
subDomainHost = "test.local"
auth.method = "token"
auth.token = "$token"
transport.tcpMux = false
log.to = "$TEST_DIR/go-frps.log"
log.level = "debug"
TOML
    run_go "$GO_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Go frps did not start"
        return
    }
    wait_for_port_safe 127.0.0.1 "$vhost_port" 5 || {
        fail_test "$name" "VHost HTTP port $vhost_port not reachable"
        return
    }

    # Start Rust frpc with HTTP proxy + response_headers
    cat > "$TEST_DIR/$name/frpc.toml" <<TOML
server_addr = "127.0.0.1"
server_port = $frps_port
token = "$token"
tcp_mux = false
tls_enable = false
login_fail_exit = true
pool_count = 1

[[proxies]]
name = "http-headers"
type = "http"
local_ip = "127.0.0.1"
local_port = $echo_port
custom_domains = ["headers-test.local"]
response_headers = { "X-Frame-Options" = "DENY" }
TOML
    RUST_LOG=info "$RUST_FRPC" -c "$TEST_DIR/$name/frpc.toml" \
        > "$TEST_DIR/$name/frpc.log" 2>&1 &
    track_pid $!

    sleep 3

    # Send HTTP request and verify X-Frame-Options: DENY header is present
    local result
    result=$(python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
s.connect(('127.0.0.1', $vhost_port))
req = b'POST /test HTTP/1.1\r\nHost: headers-test.local\r\nContent-Length: 5\r\n\r\nhello'
s.sendall(req)
resp = b''
while True:
    chunk = s.recv(4096)
    if not chunk:
        break
    resp += chunk
    if b'\r\n\r\n' in resp:
        hdr_end = resp.index(b'\r\n\r\n') + 4
        hdrs_text = resp[:hdr_end].decode('utf-8', errors='ignore')
        cl = 0
        for line in hdrs_text.split('\r\n'):
            if line.lower().startswith('content-length:'):
                try: cl = int(line.split(':')[1].strip())
                except: pass
        if len(resp) - hdr_end >= cl:
            break
s.close()
if b'HTTP/1.1 200 OK' in resp and b'X-Frame-Options: DENY' in resp:
    print('OK')
else:
    print('FAIL: response=' + repr(resp[:500]))
" 2>&1)
    if [[ "$result" == "OK" ]]; then
        pass_test "$name"
    else
        fail_test "$name" "$result"
    fi
}

# =============================================================================
# Test: Go frpc -> Rust frps, HTTP proxy with locations
# =============================================================================
test_g2r_http_locations() {
    local name="go-to-rust-http-locations"
    should_run_test "$name" || return 0

    log "=== $name ==="
    local frps_port=$(random_port)
    local vhost_port=$(random_port)
    local echo_port=$(random_port)
    local token="test-token-g2r-http-locations"

    mkdir -p "$TEST_DIR/$name"

    # Start HTTP echo server
    start_http_echo_server "$echo_port" "http-loc-ok:"
    wait_for_port 127.0.0.1 "$echo_port" 3 || {
        fail_test "$name" "HTTP echo server did not start"
        return
    }

    # Start Rust frps with VHost HTTP port
    cat > "$TEST_DIR/$name/frps.toml" <<TOML
bind_addr = "127.0.0.1"
bind_port = $frps_port
vhost_http_port = $vhost_port
subdomain_host = "test.local"

[auth]
method = "token"
token = "$token"

[transport]
tcp_mux = false
TOML
    RUST_LOG=info "$RUST_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Rust frps did not start"
        return
    }
    wait_for_port_safe 127.0.0.1 "$vhost_port" 5 || {
        fail_test "$name" "VHost HTTP port $vhost_port not reachable"
        return
    }

    # Start Go frpc with HTTP proxy + locations
    cat > "$TEST_DIR/$name/frpc.toml" <<TOML
serverAddr = "127.0.0.1"
serverPort = $frps_port
auth.token = "$token"
transport.tls.enable = false
transport.tcpMux = false
log.to = "$TEST_DIR/go-frpc-$name.log"
log.level = "debug"

[[proxies]]
name = "http-loc"
type = "http"
localIP = "127.0.0.1"
localPort = $echo_port
customDomains = ["loc-test.local"]
locations = ["/api", "/health"]
TOML
    run_go "$GO_FRPC" -c "$TEST_DIR/$name/frpc.toml" \
        > "$TEST_DIR/$name/frpc.log" 2>&1 &
    track_pid $!

    sleep 3

    # Test 1: /api path should succeed
    local api_result
    api_result=$(python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
s.connect(('127.0.0.1', $vhost_port))
req = b'POST /api HTTP/1.1\r\nHost: loc-test.local\r\nContent-Length: 5\r\n\r\nhello'
s.sendall(req)
resp = s.recv(4096)
s.close()
if b'200 OK' in resp:
    print('OK')
else:
    print('FAIL: ' + repr(resp[:200]))
" 2>&1)
    if [[ "$api_result" != "OK" ]]; then
        fail_test "$name" "/api: $api_result"
        return
    fi

    # Test 2: /health path should succeed
    local health_result
    health_result=$(python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
s.connect(('127.0.0.1', $vhost_port))
req = b'POST /health HTTP/1.1\r\nHost: loc-test.local\r\nContent-Length: 5\r\n\r\nhello'
s.sendall(req)
resp = s.recv(4096)
s.close()
if b'200 OK' in resp:
    print('OK')
else:
    print('FAIL: ' + repr(resp[:200]))
" 2>&1)
    if [[ "$health_result" != "OK" ]]; then
        fail_test "$name" "/health: $health_result"
        return
    fi

    # Test 3: /other path should NOT reach the backend (404 or connection close)
    local other_result
    other_result=$(python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
s.connect(('127.0.0.1', $vhost_port))
req = b'POST /other HTTP/1.1\r\nHost: loc-test.local\r\nContent-Length: 5\r\n\r\nhello'
s.sendall(req)
resp = b''
while True:
    try:
        chunk = s.recv(4096)
        if not chunk:
            break
        resp += chunk
    except:
        break
s.close()
if b'200' in resp and b'http-loc-ok' in resp:
    print('FAIL: /other unexpectedly reached backend')
elif b'404' in resp or b'Not Found' in resp or len(resp) == 0:
    print('OK')
else:
    print('OK: unexpected response but no backend echo=' + repr(resp[:200]))
" 2>&1)
    if [[ "$other_result" != OK* ]]; then
        fail_test "$name" "/other: $other_result"
        return
    fi

    pass_test "$name"
}

# =============================================================================
# Test: Rust frpc -> Go frps, HTTP proxy with locations
# =============================================================================
test_r2g_http_locations() {
    local name="rust-to-go-http-locations"
    should_run_test "$name" || return 0

    log "=== $name ==="
    local frps_port=$(random_port)
    local vhost_port=$(random_port)
    local echo_port=$(random_port)
    local token="test-token-r2g-http-locations"

    mkdir -p "$TEST_DIR/$name"

    # Start HTTP echo server
    start_http_echo_server "$echo_port" "http-loc-ok:"
    wait_for_port 127.0.0.1 "$echo_port" 3 || {
        fail_test "$name" "HTTP echo server did not start"
        return
    }

    # Start Go frps with VHost HTTP port
    cat > "$TEST_DIR/$name/frps.toml" <<TOML
bindAddr = "127.0.0.1"
bindPort = $frps_port
vhostHTTPPort = $vhost_port
subDomainHost = "test.local"
auth.method = "token"
auth.token = "$token"
transport.tcpMux = false
log.to = "$TEST_DIR/go-frps.log"
log.level = "debug"
TOML
    run_go "$GO_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Go frps did not start"
        return
    }
    wait_for_port_safe 127.0.0.1 "$vhost_port" 5 || {
        fail_test "$name" "VHost HTTP port $vhost_port not reachable"
        return
    }

    # Start Rust frpc with HTTP proxy + locations
    cat > "$TEST_DIR/$name/frpc.toml" <<TOML
server_addr = "127.0.0.1"
server_port = $frps_port
token = "$token"
tcp_mux = false
tls_enable = false
login_fail_exit = true
pool_count = 1

[[proxies]]
name = "http-loc"
type = "http"
local_ip = "127.0.0.1"
local_port = $echo_port
custom_domains = ["loc-test.local"]
locations = ["/api", "/health"]
TOML
    RUST_LOG=info "$RUST_FRPC" -c "$TEST_DIR/$name/frpc.toml" \
        > "$TEST_DIR/$name/frpc.log" 2>&1 &
    track_pid $!

    sleep 3

    # Test 1: /api path should succeed
    local api_result
    api_result=$(python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
s.connect(('127.0.0.1', $vhost_port))
req = b'POST /api HTTP/1.1\r\nHost: loc-test.local\r\nContent-Length: 5\r\n\r\nhello'
s.sendall(req)
resp = s.recv(4096)
s.close()
if b'200 OK' in resp:
    print('OK')
else:
    print('FAIL: ' + repr(resp[:200]))
" 2>&1)
    if [[ "$api_result" != "OK" ]]; then
        fail_test "$name" "/api: $api_result"
        return
    fi

    # Test 2: /health path should succeed
    local health_result
    health_result=$(python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
s.connect(('127.0.0.1', $vhost_port))
req = b'POST /health HTTP/1.1\r\nHost: loc-test.local\r\nContent-Length: 5\r\n\r\nhello'
s.sendall(req)
resp = s.recv(4096)
s.close()
if b'200 OK' in resp:
    print('OK')
else:
    print('FAIL: ' + repr(resp[:200]))
" 2>&1)
    if [[ "$health_result" != "OK" ]]; then
        fail_test "$name" "/health: $health_result"
        return
    fi

    # Test 3: /other path should NOT reach the backend (404 or connection close)
    local other_result
    other_result=$(python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
s.connect(('127.0.0.1', $vhost_port))
req = b'POST /other HTTP/1.1\r\nHost: loc-test.local\r\nContent-Length: 5\r\n\r\nhello'
s.sendall(req)
resp = b''
while True:
    try:
        chunk = s.recv(4096)
        if not chunk:
            break
        resp += chunk
    except:
        break
s.close()
if b'200' in resp and b'http-loc-ok' in resp:
    print('FAIL: /other unexpectedly reached backend')
elif b'404' in resp or b'Not Found' in resp or len(resp) == 0:
    print('OK')
else:
    print('OK: unexpected response but no backend echo=' + repr(resp[:200]))
" 2>&1)
    if [[ "$other_result" != OK* ]]; then
        fail_test "$name" "/other: $other_result"
        return
    fi

    pass_test "$name"
}

# =============================================================================
# Test: Go frpc -> Rust frps, HTTP proxy with route_by_http_user
# =============================================================================
test_g2r_route_by_http_user() {
    local name="go-to-rust-route-by-http-user"
    should_run_test "$name" || return 0

    log "=== $name ==="
    local frps_port=$(random_port)
    local vhost_port=$(random_port)
    local echo1_port=$(random_port)
    local echo2_port=$(random_port)
    local echo3_port=$(random_port)
    local token="test-token-g2r-rubu"

    mkdir -p "$TEST_DIR/$name"

    # Start 3 HTTP echo servers with different prefixes
    start_http_echo_server "$echo1_port" "user1-ok:"
    wait_for_port 127.0.0.1 "$echo1_port" 3 || { fail_test "$name" "echo1 did not start"; return; }
    start_http_echo_server "$echo2_port" "user2-ok:"
    wait_for_port 127.0.0.1 "$echo2_port" 3 || { fail_test "$name" "echo2 did not start"; return; }
    start_http_echo_server "$echo3_port" "catchall-ok:"
    wait_for_port 127.0.0.1 "$echo3_port" 3 || { fail_test "$name" "echo3 did not start"; return; }

    # Start Rust frps with VHost HTTP port
    cat > "$TEST_DIR/$name/frps.toml" <<TOML
bind_addr = "127.0.0.1"
bind_port = $frps_port
vhost_http_port = $vhost_port
subdomain_host = "test.local"

[auth]
method = "token"
token = "$token"

[transport]
tcp_mux = false
TOML
    RUST_LOG=info "$RUST_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || { fail_test "$name" "Rust frps did not start"; return; }
    wait_for_port_safe 127.0.0.1 "$vhost_port" 5 || { fail_test "$name" "VHost HTTP port $vhost_port not reachable"; return; }

    # Start Go frpc with 3 HTTP proxies on the same domain, differentiated by routeByHTTPUser
    cat > "$TEST_DIR/$name/frpc.toml" <<TOML
serverAddr = "127.0.0.1"
serverPort = $frps_port
auth.token = "$token"
transport.tls.enable = false
transport.tcpMux = false
log.to = "$TEST_DIR/go-frpc-$name.log"
log.level = "debug"

[[proxies]]
name = "rubu-user1"
type = "http"
localIP = "127.0.0.1"
localPort = $echo1_port
customDomains = ["rubu.local"]
routeByHTTPUser = "user1"

[[proxies]]
name = "rubu-user2"
type = "http"
localIP = "127.0.0.1"
localPort = $echo2_port
customDomains = ["rubu.local"]
routeByHTTPUser = "user2"

[[proxies]]
name = "rubu-catchall"
type = "http"
localIP = "127.0.0.1"
localPort = $echo3_port
customDomains = ["rubu.local"]
TOML
    run_go "$GO_FRPC" -c "$TEST_DIR/$name/frpc.toml" \
        > "$TEST_DIR/$name/frpc.log" 2>&1 &
    track_pid $!

    sleep 3

    # Helper: send HTTP request with optional Basic auth
    send_auth_req() {
        local label="$1" user="$2" pass="$3" expected_prefix="$4"
        local result
        result=$(python3 -c "
import socket, base64
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
s.connect(('127.0.0.1', $vhost_port))
req = b'GET / HTTP/1.1\r\nHost: rubu.local\r\n'
if '$user':
    creds = base64.b64encode(('$user:$pass').encode()).decode()
    req += b'Authorization: Basic ' + creds.encode() + b'\r\n'
req += b'Connection: close\r\n\r\n'
s.sendall(req)
resp = s.recv(4096)
s.close()
expected = b'${expected_prefix}'
if expected in resp:
    print('OK')
else:
    print('FAIL: ' + repr(resp[:200]))
" 2>&1)
        if [[ "$result" != "OK" ]]; then
            fail_test "$name" "$label: $result"
            return 1
        fi
        log "  $name: $label OK"
        return 0
    }

    # Test 1: user1/auth → proxy rubu-user1 (echo1)
    send_auth_req "user1" "user1" "pass1" "user1-ok:" || return

    # Test 2: user2/auth → proxy rubu-user2 (echo2)
    send_auth_req "user2" "user2" "pass2" "user2-ok:" || return

    # Test 3: no auth → proxy rubu-catchall (echo3)
    send_auth_req "no-auth" "" "" "catchall-ok:" || return

    pass_test "$name"
}

# =============================================================================
# Test: Rust frpc -> Go frps, HTTP proxy with route_by_http_user
# =============================================================================
test_r2g_route_by_http_user() {
    local name="rust-to-go-route-by-http-user"
    should_run_test "$name" || return 0

    log "=== $name ==="
    local frps_port=$(random_port)
    local vhost_port=$(random_port)
    local echo1_port=$(random_port)
    local echo2_port=$(random_port)
    local echo3_port=$(random_port)
    local token="test-token-r2g-rubu"

    mkdir -p "$TEST_DIR/$name"

    # Start 3 HTTP echo servers with different prefixes
    start_http_echo_server "$echo1_port" "user1-ok:"
    wait_for_port 127.0.0.1 "$echo1_port" 3 || { fail_test "$name" "echo1 did not start"; return; }
    start_http_echo_server "$echo2_port" "user2-ok:"
    wait_for_port 127.0.0.1 "$echo2_port" 3 || { fail_test "$name" "echo2 did not start"; return; }
    start_http_echo_server "$echo3_port" "catchall-ok:"
    wait_for_port 127.0.0.1 "$echo3_port" 3 || { fail_test "$name" "echo3 did not start"; return; }

    # Start Go frps with VHost HTTP port
    cat > "$TEST_DIR/$name/frps.toml" <<TOML
bindAddr = "127.0.0.1"
bindPort = $frps_port
vhostHTTPPort = $vhost_port
subDomainHost = "test.local"
auth.method = "token"
auth.token = "$token"
transport.tcpMux = false
log.to = "$TEST_DIR/go-frps.log"
log.level = "debug"
TOML
    run_go "$GO_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || { fail_test "$name" "Go frps did not start"; return; }
    wait_for_port_safe 127.0.0.1 "$vhost_port" 5 || { fail_test "$name" "VHost HTTP port $vhost_port not reachable"; return; }

    # Start Rust frpc with 3 HTTP proxies on the same domain, differentiated by route_by_http_user
    cat > "$TEST_DIR/$name/frpc.toml" <<TOML
server_addr = "127.0.0.1"
server_port = $frps_port
token = "$token"
tcp_mux = false
tls_enable = false
login_fail_exit = true
pool_count = 1

[[proxies]]
name = "rubu-user1"
type = "http"
local_ip = "127.0.0.1"
local_port = $echo1_port
custom_domains = ["rubu.local"]
route_by_http_user = "user1"

[[proxies]]
name = "rubu-user2"
type = "http"
local_ip = "127.0.0.1"
local_port = $echo2_port
custom_domains = ["rubu.local"]
route_by_http_user = "user2"

[[proxies]]
name = "rubu-catchall"
type = "http"
local_ip = "127.0.0.1"
local_port = $echo3_port
custom_domains = ["rubu.local"]
TOML
    RUST_LOG=info "$RUST_FRPC" -c "$TEST_DIR/$name/frpc.toml" \
        > "$TEST_DIR/$name/frpc.log" 2>&1 &
    track_pid $!

    sleep 3

    # Same helper as g2r test
    send_auth_req() {
        local label="$1" user="$2" pass="$3" expected_prefix="$4"
        local result
        result=$(python3 -c "
import socket, base64
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
s.connect(('127.0.0.1', $vhost_port))
req = b'GET / HTTP/1.1\r\nHost: rubu.local\r\n'
if '$user':
    creds = base64.b64encode(('$user:$pass').encode()).decode()
    req += b'Authorization: Basic ' + creds.encode() + b'\r\n'
req += b'Connection: close\r\n\r\n'
s.sendall(req)
resp = s.recv(4096)
s.close()
expected = b'${expected_prefix}'
if expected in resp:
    print('OK')
else:
    print('FAIL: ' + repr(resp[:200]))
" 2>&1)
        if [[ "$result" != "OK" ]]; then
            fail_test "$name" "$label: $result"
            return 1
        fi
        log "  $name: $label OK"
        return 0
    }

    # Test 1: user1/auth → proxy rubu-user1 (echo1)
    send_auth_req "user1" "user1" "pass1" "user1-ok:" || return

    # Test 2: user2/auth → proxy rubu-user2 (echo2)
    send_auth_req "user2" "user2" "pass2" "user2-ok:" || return

    # Test 3: no auth → proxy rubu-catchall (echo3)
    send_auth_req "no-auth" "" "" "catchall-ok:" || return

    pass_test "$name"
}

# =============================================================================
# Test: Go frpc -> Rust frps, STCP relay
# =============================================================================
test_g2r_stcp() {
    local name="go-to-rust-stcp"
    should_run_test "$name" || return 0

    log "=== $name ==="
    local frps_port=$(random_port)
    local echo_port=$(random_port)
    local visitor_port=$(random_port)
    local token="test-token-g2r-stcp"
    local sk="stcp-secret-key-42"

    mkdir -p "$TEST_DIR/$name"

    start_echo_server "$echo_port"
    wait_for_port 127.0.0.1 "$echo_port" 3 || {
        fail_test "$name" "echo server did not start"
        return
    }

    # Start Rust frps
    write_frps_config rust "$frps_port" "$token" "$TEST_DIR/$name/frps.toml" ""
    RUST_LOG=debug "$RUST_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Rust frps did not start"
        return
    }

    # Start Go frpc provider (stcp proxy)
    cat > "$TEST_DIR/$name/frpc-provider.toml" <<TOML
serverAddr = "127.0.0.1"
serverPort = $frps_port
auth.token = "$token"
transport.tls.enable = false
transport.tcpMux = false
log.to = "$TEST_DIR/go-frpc-provider-$name.log"
log.level = "debug"

[[proxies]]
name = "stcp-svc"
type = "stcp"
secretKey = "$sk"
localIP = "127.0.0.1"
localPort = $echo_port
TOML
    run_go "$GO_FRPC" -c "$TEST_DIR/$name/frpc-provider.toml" \
        > "$TEST_DIR/$name/frpc-provider.log" 2>&1 &
    track_pid $!

    # Start Go frpc visitor (stcp visitor)
    cat > "$TEST_DIR/$name/frpc-visitor.toml" <<TOML
serverAddr = "127.0.0.1"
serverPort = $frps_port
auth.token = "$token"
transport.tls.enable = false
transport.tcpMux = false
log.to = "$TEST_DIR/go-frpc-visitor-$name.log"
log.level = "debug"

[[visitors]]
name = "stcp-visitor"
type = "stcp"
serverName = "stcp-svc"
secretKey = "$sk"
bindAddr = "127.0.0.1"
bindPort = $visitor_port
TOML
    run_go "$GO_FRPC" -c "$TEST_DIR/$name/frpc-visitor.toml" \
        > "$TEST_DIR/$name/frpc-visitor.log" 2>&1 &
    track_pid $!

    if ! wait_for_port_safe 127.0.0.1 "$visitor_port" 15; then
        fail_test "$name" "visitor port $visitor_port not reachable"
        return
    fi

    local result
    result=$(send_and_expect "$visitor_port" "stcp-data-test" "stcp-data-test" 5)
    if [[ "$result" == OK:* ]]; then
        pass_test "$name"
    else
        fail_test "$name" "$result"
    fi
}

# =============================================================================
# Test: Rust frpc -> Go frps, STCP relay
# =============================================================================
test_r2g_stcp() {
    local name="rust-to-go-stcp"
    should_run_test "$name" || return 0

    log "=== $name ==="
    local frps_port=$(random_port)
    local echo_port=$(random_port)
    local visitor_port=$(random_port)
    local token="test-token-r2g-stcp"
    local sk="stcp-secret-key-43"

    mkdir -p "$TEST_DIR/$name"

    start_echo_server "$echo_port"
    wait_for_port 127.0.0.1 "$echo_port" 3 || {
        fail_test "$name" "echo server did not start"
        return
    }

    # Start Go frps
    write_frps_config go "$frps_port" "$token" "$TEST_DIR/$name/frps.toml" ""
    run_go "$GO_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Go frps did not start"
        return
    }

    # Start Rust frpc provider (STCP)
    cat > "$TEST_DIR/$name/frpc-provider.toml" <<TOML
server_addr = "127.0.0.1"
server_port = $frps_port
token = "$token"
tcp_mux = false
tls_enable = false
login_fail_exit = true
pool_count = 1

[[proxies]]
name = "stcp-svc"
type = "stcp"
local_ip = "127.0.0.1"
local_port = $echo_port
sk = "$sk"
TOML
    RUST_LOG=debug "$RUST_FRPC" -c "$TEST_DIR/$name/frpc-provider.toml" \
        > "$TEST_DIR/$name/frpc-provider.log" 2>&1 &
    track_pid $!

    # Start Rust frpc visitor (STCP visitor)
    cat > "$TEST_DIR/$name/frpc-visitor.toml" <<TOML
server_addr = "127.0.0.1"
server_port = $frps_port
token = "$token"
tcp_mux = false
tls_enable = false
login_fail_exit = true
pool_count = 1

[[visitors]]
name = "stcp-visitor"
type = "stcp"
server_name = "stcp-svc"
sk = "$sk"
bind_addr = "127.0.0.1"
bind_port = $visitor_port
TOML
    RUST_LOG=debug "$RUST_FRPC" -c "$TEST_DIR/$name/frpc-visitor.toml" \
        > "$TEST_DIR/$name/frpc-visitor.log" 2>&1 &
    track_pid $!

    if ! wait_for_port_safe 127.0.0.1 "$visitor_port" 15; then
        fail_test "$name" "visitor port $visitor_port not reachable"
        return
    fi

    local result
    result=$(send_and_expect "$visitor_port" "r2g-stcp-data" "r2g-stcp-data" 5)
    if [[ "$result" == OK:* ]]; then
        pass_test "$name"
    else
        fail_test "$name" "$result"
    fi
}

# =============================================================================
# Test: Go frpc -> Rust frps, STCP relay + encryption
# =============================================================================
test_g2r_stcp_encrypted() {
    local name="go-to-rust-stcp-encrypted"
    should_run_test "$name" || return 0

    log "=== $name ==="
    local frps_port=$(random_port)
    local echo_port=$(random_port)
    local visitor_port=$(random_port)
    local token="test-token-g2r-stcp-enc"
    local sk="stcp-secret-key-enc-42"

    mkdir -p "$TEST_DIR/$name"

    start_echo_server "$echo_port"
    wait_for_port 127.0.0.1 "$echo_port" 3 || {
        fail_test "$name" "echo server did not start"
        return
    }

    # Start Rust frps
    write_frps_config rust "$frps_port" "$token" "$TEST_DIR/$name/frps.toml" ""
    RUST_LOG=debug "$RUST_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Rust frps did not start"
        return
    }

    # Start Go frpc provider (stcp proxy, encrypted)
    cat > "$TEST_DIR/$name/frpc-provider.toml" <<TOML
serverAddr = "127.0.0.1"
serverPort = $frps_port
auth.token = "$token"
transport.tls.enable = false
transport.tcpMux = false
log.to = "$TEST_DIR/go-frpc-provider-$name.log"
log.level = "debug"

[[proxies]]
name = "stcp-svc-enc"
type = "stcp"
secretKey = "$sk"
localIP = "127.0.0.1"
localPort = $echo_port
transport.useEncryption = true
TOML
    run_go "$GO_FRPC" -c "$TEST_DIR/$name/frpc-provider.toml" \
        > "$TEST_DIR/$name/frpc-provider.log" 2>&1 &
    track_pid $!

    # Start Go frpc visitor (stcp visitor)
    cat > "$TEST_DIR/$name/frpc-visitor.toml" <<TOML
serverAddr = "127.0.0.1"
serverPort = $frps_port
auth.token = "$token"
transport.tls.enable = false
transport.tcpMux = false
log.to = "$TEST_DIR/go-frpc-visitor-$name.log"
log.level = "debug"

[[visitors]]
name = "stcp-visitor-enc"
type = "stcp"
serverName = "stcp-svc-enc"
secretKey = "$sk"
bindAddr = "127.0.0.1"
bindPort = $visitor_port
TOML
    run_go "$GO_FRPC" -c "$TEST_DIR/$name/frpc-visitor.toml" \
        > "$TEST_DIR/$name/frpc-visitor.log" 2>&1 &
    track_pid $!

    if ! wait_for_port_safe 127.0.0.1 "$visitor_port" 15; then
        fail_test "$name" "visitor port $visitor_port not reachable"
        return
    fi

    local result
    result=$(send_and_expect "$visitor_port" "stcp-enc-data" "stcp-enc-data" 5)
    if [[ "$result" == OK:* ]]; then
        pass_test "$name"
    else
        fail_test "$name" "$result"
    fi
}

# =============================================================================
# Test: Rust frpc -> Go frps, STCP relay + encryption
# =============================================================================
test_r2g_stcp_encrypted() {
    local name="rust-to-go-stcp-encrypted"
    should_run_test "$name" || return 0

    log "=== $name ==="
    local frps_port=$(random_port)
    local echo_port=$(random_port)
    local visitor_port=$(random_port)
    local token="test-token-r2g-stcp-enc"
    local sk="stcp-secret-key-enc-43"

    mkdir -p "$TEST_DIR/$name"

    start_echo_server "$echo_port"
    wait_for_port 127.0.0.1 "$echo_port" 3 || {
        fail_test "$name" "echo server did not start"
        return
    }

    # Start Go frps
    write_frps_config go "$frps_port" "$token" "$TEST_DIR/$name/frps.toml" ""
    run_go "$GO_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Go frps did not start"
        return
    }

    # Start Rust frpc provider (STCP, encrypted)
    cat > "$TEST_DIR/$name/frpc-provider.toml" <<TOML
server_addr = "127.0.0.1"
server_port = $frps_port
token = "$token"
tcp_mux = false
tls_enable = false
login_fail_exit = true
pool_count = 1

[[proxies]]
name = "stcp-svc-enc"
type = "stcp"
local_ip = "127.0.0.1"
local_port = $echo_port
sk = "$sk"
use_encryption = true
TOML
    RUST_LOG=debug "$RUST_FRPC" -c "$TEST_DIR/$name/frpc-provider.toml" \
        > "$TEST_DIR/$name/frpc-provider.log" 2>&1 &
    track_pid $!

    # Start Rust frpc visitor (STCP visitor)
    cat > "$TEST_DIR/$name/frpc-visitor.toml" <<TOML
server_addr = "127.0.0.1"
server_port = $frps_port
token = "$token"
tcp_mux = false
tls_enable = false
login_fail_exit = true
pool_count = 1

[[visitors]]
name = "stcp-visitor-enc"
type = "stcp"
server_name = "stcp-svc-enc"
sk = "$sk"
bind_addr = "127.0.0.1"
bind_port = $visitor_port
TOML
    RUST_LOG=debug "$RUST_FRPC" -c "$TEST_DIR/$name/frpc-visitor.toml" \
        > "$TEST_DIR/$name/frpc-visitor.log" 2>&1 &
    track_pid $!

    if ! wait_for_port_safe 127.0.0.1 "$visitor_port" 15; then
        fail_test "$name" "visitor port $visitor_port not reachable"
        return
    fi

    local result
    result=$(send_and_expect "$visitor_port" "r2g-stcp-enc-data" "r2g-stcp-enc-data" 5)
    if [[ "$result" == OK:* ]]; then
        pass_test "$name"
    else
        fail_test "$name" "$result"
    fi
}

# =============================================================================
# Test: Go frpc SUDP visitor -> Rust frps (sudpPort) -> Rust frpc SUDP provider
# NOTE: Go frp v0.70.1 SUDP is a client-side half implementation — its server
# never registers the visitor listener ("custom listener doesn't exist") — so
# SUDP is only testable in the go->rust direction (Go visitor + Rust frps +
# Rust provider). rust->go-sudp is therefore skipped in this suite.
# =============================================================================
test_g2r_sudp() {
    local name="go-to-rust-sudp"
    should_run_test "$name" || return 0

    log "=== $name ==="
    local frps_port=$(random_port)
    local sudp_port=$(random_port)
    local echo_port=$(random_port)
    local visitor_port=$(random_port)
    local token="test-token-g2r-sudp"
    local sk="sudp-secret-key-51"

    mkdir -p "$TEST_DIR/$name"

    # Start UDP echo server
    start_udp_echo_server "$echo_port"

    # Start Rust frps with SUDP port (frp-rs SUDP is a shared-port extension:
    # providers register via sk, and sudpPort forces all SUDP proxies there)
    cat > "$TEST_DIR/$name/frps.toml" <<TOML
bind_addr = "127.0.0.1"
bind_port = $frps_port
sudpPort = $sudp_port

[auth]
method = "token"
token = "$token"

[transport]
tcp_mux = false
TOML
    RUST_LOG=info "$RUST_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Rust frps did not start"
        return
    }

    # Start Rust frpc provider (SUDP, plaintext; no remote_port needed)
    cat > "$TEST_DIR/$name/frpc-provider.toml" <<TOML
server_addr = "127.0.0.1"
server_port = $frps_port
token = "$token"
tcp_mux = false
tls_enable = false
login_fail_exit = true
pool_count = 1

[[proxies]]
name = "sudp-echo"
type = "sudp"
local_ip = "127.0.0.1"
local_port = $echo_port
sk = "$sk"
TOML
    RUST_LOG=info "$RUST_FRPC" -c "$TEST_DIR/$name/frpc-provider.toml" \
        > "$TEST_DIR/$name/frpc-provider.log" 2>&1 &
    track_pid $!

    # Start Go frpc visitor (SUDP)
    cat > "$TEST_DIR/$name/frpc-visitor.toml" <<TOML
serverAddr = "127.0.0.1"
serverPort = $frps_port
auth.token = "$token"
transport.tls.enable = false
transport.tcpMux = false
log.to = "$TEST_DIR/go-frpc-visitor-$name.log"
log.level = "debug"

[[visitors]]
name = "sudp-visitor"
type = "sudp"
serverName = "sudp-echo"
secretKey = "$sk"
bindAddr = "127.0.0.1"
bindPort = $visitor_port
TOML
    run_go "$GO_FRPC" -c "$TEST_DIR/$name/frpc-visitor.toml" \
        > "$TEST_DIR/$name/frpc-visitor.log" 2>&1 &
    track_pid $!

    # SUDP visitor is a UDP listener (wait_for_port_safe only checks TCP);
    # give registration a moment, then let send_and_expect_udp retry.
    sleep 2

    local result
    result=$(send_and_expect_udp "$visitor_port" "sudp-plain-data" 15)
    if [[ "$result" == "OK" ]]; then
        pass_test "$name"
    else
        fail_test "$name" "$result"
    fi
}

# =============================================================================
# Test: Go frpc SUDP visitor (encrypted) -> Rust frps (sudpPort) -> Rust frpc
#       SUDP provider (encrypted)
# Go frp three-segment model: visitor<->frps encrypted with PBKDF2(sk) when
# transport.useEncryption=true, provider<->frps with PBKDF2(token) when the
# provider declares use_encryption. Only the go->rust direction is testable
# (Go frp sudp server-side half implementation — see test_g2r_sudp).
# =============================================================================
test_g2r_sudp_encrypted() {
    local name="go-to-rust-sudp-encrypted"
    should_run_test "$name" || return 0

    log "=== $name ==="
    local frps_port=$(random_port)
    local sudp_port=$(random_port)
    local echo_port=$(random_port)
    local visitor_port=$(random_port)
    local token="test-token-g2r-sudp-enc"
    local sk="sudp-secret-key-enc-52"

    mkdir -p "$TEST_DIR/$name"

    # Start UDP echo server
    start_udp_echo_server "$echo_port"

    # Start Rust frps with SUDP port
    cat > "$TEST_DIR/$name/frps.toml" <<TOML
bind_addr = "127.0.0.1"
bind_port = $frps_port
sudpPort = $sudp_port

[auth]
method = "token"
token = "$token"

[transport]
tcp_mux = false
TOML
    RUST_LOG=info "$RUST_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Rust frps did not start"
        return
    }

    # Start Rust frpc provider (SUDP, encrypted provider segment)
    cat > "$TEST_DIR/$name/frpc-provider.toml" <<TOML
server_addr = "127.0.0.1"
server_port = $frps_port
token = "$token"
tcp_mux = false
tls_enable = false
login_fail_exit = true
pool_count = 1

[[proxies]]
name = "sudp-echo"
type = "sudp"
local_ip = "127.0.0.1"
local_port = $echo_port
sk = "$sk"
use_encryption = true
TOML
    RUST_LOG=info "$RUST_FRPC" -c "$TEST_DIR/$name/frpc-provider.toml" \
        > "$TEST_DIR/$name/frpc-provider.log" 2>&1 &
    track_pid $!

    # Start Go frpc visitor (SUDP, encrypted visitor segment)
    cat > "$TEST_DIR/$name/frpc-visitor.toml" <<TOML
serverAddr = "127.0.0.1"
serverPort = $frps_port
auth.token = "$token"
transport.tls.enable = false
transport.tcpMux = false
log.to = "$TEST_DIR/go-frpc-visitor-$name.log"
log.level = "debug"

[[visitors]]
name = "sudp-visitor"
type = "sudp"
serverName = "sudp-echo"
secretKey = "$sk"
bindAddr = "127.0.0.1"
bindPort = $visitor_port
transport.useEncryption = true
TOML
    run_go "$GO_FRPC" -c "$TEST_DIR/$name/frpc-visitor.toml" \
        > "$TEST_DIR/$name/frpc-visitor.log" 2>&1 &
    track_pid $!

    # SUDP visitor is a UDP listener; give registration a moment.
    sleep 2

    local result
    result=$(send_and_expect_udp "$visitor_port" "sudp-enc-data" 15)
    if [[ "$result" == "OK" ]]; then
        pass_test "$name"
    else
        fail_test "$name" "$result"
    fi
}

# =============================================================================
# Test: Go frpc -> Rust frps, UDP proxy + encryption
# =============================================================================
test_g2r_udp_encrypted() {
    local name="go-to-rust-udp-encrypted"
    should_run_test "$name" || return 0

    log "=== $name ==="
    local frps_port=$(random_port)
    local proxy_port=$(random_port)
    local echo_port=$(random_port)
    local token="test-token-g2r-udp-enc"

    mkdir -p "$TEST_DIR/$name"

    # Start UDP echo server
    start_udp_echo_server "$echo_port"

    # Start Rust frps
    write_frps_config rust "$frps_port" "$token" "$TEST_DIR/$name/frps.toml" ""
    RUST_LOG=info "$RUST_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Rust frps did not start"
        return
    }

    # Start Go frpc with encrypted UDP proxy
    write_frpc_config_udp go "$frps_port" "$token" "$echo_port" "$proxy_port" "udp-echo" "$TEST_DIR/$name/frpc.toml" enc
    run_go "$GO_FRPC" -c "$TEST_DIR/$name/frpc.toml" \
        > "$TEST_DIR/$name/frpc.log" 2>&1 &
    track_pid $!

    # UDP proxy needs a moment for work connection assignment
    sleep 1

    local result
    result=$(send_and_expect_udp "$proxy_port" "g2r-udp-enc-data" 15)
    if [[ "$result" == "OK" ]]; then
        pass_test "$name"
    else
        fail_test "$name" "$result"
    fi
}

# =============================================================================
# Test: Rust frpc -> Go frps, UDP proxy + encryption
# =============================================================================
test_r2g_udp_encrypted() {
    local name="rust-to-go-udp-encrypted"
    should_run_test "$name" || return 0

    log "=== $name ==="
    local frps_port=$(random_port)
    local proxy_port=$(random_port)
    local echo_port=$(random_port)
    local token="test-token-r2g-udp-enc"

    mkdir -p "$TEST_DIR/$name"

    # Start UDP echo server
    start_udp_echo_server "$echo_port"

    # Start Go frps
    write_frps_config go "$frps_port" "$token" "$TEST_DIR/$name/frps.toml" ""
    run_go "$GO_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Go frps did not start"
        return
    }

    # Start Rust frpc with encrypted UDP proxy
    write_frpc_config_udp rust "$frps_port" "$token" "$echo_port" "$proxy_port" "udp-echo" "$TEST_DIR/$name/frpc.toml" enc
    RUST_LOG=info "$RUST_FRPC" -c "$TEST_DIR/$name/frpc.toml" \
        > "$TEST_DIR/$name/frpc.log" 2>&1 &
    track_pid $!

    local result
    result=$(send_and_expect_udp "$proxy_port" "r2g-udp-enc-data" 15)
    if [[ "$result" == "OK" ]]; then
        pass_test "$name"
    else
        fail_test "$name" "$result"
    fi
}

# ═══ XTCP test infrastructure ═══════════════════════════════════════════════

# Generic XTCP end-to-end test runner.
# Usage: run_xtcp_test <name> <frps-impl> <provider-impl> <visitor-impl> [features]
#   features: space-separated list, e.g. "enc compression"
run_xtcp_test() {
    local name="$1" frps_impl="$2" prov_impl="$3" vis_impl="$4" features="${5:-}"
    # Extract numeric shard index from XTCP_SHARD (format "N/TOTAL")
    local shard_index=""
    if [[ -n "${XTCP_SHARD:-}" ]]; then
        shard_index="${XTCP_SHARD%%/*}"
    fi
    should_run_test "$name" || return 0

    # Kill any frpc/frps processes leaked from previous tests.
    # Old Go frpc processes keep trying to reconnect with stale tokens,
    # causing noise ("token doesn't match") and potential port conflicts.
    pkill -f "frpc -c" 2>/dev/null || true
    pkill -f "frps -c" 2>/dev/null || true
    sleep 0.5
    # Also kill local processes bound to our shard's base port
    local _sp
    if [[ -n "${shard_index:-}" ]]; then
        _sp=$((17000 + shard_index * 100))
        # fuser is available on all Linux distros (psmisc), no root needed
        local _pid
        _pid=$(fuser "${_sp}/tcp" 2>/dev/null || true)
        if [[ -n "$_pid" ]]; then
            kill $_pid 2>/dev/null || true
            sleep 0.3
        fi
    fi

    log "=== $name ==="
    local frps_port
    if [[ -n "$shard_index" ]]; then
        # Per-shard port range prevents TOCTOU race on shared VPS.
        # Shard 0: 17000-17099, Shard 1: 17100-17199, etc.
        frps_port=$((17000 + shard_index * 100))
    else
        frps_port=$(random_port)
    fi
    local echo_port=$(random_port)
    local visitor_port=$(random_port)
    local token="${name}-token-$(date +%s)"
    local sk="${name}-sk"

    mkdir -p "$TEST_DIR/$name"

    # Start echo server
    start_echo_server "$echo_port"
    wait_for_port 127.0.0.1 "$echo_port" 3 || {
        fail_test "$name" "echo server did not start"
        return
    }

    # Determine server address
    local server_host="127.0.0.1"
    if [[ -n "${XTCP_FRPS_REMOTE:-}" ]]; then
        server_host="$XTCP_FRPS_REMOTE"
        # SECURITY: --debug traces all commands including secrets. Refuse.
        if ${DEBUG:-false}; then
            fail_test "$name" "DEBUG mode incompatible with --frps-remote (exposes secrets via set -x)"
            return
        fi
        # Resolve SSH key: accept file path or inline key content
        local ssh_key_path="${XTCP_VPS_SSH_KEY:-}"
        if [[ -n "$ssh_key_path" ]] && [[ ! -f "$ssh_key_path" ]]; then
            # Not a file — assume inline key content, write to temp file
            local tmp_key="$TEST_DIR/$name/ssh-key"
            printf '%s\n' "$ssh_key_path" > "$tmp_key"
            chmod 600 "$tmp_key"
            ssh_key_path="$tmp_key"
        fi

        # Start frps on remote VPS — capture actual port (handles port conflicts)
        local actual_port
        actual_port=$(bash "$SCRIPT_DIR/remote-frps.sh" start "$frps_impl" "$XTCP_FRPS_REMOTE" \
            "$frps_port" "$token" "$ssh_key_path" "$shard_index" | tail -1) || {
            fail_test "$name" "remote frps ($frps_impl) did not start"
            bash "$SCRIPT_DIR/remote-frps.sh" stop "$XTCP_FRPS_REMOTE" "$ssh_key_path" "$shard_index" || true
            return
        }
        frps_port="$actual_port"
        log "Remote frps ready on port $frps_port"
    else
        # Start frps locally
        write_frps_config "$frps_impl" "$frps_port" "$token" "$TEST_DIR/$name/frps.toml" ""
        if [[ "$frps_impl" == "go" ]]; then
            run_go "$GO_FRPS" -c "$TEST_DIR/$name/frps.toml" \
                > "$TEST_DIR/$name/frps.log" 2>&1 &
            track_pid $!
        else
            RUST_LOG=info "$RUST_FRPS" -c "$TEST_DIR/$name/frps.toml" \
                > "$TEST_DIR/$name/frps.log" 2>&1 &
            track_pid $!
        fi
        wait_for_port 127.0.0.1 "$frps_port" 5 || {
            fail_test "$name" "local $frps_impl frps did not start"
            return
        }
    fi

    # Start provider frpc
    write_frpc_config_xtcp_provider "$prov_impl" "$server_host" "$frps_port" \
        "$token" "$echo_port" "$name" "$sk" "$TEST_DIR/$name/frpc-provider.toml" "$features"

    if [[ "$prov_impl" == "go" ]]; then
        run_go "$GO_FRPC" -c "$TEST_DIR/$name/frpc-provider.toml" \
            > "$TEST_DIR/$name/frpc-provider.log" 2>&1 &
        track_pid $!
    else
        RUST_LOG=debug "$RUST_FRPC" -c "$TEST_DIR/$name/frpc-provider.toml" \
            > "$TEST_DIR/$name/frpc-provider.log" 2>&1 &
        track_pid $!
    fi

    # Start visitor frpc
    write_frpc_config_xtcp_visitor "$vis_impl" "$server_host" "$frps_port" \
        "$token" "$visitor_port" "$name" "$sk" "$TEST_DIR/$name/frpc-visitor.toml" "$features"

    if [[ "$vis_impl" == "go" ]]; then
        run_go "$GO_FRPC" -c "$TEST_DIR/$name/frpc-visitor.toml" \
            > "$TEST_DIR/$name/frpc-visitor.log" 2>&1 &
        track_pid $!
    else
        RUST_LOG=debug "$RUST_FRPC" -c "$TEST_DIR/$name/frpc-visitor.toml" \
            > "$TEST_DIR/$name/frpc-visitor.log" 2>&1 &
        local _rpid=$!
        track_pid $_rpid
        # Quick health checks: verify process alive and producing log output
        sleep 1
        if ! kill -0 $_rpid 2>/dev/null; then
            wait $_rpid 2>/dev/null || true
            local _rc=$?
            fail_test "$name" "Rust frpc visitor PID $_rpid exited immediately (rc=$_rc)"
            if [[ -n "${XTCP_FRPS_REMOTE:-}" ]]; then
                bash "$SCRIPT_DIR/remote-frps.sh" stop "$XTCP_FRPS_REMOTE" "$ssh_key_path" "$shard_index" || true
            fi
            return
        fi
        # Check if log is being written
        sleep 2
        local _logsize
        _logsize=$(wc -c < "$TEST_DIR/$name/frpc-visitor.log" 2>/dev/null || echo 0)
        if [[ $_logsize -eq 0 ]]; then
            fail_test "$name" "Rust frpc visitor log empty after 3s (pid $_rpid alive but no output)"
            kill $_rpid 2>/dev/null || true
            if [[ -n "${XTCP_FRPS_REMOTE:-}" ]]; then
                bash "$SCRIPT_DIR/remote-frps.sh" stop "$XTCP_FRPS_REMOTE" "$ssh_key_path" "$shard_index" || true
            fi
            return
        fi
        echo "DBG: Rust frpc visitor log has ${_logsize}B after 3s" >&2
    fi

    # XTCP NAT hole punch coordination time
    sleep 2

    # Wait for visitor port to be ready
    if ! wait_for_port_safe 127.0.0.1 "$visitor_port" 30; then
        fail_test "$name" "visitor port $visitor_port not reachable"
        if [[ -n "${XTCP_FRPS_REMOTE:-}" ]]; then
            bash "$SCRIPT_DIR/remote-frps.sh" stop "$XTCP_FRPS_REMOTE" "$ssh_key_path" "$shard_index" || true
        fi
        return
    fi

    # Echo data round-trip
    local result
    result=$(send_and_expect "$visitor_port" "${name}-data" "${name}-data" 60)
    if [[ "$result" == OK:* ]]; then
        pass_test "$name"
    else
        fail_test "$name" "$result"
    fi

    # Cleanup remote frps
    if [[ -n "${XTCP_FRPS_REMOTE:-}" ]]; then
        bash "$SCRIPT_DIR/remote-frps.sh" stop "$XTCP_FRPS_REMOTE" "$ssh_key_path" "$shard_index" || true
    fi
}

# ═══ XTCP test definitions (17 pairwise matrix) ══════════════════════════════

# ── XTCP baselines (same-implementation) ──

test_xtcp_g2g_basic() { run_xtcp_test "xtcp-g2g-basic" go go go ""; }
test_xtcp_r2r_basic() { run_xtcp_test "xtcp-r2r-basic" rust rust rust ""; }

# ── XTCP cross-implementation ──

test_xtcp_g2r_basic() { run_xtcp_test "xtcp-g2r-basic" rust go go ""; }
test_xtcp_r2g_basic() { run_xtcp_test "xtcp-r2g-basic" go rust rust ""; }
test_xtcp_go_frps_go_prov_rust_vis() { run_xtcp_test "xtcp-go-frps-go-prov-rust-vis" go go rust ""; }
test_xtcp_go_frps_rust_prov_go_vis() { run_xtcp_test "xtcp-go-frps-rust-prov-go-vis" go rust go "kcp"; }
test_xtcp_rust_frps_go_prov_rust_vis() { run_xtcp_test "xtcp-rust-frps-go-prov-rust-vis" rust go rust ""; }
test_xtcp_rust_frps_rust_prov_go_vis() { run_xtcp_test "xtcp-rust-frps-rust-prov-go-vis" rust rust go "kcp"; }
test_xtcp_go_frps_go_prov_rust_vis_quic() { run_xtcp_test "xtcp-go-frps-go-prov-rust-vis-quic" go go rust "quic"; }

# ── XTCP encrypted variants ──

test_xtcp_g2g_enc() { run_xtcp_test "xtcp-g2g-enc" go go go "enc compression"; }
test_xtcp_r2r_enc() { run_xtcp_test "xtcp-r2r-enc" rust rust rust "enc compression"; }
test_xtcp_g2r_enc() { run_xtcp_test "xtcp-g2r-enc" rust go go "enc compression"; }
test_xtcp_r2g_enc() { run_xtcp_test "xtcp-r2g-enc" go rust rust "enc compression"; }
test_xtcp_go_frps_go_prov_rust_vis_enc() { run_xtcp_test "xtcp-go-frps-go-prov-rust-vis-enc" go go rust "enc compression"; }
test_xtcp_go_frps_rust_prov_go_vis_enc() { run_xtcp_test "xtcp-go-frps-rust-prov-go-vis-enc" go rust go "kcp enc compression"; }
test_xtcp_rust_frps_go_prov_rust_vis_enc() { run_xtcp_test "xtcp-rust-frps-go-prov-rust-vis-enc" rust go rust "enc compression"; }
test_xtcp_rust_frps_rust_prov_go_vis_enc() { run_xtcp_test "xtcp-rust-frps-rust-prov-go-vis-enc" rust rust go "kcp enc compression"; }

# =============================================================================
# Test: Multi-proxy (2 TCP proxies on same client)
# =============================================================================
test_multi_proxy() {
    local name="go-to-rust-multi-proxy"
    should_run_test "$name" || return 0

    log "=== $name ==="
    local frps_port=$(random_port)
    local proxy1_port=$(random_port)
    local proxy2_port=$(random_port)
    local echo1_port=$(random_port)
    local echo2_port=$(random_port)
    local token="test-token-multi"

    mkdir -p "$TEST_DIR/$name"

    start_echo_server "$echo1_port"
    wait_for_port 127.0.0.1 "$echo1_port" 3 || {
        fail_test "$name" "echo1 did not start"
        return
    }
    start_echo_server "$echo2_port"
    wait_for_port 127.0.0.1 "$echo2_port" 3 || {
        fail_test "$name" "echo2 did not start"
        return
    }

    write_frps_config rust "$frps_port" "$token" "$TEST_DIR/$name/frps.toml" ""
    RUST_LOG=info "$RUST_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Rust frps did not start"
        return
    }

    # Go frpc with 2 TCP proxies
    cat > "$TEST_DIR/$name/frpc.toml" <<TOML
serverAddr = "127.0.0.1"
serverPort = $frps_port
auth.token = "$token"
transport.tls.enable = false
transport.tcpMux = false
log.to = "$TEST_DIR/go-frpc-$name.log"
log.level = "debug"

[[proxies]]
name = "multi-1"
type = "tcp"
localIP = "127.0.0.1"
localPort = $echo1_port
remotePort = $proxy1_port

[[proxies]]
name = "multi-2"
type = "tcp"
localIP = "127.0.0.1"
localPort = $echo2_port
remotePort = $proxy2_port
TOML
    run_go "$GO_FRPC" -c "$TEST_DIR/$name/frpc.toml" \
        > "$TEST_DIR/$name/frpc.log" 2>&1 &
    track_pid $!

    if ! wait_for_port_safe 127.0.0.1 "$proxy1_port" 15; then
        fail_test "$name" "proxy1 port $proxy1_port not reachable"
        return
    fi
    if ! wait_for_port_safe 127.0.0.1 "$proxy2_port" 15; then
        fail_test "$name" "proxy2 port $proxy2_port not reachable"
        return
    fi

    # Test both proxies
    local r1 r2
    r1=$(send_and_expect "$proxy1_port" "multi-one" "multi-one" 5)
    r2=$(send_and_expect "$proxy2_port" "multi-two" "multi-two" 5)
    if [[ "$r1" == OK:* && "$r2" == OK:* ]]; then
        pass_test "$name"
    else
        fail_test "$name" "proxy1=$r1 proxy2=$r2"
    fi
}

# =============================================================================
# Test: Compression (useCompression)
# =============================================================================
test_g2r_compression() {
    local name="go-to-rust-compression"
    should_run_test "$name" || return 0

    log "=== $name ==="
    local frps_port=$(random_port)
    local proxy_port=$(random_port)
    local echo_port=$(random_port)
    local token="test-token-g2r-comp"

    mkdir -p "$TEST_DIR/$name"

    start_echo_server "$echo_port"
    wait_for_port 127.0.0.1 "$echo_port" 3 || {
        fail_test "$name" "echo server did not start"
        return
    }

    write_frps_config rust "$frps_port" "$token" "$TEST_DIR/$name/frps.toml" ""
    RUST_LOG=info "$RUST_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Rust frps did not start"
        return
    }

    write_frpc_config go "$frps_port" "$token" "$echo_port" "$proxy_port" "tcp-comp" "$TEST_DIR/$name/frpc.toml" "compression"
    run_go "$GO_FRPC" -c "$TEST_DIR/$name/frpc.toml" \
        > "$TEST_DIR/$name/frpc.log" 2>&1 &
    track_pid $!

    if ! wait_for_port_safe 127.0.0.1 "$proxy_port" 10; then
        fail_test "$name" "proxy port $proxy_port not reachable"
        return
    fi

    local result
    result=$(send_and_expect "$proxy_port" "compression-test-data" "compression-test-data" 5)
    if [[ "$result" == OK:* ]]; then
        pass_test "$name"
    else
        fail_test "$name" "$result"
    fi
}

# =============================================================================
# Test: Go frpc -> Rust frps, tcpmux HTTP CONNECT
# =============================================================================
test_g2r_tcpmux() {
    local name="go-to-rust-tcpmux"
    should_run_test "$name" || return 0

    log "=== $name ==="
    local frps_port=$(random_port)
    local tcpmux_port=$(random_port)
    local echo_port=$(random_port)
    local token="test-token-g2r-tcpmux"
    local domain="tcpmux-g2r.local"

    mkdir -p "$TEST_DIR/$name"

    start_echo_server "$echo_port"
    wait_for_port 127.0.0.1 "$echo_port" 3 || {
        fail_test "$name" "echo server did not start"
        return
    }

    # Start Rust frps with tcpmux HTTP CONNECT port
    write_frps_config rust "$frps_port" "$token" "$TEST_DIR/$name/frps.toml" "tcpmux=$tcpmux_port"
    RUST_LOG=info "$RUST_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Rust frps did not start"
        return
    }
    wait_for_port_safe 127.0.0.1 "$tcpmux_port" 5 || {
        fail_test "$name" "tcpmux port $tcpmux_port not reachable"
        return
    }

    # Start Go frpc with tcpmux proxy
    write_frpc_config_tcpmux go "$frps_port" "$token" "$echo_port" "tcpmux-g2r" "$domain" "$TEST_DIR/$name/frpc.toml" ""
    run_go "$GO_FRPC" -c "$TEST_DIR/$name/frpc.toml" \
        > "$TEST_DIR/$name/frpc.log" 2>&1 &
    track_pid $!

    # tcpmux routing needs time to propagate
    sleep 2

    # HTTP CONNECT through tcpmux port, then echo test
    local result
    result=$(send_tcpmux_test "$tcpmux_port" "$domain" "tcpmux-g2r-echo" 15)
    if [[ "$result" == OK:* ]]; then
        pass_test "$name"
    else
        fail_test "$name" "$result"
    fi
}

# =============================================================================
# Test: Rust frpc -> Go frps, tcpmux HTTP CONNECT
# =============================================================================
test_r2g_tcpmux() {
    local name="rust-to-go-tcpmux"
    should_run_test "$name" || return 0

    log "=== $name ==="
    local frps_port=$(random_port)
    local tcpmux_port=$(random_port)
    local echo_port=$(random_port)
    local token="test-token-r2g-tcpmux"
    local domain="tcpmux-r2g.local"

    mkdir -p "$TEST_DIR/$name"

    start_echo_server "$echo_port"
    wait_for_port 127.0.0.1 "$echo_port" 3 || {
        fail_test "$name" "echo server did not start"
        return
    }

    # Start Go frps with tcpmux HTTP CONNECT port
    write_frps_config go "$frps_port" "$token" "$TEST_DIR/$name/frps.toml" "tcpmux=$tcpmux_port"
    run_go "$GO_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Go frps did not start"
        return
    }
    wait_for_port_safe 127.0.0.1 "$tcpmux_port" 5 || {
        fail_test "$name" "tcpmux port $tcpmux_port not reachable"
        return
    }

    # Start Rust frpc with tcpmux proxy
    write_frpc_config_tcpmux rust "$frps_port" "$token" "$echo_port" "tcpmux-r2g" "$domain" "$TEST_DIR/$name/frpc.toml" ""
    RUST_LOG=info "$RUST_FRPC" -c "$TEST_DIR/$name/frpc.toml" \
        > "$TEST_DIR/$name/frpc.log" 2>&1 &
    track_pid $!

    # Python client below retries connect with 10s timeout

    # HTTP CONNECT through tcpmux port, then echo test
    local result
    result=$(send_tcpmux_test "$tcpmux_port" "$domain" "tcpmux-r2g-echo" 10)
    if [[ "$result" == OK:* ]]; then
        pass_test "$name"
    else
        fail_test "$name" "$result"
    fi
}

# =============================================================================
# Main
# =============================================================================

echo "============================================="
echo " frp-rs Cross-Compatibility Test Suite"
echo " Go frp v0.70.1 <-> Rust frp-rs"
echo "============================================="
echo ""

# Print binary versions
echo "Go frps: $($GO_FRPS --version 2>&1 || echo 'unknown')"
echo "Go frpc: $($GO_FRPC --version 2>&1 || echo 'unknown')"
echo "Rust frps: $($RUST_FRPS --version 2>&1 || echo 'unknown')"
echo "Rust frpc: $($RUST_FRPC --version 2>&1 || echo 'unknown')"
echo ""

# Verify binaries exist
for bin in "$GO_FRPS" "$GO_FRPC" "$RUST_FRPS" "$RUST_FRPC"; do
    if [[ ! -x "$bin" ]]; then
        echo "ERROR: Binary not found or not executable: $bin"
        exit 1
    fi
done

# Verify certs exist
for cert in "$CERT_DIR/ca.crt" "$CERT_DIR/server.crt" "$CERT_DIR/server.key"; do
    if [[ ! -f "$cert" ]]; then
        echo "ERROR: Certificate not found: $cert"
        exit 1
    fi
done

# Create test directory
rm -rf "$TEST_DIR"
mkdir -p "$TEST_DIR"

test_kcp_rust_to_rust() {
    local name="kcp-rust-to-rust"
    should_run_test "$name" || return 0

    log "=== $name ==="
    local frps_port=$(random_port)
    local kcp_port=$(random_port)
    local proxy_port=$(random_port)
    local echo_port=$(random_port)
    local token="test-token-kcp-r2r"

    mkdir -p "$TEST_DIR/$name"

    start_echo_server "$echo_port"
    wait_for_port 127.0.0.1 "$echo_port" 3 || {
        fail_test "$name" "echo server did not start"
        return
    }

    write_frps_config rust "$frps_port" "$token" "$TEST_DIR/$name/frps.toml" "kcp=$kcp_port"
    RUST_LOG=info "$RUST_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    # KCP uses UDP — wait for TCP bind port as readiness signal
    wait_for_port 127.0.0.1 "$frps_port" 10 || {
        fail_test "$name" "Rust frps did not start"
        return
    }

    write_frpc_config rust "$kcp_port" "$token" "$echo_port" "$proxy_port" "kcp-r2r" "$TEST_DIR/$name/frpc.toml" "kcp"
    RUST_LOG=info "$RUST_FRPC" -c "$TEST_DIR/$name/frpc.toml" \
        > "$TEST_DIR/$name/frpc.log" 2>&1 &
    track_pid $!

    if ! wait_for_port_safe 127.0.0.1 "$proxy_port" 15; then
        fail_test "$name" "proxy port $proxy_port not reachable"
        return
    fi

    local result
    result=$(send_and_expect "$proxy_port" "kcp-r2r-data" "kcp-r2r-data" 10)
    if [[ "$result" == OK:* ]]; then
        pass_test "$name"
    else
        fail_test "$name" "$result"
    fi
}

# =============================================================================
# Test: Rust frps -> Rust frpc, KCP transport + encrypted bridge
# =============================================================================
test_kcp_rust_encrypted() {
    local name="kcp-rust-encrypted"
    should_run_test "$name" || return 0

    log "=== $name ==="
    local frps_port=$(random_port)
    local kcp_port=$(random_port)
    local proxy_port=$(random_port)
    local echo_port=$(random_port)
    local token="test-token-kcp-r2r-enc"

    mkdir -p "$TEST_DIR/$name"

    start_echo_server "$echo_port"
    wait_for_port 127.0.0.1 "$echo_port" 3 || {
        fail_test "$name" "echo server did not start"
        return
    }

    write_frps_config rust "$frps_port" "$token" "$TEST_DIR/$name/frps.toml" "kcp=$kcp_port"
    RUST_LOG=info "$RUST_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 10 || {
        fail_test "$name" "Rust frps did not start"
        return
    }

    write_frpc_config rust "$kcp_port" "$token" "$echo_port" "$proxy_port" "kcp-enc" "$TEST_DIR/$name/frpc.toml" "kcp enc"
    RUST_LOG=info "$RUST_FRPC" -c "$TEST_DIR/$name/frpc.toml" \
        > "$TEST_DIR/$name/frpc.log" 2>&1 &
    track_pid $!

    if ! wait_for_port_safe 127.0.0.1 "$proxy_port" 15; then
        fail_test "$name" "proxy port $proxy_port not reachable"
        return
    fi

    local result
    result=$(send_and_expect "$proxy_port" "kcp-enc-test" "kcp-enc-test" 10)
    if [[ "$result" == OK:* ]]; then
        pass_test "$name"
    else
        fail_test "$name" "$result"
    fi
}

# =============================================================================
# Test: Rust frps -> Rust frpc, QUIC transport (Rust↔Rust)
# =============================================================================
test_quic_rust_to_rust() {
    local name="quic-rust-to-rust"
    should_run_test "$name" || return 0

    log "=== $name ==="
    local frps_port=$(random_port)
    local quic_port=$(random_port)
    local proxy_port=$(random_port)
    local echo_port=$(random_port)
    local token="test-token-quic-r2r"

    mkdir -p "$TEST_DIR/$name"

    start_echo_server "$echo_port"
    wait_for_port 127.0.0.1 "$echo_port" 3 || {
        fail_test "$name" "echo server did not start"
        return
    }

    write_frps_config rust "$frps_port" "$token" "$TEST_DIR/$name/frps.toml" "quic=$quic_port"
    RUST_LOG=info "$RUST_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    # QUIC uses UDP — wait for TCP bind port as readiness signal
    wait_for_port 127.0.0.1 "$frps_port" 10 || {
        fail_test "$name" "Rust frps did not start"
        return
    }

    write_frpc_config rust "$quic_port" "$token" "$echo_port" "$proxy_port" "quic-r2r" "$TEST_DIR/$name/frpc.toml" "quic"
    RUST_LOG=info "$RUST_FRPC" -c "$TEST_DIR/$name/frpc.toml" \
        > "$TEST_DIR/$name/frpc.log" 2>&1 &
    track_pid $!

    if ! wait_for_port_safe 127.0.0.1 "$proxy_port" 15; then
        fail_test "$name" "proxy port $proxy_port not reachable"
        return
    fi

    # Idle resilience: verify QUIC survives idle period
    sleep 5

    local result
    result=$(send_and_expect "$proxy_port" "quic-r2r-data" "quic-r2r-data" 10)
    if [[ "$result" == OK:* ]]; then
        pass_test "$name"
    else
        fail_test "$name" "$result"
    fi
}

# =============================================================================
# Test: Go frpc -> Rust frps, HTTPS proxy (VHost HTTPS)
# =============================================================================
test_g2r_https() {
    local name="go-to-rust-https"
    should_run_test "$name" || return 0

    log "=== $name ==="
    local frps_port=$(random_port)
    local vhost_https_port=$(random_port)
    local echo_port=$(random_port)
    local token="test-token-g2r-https"

    mkdir -p "$TEST_DIR/$name"

    # TLS-terminating echo server (Go frp semantics: frps/frpc pass TLS bytes
    # through; the local service terminates TLS).
    start_tls_echo_server "$echo_port" "https-ok:"
    wait_for_port 127.0.0.1 "$echo_port" 3 || {
        fail_test "$name" "TLS echo server did not start"
        return
    }

    # Start Rust frps with VHost HTTPS port
    cat > "$TEST_DIR/$name/frps.toml" <<TOML
bind_addr = "127.0.0.1"
bind_port = $frps_port
vhost_https_port = $vhost_https_port
subdomain_host = "test.local"
tls_enable = true
tls_cert_file = "$CERT_DIR/server.crt"
tls_key_file = "$CERT_DIR/server.key"

[auth]
method = "token"
token = "$token"

[transport]
tcp_mux = false
TOML
    RUST_LOG=info "$RUST_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Rust frps did not start"
        return
    }
    wait_for_port_safe 127.0.0.1 "$vhost_https_port" 5 || {
        fail_test "$name" "VHost HTTPS port $vhost_https_port not reachable"
        return
    }

    # Start Go frpc with HTTPS proxy
    cat > "$TEST_DIR/$name/frpc.toml" <<TOML
serverAddr = "127.0.0.1"
serverPort = $frps_port
auth.token = "$token"
transport.tls.enable = false
transport.tcpMux = false
log.to = "$TEST_DIR/go-frpc-$name.log"
log.level = "debug"

[[proxies]]
name = "https-web"
type = "https"
localIP = "127.0.0.1"
localPort = $echo_port
customDomains = ["https-test.local"]
TOML
    run_go "$GO_FRPC" -c "$TEST_DIR/$name/frpc.toml" \
        > "$TEST_DIR/$name/frpc.log" 2>&1 &
    track_pid $!

    # sleep 3: wait for HTTPS proxy registration + VHost routing propagation
    sleep 3

    # Send HTTPS request through VHost (skip TLS verification — self-signed cert)
    local result
    result=$(send_https_test "$vhost_https_port" "https-test.local" "https-ok:" 5)
    if [[ "$result" == "OK" ]]; then
        pass_test "$name"
    else
        fail_test "$name" "$result"
    fi
}

# =============================================================================
# Test: Rust frpc -> Go frps, HTTPS proxy (VHost HTTPS)
# =============================================================================
test_r2g_https() {
    local name="rust-to-go-https"
    should_run_test "$name" || return 0

    log "=== $name ==="
    local frps_port=$(random_port)
    local vhost_https_port=$(random_port)
    local echo_port=$(random_port)
    local token="test-token-r2g-https"

    mkdir -p "$TEST_DIR/$name"

    # Start HTTPS echo server (Go frps forwards raw TLS bytes; frpc needs local
    # service to terminate TLS — unlike g2r where Rust frps terminates TLS).
    # Use existing test certs; Python ssl module handles the TLS handshake.
    python3 -c "
import socket, ssl
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', $echo_port))
s.listen(5)
ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
ctx.load_cert_chain('$CERT_DIR/server.crt', '$CERT_DIR/server.key')
while True:
    try:
        conn, _ = s.accept()
        ss = ctx.wrap_socket(conn, server_side=True)
        data = b''
        while True:
            chunk = ss.recv(4096)
            if not chunk:
                break
            data += chunk
            if b'\r\n\r\n' in data:
                hdr_end = data.index(b'\r\n\r\n') + 4
                hdrs = data[:hdr_end].decode('utf-8', errors='ignore').lower()
                cl = 0
                for line in hdrs.split('\r\n'):
                    if line.startswith('content-length:'):
                        try:
                            cl = int(line.split(':')[1].strip())
                        except:
                            pass
                if len(data) - hdr_end >= cl:
                    break
        if data:
            body = b'https-ok:' + data.split(b'\r\n\r\n', 1)[-1] if b'\r\n\r\n' in data else b'https-ok'
            resp = b'HTTP/1.1 200 OK\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body
            ss.sendall(resp)
        ss.close()
    except Exception:
        # SSL errors per-connection are expected (e.g., wait_for_port
        # uses nc -z which doesn't do TLS handshake). Continue serving.
        try:
            conn.close()
        except Exception:
            pass
" &
    track_pid $!
    # NOTE: wait_for_port uses nc -z which triggers a TLS handshake
    # failure on the HTTPS echo server. The server handles this gracefully
    # by catching the per-connection error and continuing. But we still
    # need to verify the port is listening.
    wait_for_port 127.0.0.1 "$echo_port" 3 || {
        fail_test "$name" "HTTPS echo server did not start"
        return
    }

    # Start Go frps with VHost HTTPS port.
    # Note: Go frps vhostHTTPSPort does NOT terminate TLS — it reads SNI from
    # the ClientHello, routes to the correct frpc, and forwards raw TLS bytes.
    # TLS termination happens at frpc (or the local service behind frpc).
    # No TLS certs needed on Go frps for this path.
    cat > "$TEST_DIR/$name/frps.toml" <<TOML
bindAddr = "127.0.0.1"
bindPort = $frps_port
vhostHTTPSPort = $vhost_https_port
subDomainHost = "test.local"
auth.method = "token"
auth.token = "$token"

transport.tcpMux = false
log.to = "$TEST_DIR/go-frps.log"
log.level = "debug"
TOML
    run_go "$GO_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Go frps did not start"
        return
    }
    # wait_for_port_safe below polls for VHost HTTPS port
    wait_for_port_safe 127.0.0.1 "$vhost_https_port" 5 || {
        fail_test "$name" "VHost HTTPS port $vhost_https_port not reachable"
        return
    }

    # Start Rust frpc with HTTPS proxy
    cat > "$TEST_DIR/$name/frpc.toml" <<TOML
server_addr = "127.0.0.1"
server_port = $frps_port
token = "$token"
tcp_mux = false
tls_enable = false
login_fail_exit = true
pool_count = 1

[[proxies]]
name = "https-web"
type = "https"
local_ip = "127.0.0.1"
local_port = $echo_port
custom_domains = ["https-test.local"]
TOML
    RUST_LOG=info "$RUST_FRPC" -c "$TEST_DIR/$name/frpc.toml" \
        > "$TEST_DIR/$name/frpc.log" 2>&1 &
    track_pid $!

    # sleep 3: wait for HTTPS proxy registration + VHost routing propagation
    sleep 3

    # Send HTTPS request through VHost
    local result
    result=$(send_https_test "$vhost_https_port" "https-test.local" "https-ok:" 5)
    if [[ "$result" == "OK" ]]; then
        pass_test "$name"
    else
        fail_test "$name" "$result"
    fi
}

# -----------------------------------------------------------------------------
# Test: Auth rejection — Go frpc wrong token -> Rust frps rejects
# Verifies token-based auth replay protection across Go↔Rust boundary.
# Wrong token: proxy port never appears. Correct token: proxy works.
# -----------------------------------------------------------------------------
test_auth_g2r_reject() {
    local name="test_auth_g2r_reject"
    should_run_test "$name" || return 0

    log "=== $name ==="
    local frps_port=$(random_port)
    local proxy_port=$(random_port)
    local echo_port=$(random_port)
    local token="auth-test-token-g2r"

    mkdir -p "$TEST_DIR/$name"

    start_echo_server "$echo_port"
    wait_for_port 127.0.0.1 "$echo_port" 3 || {
        fail_test "$name" "echo server did not start"
        return
    }

    # Start Rust frps
    write_frps_config rust "$frps_port" "$token" "$TEST_DIR/$name/frps.toml" ""
    RUST_LOG=info "$RUST_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Rust frps did not start"
        return
    }

    # Attempt 1: Go frpc with WRONG token — must fail
    log "  $name: connecting with wrong token (expect rejection)..."
    write_frpc_config go "$frps_port" "wrong-token-NEVER-VALID" "$echo_port" "$proxy_port" "tcp-plain" "$TEST_DIR/$name/frpc-bad.toml" ""
    run_go "$GO_FRPC" -c "$TEST_DIR/$name/frpc-bad.toml" \
        > "$TEST_DIR/$name/frpc-bad.log" 2>&1 &
    local bad_pid=$!
    track_pid $bad_pid

    # Wait a bit — proxy port should NOT appear
    sleep 3
    if lsof -iTCP:"$proxy_port" -sTCP:LISTEN -t >/dev/null 2>&1; then
        kill $bad_pid 2>/dev/null || true
        fail_test "$name" "proxy port $proxy_port appeared with wrong token (auth bypass!)"
        return
    fi
    kill $bad_pid 2>/dev/null || true
    wait $bad_pid 2>/dev/null || true
    log "  $name: wrong token correctly rejected"

    # Attempt 2: Go frpc with CORRECT token — must succeed
    log "  $name: connecting with correct token..."
    write_frpc_config go "$frps_port" "$token" "$echo_port" "$proxy_port" "tcp-plain" "$TEST_DIR/$name/frpc.toml" ""
    run_go "$GO_FRPC" -c "$TEST_DIR/$name/frpc.toml" \
        > "$TEST_DIR/$name/frpc.log" 2>&1 &
    track_pid $!

    if ! wait_for_port_safe 127.0.0.1 "$proxy_port" 10; then
        fail_test "$name" "proxy port $proxy_port not reachable (auth rejection false positive?)"
        return
    fi

    # Verify data round-trip
    local result
    result=$(send_and_expect "$proxy_port" "auth-test-data" "auth-test-data" 5)
    if [[ "$result" == OK:* ]]; then
        pass_test "$name"
    else
        fail_test "$name" "$result"
    fi
}

# -----------------------------------------------------------------------------
# Test: Auth rejection — Rust frpc wrong token -> Go frps rejects
# Reverse direction of test_auth_g2r_reject.
# -----------------------------------------------------------------------------
test_auth_r2g_reject() {
    local name="test_auth_r2g_reject"
    should_run_test "$name" || return 0

    log "=== $name ==="
    local frps_port=$(random_port)
    local proxy_port=$(random_port)
    local echo_port=$(random_port)
    local token="auth-test-token-r2g"

    mkdir -p "$TEST_DIR/$name"

    start_echo_server "$echo_port"
    wait_for_port 127.0.0.1 "$echo_port" 3 || {
        fail_test "$name" "echo server did not start"
        return
    }

    # Start Go frps
    write_frps_config go "$frps_port" "$token" "$TEST_DIR/$name/frps.toml" ""
    run_go "$GO_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Go frps did not start"
        return
    }

    # Attempt 1: Rust frpc with WRONG token — must fail
    log "  $name: connecting with wrong token (expect rejection)..."
    write_frpc_config rust "$frps_port" "wrong-token-NEVER-VALID" "$echo_port" "$proxy_port" "tcp-plain" "$TEST_DIR/$name/frpc-bad.toml" ""
    RUST_LOG=info "$RUST_FRPC" -c "$TEST_DIR/$name/frpc-bad.toml" \
        > "$TEST_DIR/$name/frpc-bad.log" 2>&1 &
    local bad_pid=$!
    track_pid $bad_pid

    # Wait a bit — proxy port should NOT appear
    sleep 4
    if lsof -iTCP:"$proxy_port" -sTCP:LISTEN -t >/dev/null 2>&1; then
        kill $bad_pid 2>/dev/null || true
        fail_test "$name" "proxy port $proxy_port appeared with wrong token (auth bypass!)"
        return
    fi
    kill $bad_pid 2>/dev/null || true
    wait $bad_pid 2>/dev/null || true
    log "  $name: wrong token correctly rejected"

    # Give Go frps time to clean up the failed auth session
    sleep 2

    # Attempt 2: Rust frpc with CORRECT token — must succeed
    log "  $name: connecting with correct token..."
    write_frpc_config rust "$frps_port" "$token" "$echo_port" "$proxy_port" "tcp-plain" "$TEST_DIR/$name/frpc.toml" ""
    RUST_LOG=info "$RUST_FRPC" -c "$TEST_DIR/$name/frpc.toml" \
        > "$TEST_DIR/$name/frpc.log" 2>&1 &
    track_pid $!

    if ! wait_for_port_safe 127.0.0.1 "$proxy_port" 10; then
        fail_test "$name" "proxy port $proxy_port not reachable (auth rejection false positive?)"
        return
    fi

    # Verify data round-trip
    local result
    result=$(send_and_expect "$proxy_port" "auth-test-data" "auth-test-data" 5)
    if [[ "$result" == OK:* ]]; then
        pass_test "$name"
    else
        fail_test "$name" "$result"
    fi
}

# -----------------------------------------------------------------------------
# Test: Rust frpc -> Go frps authenticated HeartBeats over tcpMux.
# Both configs require the HeartBeats scope. Go frps rejects an unauthenticated
# Ping, so keeping the proxy alive across multiple 1s heartbeat intervals proves
# Rust frpc emitted token-authenticated Ping messages compatible with Go v0.70.1.
# -----------------------------------------------------------------------------
test_auth_r2g_heartbeats() {
    local name="test_auth_r2g_heartbeats"
    should_run_test "$name" || return 0

    log "=== $name ==="
    local frps_port=$(random_port)
    local proxy_port=$(random_port)
    local echo_port=$(random_port)
    local token="auth-test-token-r2g-heartbeats"

    mkdir -p "$TEST_DIR/$name"
    start_echo_server "$echo_port"
    wait_for_port 127.0.0.1 "$echo_port" 3 || {
        fail_test "$name" "echo server did not start"
        return
    }

    cat > "$TEST_DIR/$name/frps.toml" << TOML
bindAddr = "127.0.0.1"
bindPort = $frps_port

auth.method = "token"
auth.token = "$token"
auth.additionalScopes = ["HeartBeats"]

transport.tcpMux = true
transport.heartbeatTimeout = 5
log.to = "$TEST_DIR/$name/go-frps.log"
log.level = "debug"
TOML
    run_go "$GO_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Go frps did not start"
        return
    }

    cat > "$TEST_DIR/$name/frpc.toml" << TOML
server_addr = "127.0.0.1"
server_port = $frps_port
token = "$token"
login_fail_exit = true
heartbeat_interval = 1
heartbeat_timeout = 4
tcp_mux = true

[auth]
method = "token"
token = "$token"
additionalAuthScopes = ["HeartBeats"]

[[proxies]]
name = "heartbeat-auth"
type = "tcp"
local_ip = "127.0.0.1"
local_port = $echo_port
remote_port = $proxy_port
TOML
    RUST_LOG=debug "$RUST_FRPC" -c "$TEST_DIR/$name/frpc.toml" \
        > "$TEST_DIR/$name/frpc.log" 2>&1 &
    track_pid $!

    wait_for_port_safe 127.0.0.1 "$proxy_port" 10 || {
        fail_test "$name" "proxy did not register"
        return
    }
    sleep 3

    local result
    result=$(send_and_expect "$proxy_port" "heartbeat-auth-data" "heartbeat-auth-data" 5)
    if [[ "$result" == OK:* ]]; then
        pass_test "$name"
    else
        fail_test "$name" "$result"
    fi
}

# --- Run tests ---
if ! ${XTCP_ONLY:-false}; then
# Phase 1: Auth compatibility (cross-boundary token verification)
run_test test_auth_g2r_reject
run_test test_auth_r2g_reject
run_test test_auth_r2g_heartbeats
run_test test_g2r_oidc_proxy

# Phase 2: Go frpc -> Rust frps TCP data plane
run_test test_g2r_tcp_plain
run_test test_g2r_tcp_encrypted
run_test test_g2r_tcp_tls
run_test test_g2r_tcp_tls_encrypt

# Phase 2b: Go frpc -> Rust frps, tcp_mux
run_test test_g2r_mux_plain
run_test test_g2r_mux_encrypted
run_test test_g2r_mux_tls
run_test test_g2r_mux_tls_encrypt

# Phase 3: Rust frpc -> Go frps TCP data plane
run_test test_r2g_tcp_plain
run_test test_r2g_tcp_encrypted
run_test test_r2g_tcp_tls
run_test test_r2g_tcp_tls_encrypt

# Phase 3b: Rust frpc -> Go frps, tcp_mux
run_test test_r2g_mux_plain
run_test test_r2g_mux_encrypted
run_test test_r2g_mux_tls
run_test test_r2g_mux_tls_encrypt

# Phase 4: Other proxy types
run_test test_g2r_udp
run_test test_r2g_udp
run_test test_g2r_udp_encrypted
run_test test_r2g_udp_encrypted
# SUDP cross-compat (go->rust only): Go frp v0.70.1 sudp is a client-side half
# implementation — its server never registers the visitor listener ("custom
# listener doesn't exist") — so Go frps cannot serve a sudp visitor. SUDP is
# therefore only testable as Go visitor + Rust frps + Rust provider.
run_test test_g2r_sudp
run_test test_g2r_sudp_encrypted
run_test test_g2r_http
run_test test_r2g_http
run_test test_g2r_https
run_test test_r2g_https
run_test test_g2r_http_basic_auth
run_test test_g2r_http_host_header_rewrite
run_test test_g2r_http_subdomain
run_test test_g2r_http_response_headers
run_test test_r2g_http_response_headers
run_test test_g2r_http_locations
run_test test_r2g_http_locations
run_test test_g2r_route_by_http_user
run_test test_r2g_route_by_http_user
# Phase 4b: tcpmux HTTP CONNECT
run_test test_g2r_tcpmux
run_test test_r2g_tcpmux
run_test test_g2r_stcp
run_test test_r2g_stcp
run_test test_g2r_stcp_encrypted
run_test test_r2g_stcp_encrypted
fi

# ── XTCP tests (Phase 1: VPS CI or RUN_XTCP=1) ──
if [[ -n "${XTCP_FRPS_REMOTE:-}" ]]; then
    log "XTCP: remote frps mode — running pairwise tests"
    RUN_XTCP=1
fi

if ${XTCP_ONLY:-false} || [[ "${RUN_XTCP:-0}" == "1" ]]; then
    # ── 17 tests, shardable across CI matrix jobs ──
    # Use --shard INDEX/TOTAL to split across N parallel jobs
    XTCP_TESTS=(
        # Unencrypted
        "test_xtcp_g2g_basic"
        "test_xtcp_r2r_basic"
        "test_xtcp_g2r_basic"
        "test_xtcp_r2g_basic"
        "test_xtcp_go_frps_go_prov_rust_vis"
        "test_xtcp_go_frps_rust_prov_go_vis"
        "test_xtcp_rust_frps_go_prov_rust_vis"
        "test_xtcp_rust_frps_rust_prov_go_vis"
        # QUIC data plane (Rust visitor → Go provider; the reverse direction
        # is blocked by Go frp v0.70.1 sending "ip:port" as the QUIC SNI,
        # which rustls rejects — see CHANGELOG)
        "test_xtcp_go_frps_go_prov_rust_vis_quic"
        # Encrypted
        "test_xtcp_g2g_enc"
        "test_xtcp_r2r_enc"
        "test_xtcp_g2r_enc"
        "test_xtcp_r2g_enc"
        "test_xtcp_go_frps_go_prov_rust_vis_enc"
        "test_xtcp_go_frps_rust_prov_go_vis_enc"
        "test_xtcp_rust_frps_go_prov_rust_vis_enc"
        "test_xtcp_rust_frps_rust_prov_go_vis_enc"
    )

    if [[ -n "${XTCP_SHARD:-}" ]]; then
        # Sharded: run subset of tests for this CI matrix job
        # XTCP_SHARD format: "INDEX/TOTAL" e.g. "1/4"
        _xtcp_idx="${XTCP_SHARD%%/*}"
        _xtcp_total="${XTCP_SHARD##*/}"
        _xtcp_count=0
        log "XTCP shard ${_xtcp_idx}/${_xtcp_total}:"
        for ((_i=0; _i<${#XTCP_TESTS[@]}; _i++)); do
            if (( _i % _xtcp_total == _xtcp_idx )); then
                log "  [$((++_xtcp_count))] ${XTCP_TESTS[$_i]}"
                run_test "${XTCP_TESTS[$_i]}"
            fi
        done
        log "XTCP shard ${_xtcp_idx}/${_xtcp_total}: $_xtcp_count test(s) completed"
    else
        # Sequential: run all tests (local mode)
        log "XTCP: running all ${#XTCP_TESTS[@]} tests sequentially"
        for t in "${XTCP_TESTS[@]}"; do
            run_test "$t"
        done
    fi
else
    log "SKIP XTCP tests: requires public internet (STUN + NAT probes). Set RUN_XTCP=1 to enable."
fi

if ! ${XTCP_ONLY:-false}; then
# Phase 5: Multi-proxy and edge cases
run_test test_multi_proxy
run_test test_g2r_compression
# =============================================================================
# Test: Compression (useCompression) — Rust client → Go server
# =============================================================================
test_r2g_compression() {
    local name="rust-to-go-compression"
    should_run_test "$name" || return 0

    log "=== $name ==="
    local frps_port=$(random_port)
    local proxy_port=$(random_port)
    local echo_port=$(random_port)
    local token="test-token-r2g-comp"

    mkdir -p "$TEST_DIR/$name"

    start_echo_server "$echo_port"
    wait_for_port 127.0.0.1 "$echo_port" 3 || {
        fail_test "$name" "echo server did not start"
        return
    }

    write_frps_config go "$frps_port" "$token" "$TEST_DIR/$name/frps.toml" ""
    run_go "$GO_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Go frps did not start"
        return
    }

    write_frpc_config rust "$frps_port" "$token" "$echo_port" "$proxy_port" "tcp-comp" "$TEST_DIR/$name/frpc.toml" "compression"
    RUST_LOG=info "$RUST_FRPC" -c "$TEST_DIR/$name/frpc.toml" \
        > "$TEST_DIR/$name/frpc.log" 2>&1 &
    track_pid $!

    if ! wait_for_port_safe 127.0.0.1 "$proxy_port" 10; then
        fail_test "$name" "proxy port $proxy_port not reachable"
        return
    fi

    local result
    result=$(send_and_expect "$proxy_port" "hello-compression" "hello-compression" 5)
    if [[ "$result" == OK:* ]]; then
        pass_test "$name"
    else
        fail_test "$name" "expected OK: got $result"
    fi
}

# =============================================================================
# Test: Multi-Proxy — Rust client → Go server
# =============================================================================
test_r2g_multi_proxy() {
    local name="rust-to-go-multi-proxy"
    should_run_test "$name" || return 0

    log "=== $name ==="
    local frps_port=$(random_port)
    local proxy1_port=$(random_port)
    local proxy2_port=$(random_port)
    local echo1_port=$(random_port)
    local echo2_port=$(random_port)
    local token="test-token-r2g-multi"

    mkdir -p "$TEST_DIR/$name"

    start_echo_server "$echo1_port"
    wait_for_port 127.0.0.1 "$echo1_port" 3 || {
        fail_test "$name" "echo1 did not start"
        return
    }
    start_echo_server "$echo2_port"
    wait_for_port 127.0.0.1 "$echo2_port" 3 || {
        fail_test "$name" "echo2 did not start"
        return
    }

    write_frps_config go "$frps_port" "$token" "$TEST_DIR/$name/frps.toml" ""
    run_go "$GO_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Go frps did not start"
        return
    }

    # Rust frpc with 2 TCP proxies
    cat > "$TEST_DIR/$name/frpc.toml" <<TOML
server_addr = "127.0.0.1"
server_port = $frps_port
token = "$token"
tcp_mux = false
tls_enable = false
login_fail_exit = true
pool_count = 1

[[proxies]]
name = "multi-1"
type = "tcp"
local_ip = "127.0.0.1"
local_port = $echo1_port
remote_port = $proxy1_port

[[proxies]]
name = "multi-2"
type = "tcp"
local_ip = "127.0.0.1"
local_port = $echo2_port
remote_port = $proxy2_port
TOML
    RUST_LOG=info "$RUST_FRPC" -c "$TEST_DIR/$name/frpc.toml" \
        > "$TEST_DIR/$name/frpc.log" 2>&1 &
    track_pid $!

    if ! wait_for_port_safe 127.0.0.1 "$proxy1_port" 15; then
        fail_test "$name" "proxy1 port $proxy1_port not reachable"
        return
    fi
    if ! wait_for_port_safe 127.0.0.1 "$proxy2_port" 15; then
        fail_test "$name" "proxy2 port $proxy2_port not reachable"
        return
    fi

    # Test both proxies
    local r1 r2
    r1=$(send_and_expect "$proxy1_port" "multi-one-r2g" "multi-one-r2g" 5)
    r2=$(send_and_expect "$proxy2_port" "multi-two-r2g" "multi-two-r2g" 5)
    if [[ "$r1" == OK:* && "$r2" == OK:* ]]; then
        pass_test "$name"
    else
        fail_test "$name" "proxy1=$r1 proxy2=$r2"
    fi
}

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

    write_frps_config rust "$frps_port" "$token" "$TEST_DIR/$name/frps.toml" "ws"
    RUST_LOG=info "$RUST_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Rust frps did not start"
        return
    }

    write_frpc_config go "$frps_port" "$token" "$echo_port" "$proxy_port" "ws-plain" "$TEST_DIR/$name/frpc.toml" "ws"
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

    write_frps_config go "$frps_port" "$token" "$TEST_DIR/$name/frps.toml" "ws"
    run_go "$GO_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Go frps did not start"
        return
    }

    # Rust frpc connects via WebSocket to Go frps main port (bindPort).
    # Go frps HandleMux detects WS and proxies internally to VHost handler.
    write_frpc_config rust "$frps_port" "$token" "$echo_port" "$proxy_port" "ws-plain" "$TEST_DIR/$name/frpc.toml" "ws"
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

# =============================================================================
# Test: Go frpc -> Rust frps, WebSocket transport + encryption
# =============================================================================
test_g2r_ws_encrypted() {
    local name="go-to-rust-ws-encrypted"
    should_run_test "$name" || return 0

    log "=== $name ==="
    local frps_port=$(random_port)
    local proxy_port=$(random_port)
    local echo_port=$(random_port)
    local token="test-token-g2r-ws-enc"

    mkdir -p "$TEST_DIR/$name"

    start_echo_server "$echo_port"
    wait_for_port 127.0.0.1 "$echo_port" 3 || {
        fail_test "$name" "echo server did not start"
        return
    }

    write_frps_config rust "$frps_port" "$token" "$TEST_DIR/$name/frps.toml" "ws"
    RUST_LOG=info "$RUST_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Rust frps did not start"
        return
    }

    write_frpc_config go "$frps_port" "$token" "$echo_port" "$proxy_port" "ws-enc" "$TEST_DIR/$name/frpc.toml" "ws enc"
    run_go "$GO_FRPC" -c "$TEST_DIR/$name/frpc.toml" \
        > "$TEST_DIR/$name/frpc.log" 2>&1 &
    track_pid $!

    if ! wait_for_port_safe 127.0.0.1 "$proxy_port" 15; then
        fail_test "$name" "proxy port $proxy_port not reachable"
        return
    fi

    local result
    result=$(send_and_expect "$proxy_port" "ws-enc-test" "ws-enc-test" 5)
    if [[ "$result" == OK:* ]]; then
        pass_test "$name"
    else
        fail_test "$name" "$result"
    fi
}

# =============================================================================
# Test: Rust frpc -> Go frps, WebSocket transport + encryption
# =============================================================================
test_r2g_ws_encrypted() {
    local name="rust-to-go-ws-encrypted"
    should_run_test "$name" || return 0

    log "=== $name ==="
    local frps_port=$(random_port)
    local proxy_port=$(random_port)
    local echo_port=$(random_port)
    local token="test-token-r2g-ws-enc"

    mkdir -p "$TEST_DIR/$name"

    start_echo_server "$echo_port"
    wait_for_port 127.0.0.1 "$echo_port" 3 || {
        fail_test "$name" "echo server did not start"
        return
    }

    write_frps_config go "$frps_port" "$token" "$TEST_DIR/$name/frps.toml" "ws"
    run_go "$GO_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Go frps did not start"
        return
    }

    write_frpc_config rust "$frps_port" "$token" "$echo_port" "$proxy_port" "ws-enc" "$TEST_DIR/$name/frpc.toml" "ws enc"
    RUST_LOG=info "$RUST_FRPC" -c "$TEST_DIR/$name/frpc.toml" \
        > "$TEST_DIR/$name/frpc.log" 2>&1 &
    track_pid $!

    if ! wait_for_port_safe 127.0.0.1 "$proxy_port" 15; then
        fail_test "$name" "proxy port $proxy_port not reachable"
        return
    fi

    local result
    result=$(send_and_expect "$proxy_port" "r2g-ws-enc-test" "r2g-ws-enc-test" 5)
    if [[ "$result" == OK:* ]]; then
        pass_test "$name"
    else
        fail_test "$name" "$result"
    fi
}

# =============================================================================
# Test: Go frpc -> Rust frps, WSS transport
# =============================================================================
test_g2r_wss_plain() {
    local name="go-to-rust-wss-plain"
    should_run_test "$name" || return 0

    log "=== $name ==="
    local frps_port=$(random_port)
    local proxy_port=$(random_port)
    local echo_port=$(random_port)
    local token="test-token-g2r-wss"

    mkdir -p "$TEST_DIR/$name"

    start_echo_server "$echo_port"
    wait_for_port 127.0.0.1 "$echo_port" 3 || {
        fail_test "$name" "echo server did not start"
        return
    }

    write_frps_config rust "$frps_port" "$token" "$TEST_DIR/$name/frps.toml" "tls"
    RUST_LOG=info "$RUST_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Rust frps did not start"
        return
    }

    write_frpc_config go "$frps_port" "$token" "$echo_port" "$proxy_port" "wss-plain" "$TEST_DIR/$name/frpc.toml" "wss"
    run_go "$GO_FRPC" -c "$TEST_DIR/$name/frpc.toml" \
        > "$TEST_DIR/$name/frpc.log" 2>&1 &
    track_pid $!

    if ! wait_for_port_safe 127.0.0.1 "$proxy_port" 15; then
        fail_test "$name" "proxy port $proxy_port not reachable"
        return
    fi

    local result
    result=$(send_and_expect "$proxy_port" "wss-test-data" "wss-test-data" 5)
    if [[ "$result" == OK:* ]]; then
        pass_test "$name"
    else
        fail_test "$name" "$result"
    fi
}

# =============================================================================
# Test: Rust frpc -> Go frps, WSS transport
# =============================================================================
test_r2g_wss_plain() {
    local name="rust-to-go-wss-plain"
    should_run_test "$name" || return 0

    log "=== $name ==="
    local frps_port=$(random_port)
    local wss_port=$(random_port)
    local proxy_port=$(random_port)
    local echo_port=$(random_port)
    local token="test-token-r2g-wss"

    mkdir -p "$TEST_DIR/$name"

    start_echo_server "$echo_port"
    wait_for_port 127.0.0.1 "$echo_port" 3 || {
        fail_test "$name" "echo server did not start"
        return
    }

    write_frps_config go "$frps_port" "$token" "$TEST_DIR/$name/frps.toml" "tls ws vhost_wss=$wss_port"
    run_go "$GO_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Go frps did not start"
        return
    }
    wait_for_port 127.0.0.1 "$wss_port" 5 || {
        fail_test "$name" "Go frps WSS port $wss_port not listening"
        return
    }

    write_frpc_config rust "$wss_port" "$token" "$echo_port" "$proxy_port" "wss-plain" "$TEST_DIR/$name/frpc.toml" "wss"
    RUST_LOG=info "$RUST_FRPC" -c "$TEST_DIR/$name/frpc.toml" \
        > "$TEST_DIR/$name/frpc.log" 2>&1 &
    track_pid $!

    if ! wait_for_port_safe 127.0.0.1 "$proxy_port" 15; then
        fail_test "$name" "proxy port $proxy_port not reachable"
        return
    fi

    local result
    result=$(send_and_expect "$proxy_port" "r2g-wss-data" "r2g-wss-data" 5)
    if [[ "$result" == OK:* ]]; then
        pass_test "$name"
    else
        fail_test "$name" "$result"
    fi
}

# =============================================================================
# Test: Go frpc -> Rust frps, WSS transport + encryption
# =============================================================================
test_g2r_wss_encrypted() {
    local name="go-to-rust-wss-encrypted"
    should_run_test "$name" || return 0

    log "=== $name ==="
    local frps_port=$(random_port)
    local proxy_port=$(random_port)
    local echo_port=$(random_port)
    local token="test-token-g2r-wss-enc"

    mkdir -p "$TEST_DIR/$name"

    start_echo_server "$echo_port"
    wait_for_port 127.0.0.1 "$echo_port" 3 || {
        fail_test "$name" "echo server did not start"
        return
    }

    write_frps_config rust "$frps_port" "$token" "$TEST_DIR/$name/frps.toml" "tls"
    RUST_LOG=info "$RUST_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Rust frps did not start"
        return
    }

    write_frpc_config go "$frps_port" "$token" "$echo_port" "$proxy_port" "wss-enc" "$TEST_DIR/$name/frpc.toml" "wss enc"
    run_go "$GO_FRPC" -c "$TEST_DIR/$name/frpc.toml" \
        > "$TEST_DIR/$name/frpc.log" 2>&1 &
    track_pid $!

    if ! wait_for_port_safe 127.0.0.1 "$proxy_port" 15; then
        fail_test "$name" "proxy port $proxy_port not reachable"
        return
    fi

    local result
    result=$(send_and_expect "$proxy_port" "wss-enc-test" "wss-enc-test" 5)
    if [[ "$result" == OK:* ]]; then
        pass_test "$name"
    else
        fail_test "$name" "$result"
    fi
}

# =============================================================================
# Test: Go frpc -> Rust frps, WSS transport + tcpMux
# =============================================================================
test_g2r_wss_mux() {
    local name="go-to-rust-wss-mux"
    should_run_test "$name" || return 0

    log "=== $name ==="
    local frps_port=$(random_port)
    local proxy_port=$(random_port)
    local echo_port=$(random_port)
    local token="test-token-g2r-wss-mux"

    mkdir -p "$TEST_DIR/$name"

    start_echo_server "$echo_port"
    wait_for_port 127.0.0.1 "$echo_port" 3 || {
        fail_test "$name" "echo server did not start"
        return
    }

    write_frps_config rust "$frps_port" "$token" "$TEST_DIR/$name/frps.toml" "tls mux"
    RUST_LOG=info "$RUST_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Rust frps did not start"
        return
    }

    write_frpc_config go "$frps_port" "$token" "$echo_port" "$proxy_port" "wss-mux" "$TEST_DIR/$name/frpc.toml" "wss mux"
    run_go "$GO_FRPC" -c "$TEST_DIR/$name/frpc.toml" \
        > "$TEST_DIR/$name/frpc.log" 2>&1 &
    track_pid $!

    if ! wait_for_port_safe 127.0.0.1 "$proxy_port" 15; then
        fail_test "$name" "proxy port $proxy_port not reachable"
        return
    fi

    local result
    result=$(send_and_expect "$proxy_port" "wss-mux-data" "wss-mux-data" 5)
    if [[ "$result" == OK:* ]]; then
        pass_test "$name"
    else
        fail_test "$name" "$result"
    fi
}

# =============================================================================
# Test: Rust frpc -> Go frps, WSS transport + encryption
# =============================================================================
test_r2g_wss_encrypted() {
    local name="rust-to-go-wss-encrypted"
    should_run_test "$name" || return 0

    log "=== $name ==="
    local frps_port=$(random_port)
    local wss_port=$(random_port)
    local proxy_port=$(random_port)
    local echo_port=$(random_port)
    local token="test-token-r2g-wss-enc"

    mkdir -p "$TEST_DIR/$name"

    start_echo_server "$echo_port"
    wait_for_port 127.0.0.1 "$echo_port" 3 || {
        fail_test "$name" "echo server did not start"
        return
    }

    write_frps_config go "$frps_port" "$token" "$TEST_DIR/$name/frps.toml" "tls ws vhost_wss=$wss_port"
    run_go "$GO_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Go frps did not start"
        return
    }
    wait_for_port 127.0.0.1 "$wss_port" 5 || {
        fail_test "$name" "Go frps WSS port $wss_port not listening"
        return
    }

    write_frpc_config rust "$wss_port" "$token" "$echo_port" "$proxy_port" "wss-enc" "$TEST_DIR/$name/frpc.toml" "wss enc"
    RUST_LOG=info "$RUST_FRPC" -c "$TEST_DIR/$name/frpc.toml" \
        > "$TEST_DIR/$name/frpc.log" 2>&1 &
    track_pid $!

    if ! wait_for_port_safe 127.0.0.1 "$proxy_port" 15; then
        fail_test "$name" "proxy port $proxy_port not reachable"
        return
    fi

    local result
    result=$(send_and_expect "$proxy_port" "r2g-wss-enc-test" "r2g-wss-enc-test" 5)
    if [[ "$result" == OK:* ]]; then
        pass_test "$name"
    else
        fail_test "$name" "$result"
    fi
}

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
    local token="test-token-r2g-socks5"

    mkdir -p "$TEST_DIR/$name"

    start_echo_server "$echo_port"
    wait_for_port 127.0.0.1 "$echo_port" 3 || {
        fail_test "$name" "echo server did not start"
        return
    }

    write_frps_config go "$frps_port" "$token" "$TEST_DIR/$name/frps.toml" ""
    run_go "$GO_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Go frps did not start"
        return
    }

    # Rust frpc with SOCKS5 plugin
    cat > "$TEST_DIR/$name/frpc.toml" <<TOML
server_addr = "127.0.0.1"
server_port = $frps_port
token = "$token"
tcp_mux = false
tls_enable = false
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
        fail_test "$name" "SOCKS5 proxy port $proxy_port not reachable"
        return
    fi

    # SOCKS5 handshake + CONNECT to echo server, then echo test
    local result
    result=$(send_socks5_test "$proxy_port" "$echo_port" "socks5-test" 10)

    if [[ "$result" == OK:* ]]; then
        pass_test "$name"
    else
        fail_test "$name" "$result"
    fi
}

# =============================================================================
# Test: Go frpc SOCKS5 plugin -> Rust frps
# =============================================================================
test_g2r_socks5() {
    local name="go-to-rust-socks5"
    should_run_test "$name" || return 0

    log "=== $name ==="
    local frps_port=$(random_port)
    local proxy_port=$(random_port)
    local echo_port=$(random_port)
    local token="test-token-g2r-socks5"

    mkdir -p "$TEST_DIR/$name"

    start_echo_server "$echo_port"
    wait_for_port 127.0.0.1 "$echo_port" 3 || {
        fail_test "$name" "echo server did not start"
        return
    }

    write_frps_config rust "$frps_port" "$token" "$TEST_DIR/$name/frps.toml" ""
    RUST_LOG=info "$RUST_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Rust frps did not start"
        return
    }

    # Go frpc with SOCKS5 plugin
    cat > "$TEST_DIR/$name/frpc.toml" <<TOML
serverAddr = "127.0.0.1"
serverPort = $frps_port
auth.token = "$token"
transport.tls.enable = false
transport.tcpMux = false
log.to = "$TEST_DIR/go-frpc-$name.log"
log.level = "debug"

[[proxies]]
name = "socks5-proxy"
type = "tcp"
remotePort = $proxy_port

[proxies.plugin]
type = "socks5"
TOML
    run_go "$GO_FRPC" -c "$TEST_DIR/$name/frpc.toml" \
        > "$TEST_DIR/$name/frpc.log" 2>&1 &
    track_pid $!

    if ! wait_for_port_safe 127.0.0.1 "$proxy_port" 15; then
        fail_test "$name" "SOCKS5 proxy port $proxy_port not reachable"
        return
    fi

    # SOCKS5 handshake + CONNECT to echo server, then echo test
    local result
    result=$(send_socks5_test "$proxy_port" "$echo_port" "socks5-g2r-test" 10)

    if [[ "$result" == OK:* ]]; then
        pass_test "$name"
    else
        fail_test "$name" "$result"
    fi
}

# =============================================================================
# Test: Go frpc -> Rust frps, KCP transport
# =============================================================================
test_g2r_kcp() {
    local name="go-to-rust-kcp"
    should_run_test "$name" || return 0

    log "=== $name ==="
    local frps_port=$(random_port)
    local kcp_port=$(random_port)
    local proxy_port=$(random_port)
    local echo_port=$(random_port)
    local token="test-token-g2r-kcp"

    mkdir -p "$TEST_DIR/$name"

    start_echo_server "$echo_port"
    wait_for_port 127.0.0.1 "$echo_port" 3 || {
        fail_test "$name" "echo server did not start"
        return
    }

    write_frps_config rust "$frps_port" "$token" "$TEST_DIR/$name/frps.toml" "kcp=$kcp_port"
    RUST_LOG=info "$RUST_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    # KCP uses UDP — wait for TCP bind port as readiness signal
    wait_for_port 127.0.0.1 "$frps_port" 10 || {
        fail_test "$name" "Rust frps did not start"
        return
    }

    # Go frpc with transport.protocol=kcp connects to the KCP port directly
    write_frpc_config go "$kcp_port" "$token" "$echo_port" "$proxy_port" "kcp-plain" "$TEST_DIR/$name/frpc.toml" "kcp"
    run_go "$GO_FRPC" -c "$TEST_DIR/$name/frpc.toml" \
        > "$TEST_DIR/$name/frpc.log" 2>&1 &
    track_pid $!

    if ! wait_for_port_safe 127.0.0.1 "$proxy_port" 15; then
        fail_test "$name" "proxy port $proxy_port not reachable"
        return
    fi

    local result
    result=$(send_and_expect "$proxy_port" "kcp-test-data" "kcp-test-data" 10)
    if [[ "$result" == OK:* ]]; then
        pass_test "$name"
    else
        fail_test "$name" "$result"
    fi
}

# =============================================================================
# Test: Rust frpc -> Go frps, KCP transport
# =============================================================================
test_r2g_kcp() {
    local name="rust-to-go-kcp"
    should_run_test "$name" || return 0

    log "=== $name ==="
    local frps_port=$(random_port)
    local kcp_port=$(random_port)
    local proxy_port=$(random_port)
    local echo_port=$(random_port)
    local token="test-token-r2g-kcp"

    mkdir -p "$TEST_DIR/$name"

    start_echo_server "$echo_port"
    wait_for_port 127.0.0.1 "$echo_port" 3 || {
        fail_test "$name" "echo server did not start"
        return
    }

    write_frps_config go "$frps_port" "$token" "$TEST_DIR/$name/frps.toml" "kcp=$kcp_port"
    run_go "$GO_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    # KCP uses UDP — wait for TCP bind port as readiness signal
    wait_for_port 127.0.0.1 "$frps_port" 10 || {
        fail_test "$name" "Go frps did not start"
        return
    }

    # Rust frpc with transport_protocol=kcp connects to the KCP port directly
    write_frpc_config rust "$kcp_port" "$token" "$echo_port" "$proxy_port" "kcp-plain" "$TEST_DIR/$name/frpc.toml" "kcp"
    RUST_LOG=info "$RUST_FRPC" -c "$TEST_DIR/$name/frpc.toml" \
        > "$TEST_DIR/$name/frpc.log" 2>&1 &
    track_pid $!

    if ! wait_for_port_safe 127.0.0.1 "$proxy_port" 15; then
        fail_test "$name" "proxy port $proxy_port not reachable"
        return
    fi

    local result
    result=$(send_and_expect "$proxy_port" "kcp-r2g-test" "kcp-r2g-test" 10)
    if [[ "$result" == OK:* ]]; then
        pass_test "$name"
    else
        fail_test "$name" "$result"
    fi
}

# =============================================================================
# Test: Go frpc -> Rust frps, KCP transport + TLS
# Go frp v0.70.1 supports KCP+TLS: Go frpc realConnect() applies the same TLS
# hooks (DialHookCustomTLSHeadByte + WithTLSConfig) with WithProtocol("kcp");
# Go frps HandleListener() runs CheckAndEnableTLSServerConn over its
# kcpListener. Rust side: transport.rs dials KCP then wraps in TLS; service.rs
# accept path strips 0x17/0x16 prefix and does TLS accept over KCP.
# =============================================================================
test_g2r_kcp_tls() {
    local name="go-to-rust-kcp-tls"
    should_run_test "$name" || return 0

    log "=== $name ==="
    local frps_port=$(random_port)
    local kcp_port=$(random_port)
    local proxy_port=$(random_port)
    local echo_port=$(random_port)
    local token="test-token-g2r-kcp-tls"

    mkdir -p "$TEST_DIR/$name"

    start_echo_server "$echo_port"
    wait_for_port 127.0.0.1 "$echo_port" 3 || {
        fail_test "$name" "echo server did not start"
        return
    }

    write_frps_config rust "$frps_port" "$token" "$TEST_DIR/$name/frps.toml" "kcp=$kcp_port tls"
    RUST_LOG=info "$RUST_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    # KCP uses UDP — wait for TCP bind port as readiness signal
    wait_for_port 127.0.0.1 "$frps_port" 10 || {
        fail_test "$name" "Rust frps did not start"
        return
    }

    # Go frpc with transport.protocol=kcp + TLS connects to the KCP port directly
    write_frpc_config go "$kcp_port" "$token" "$echo_port" "$proxy_port" "kcp-tls" "$TEST_DIR/$name/frpc.toml" "kcp tls"
    run_go "$GO_FRPC" -c "$TEST_DIR/$name/frpc.toml" \
        > "$TEST_DIR/$name/frpc.log" 2>&1 &
    track_pid $!

    if ! wait_for_port_safe 127.0.0.1 "$proxy_port" 15; then
        fail_test "$name" "proxy port $proxy_port not reachable"
        return
    fi

    local result
    result=$(send_and_expect "$proxy_port" "kcp-tls-test-data" "kcp-tls-test-data" 10)
    if [[ "$result" == OK:* ]]; then
        pass_test "$name"
    else
        fail_test "$name" "$result"
    fi
}

# =============================================================================
# Test: Rust frpc -> Go frps, KCP transport + TLS
# =============================================================================
test_r2g_kcp_tls() {
    local name="rust-to-go-kcp-tls"
    should_run_test "$name" || return 0

    log "=== $name ==="
    local frps_port=$(random_port)
    local kcp_port=$(random_port)
    local proxy_port=$(random_port)
    local echo_port=$(random_port)
    local token="test-token-r2g-kcp-tls"

    mkdir -p "$TEST_DIR/$name"

    start_echo_server "$echo_port"
    wait_for_port 127.0.0.1 "$echo_port" 3 || {
        fail_test "$name" "echo server did not start"
        return
    }

    write_frps_config go "$frps_port" "$token" "$TEST_DIR/$name/frps.toml" "kcp=$kcp_port tls"
    run_go "$GO_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    # KCP uses UDP — wait for TCP bind port as readiness signal
    wait_for_port 127.0.0.1 "$frps_port" 10 || {
        fail_test "$name" "Go frps did not start"
        return
    }

    # Rust frpc with transport_protocol=kcp + TLS connects to the KCP port directly
    write_frpc_config rust "$kcp_port" "$token" "$echo_port" "$proxy_port" "kcp-tls" "$TEST_DIR/$name/frpc.toml" "kcp tls"
    RUST_LOG=info "$RUST_FRPC" -c "$TEST_DIR/$name/frpc.toml" \
        > "$TEST_DIR/$name/frpc.log" 2>&1 &
    track_pid $!

    if ! wait_for_port_safe 127.0.0.1 "$proxy_port" 15; then
        fail_test "$name" "proxy port $proxy_port not reachable"
        return
    fi

    local result
    result=$(send_and_expect "$proxy_port" "kcp-tls-r2g-test" "kcp-tls-r2g-test" 10)
    if [[ "$result" == OK:* ]]; then
        pass_test "$name"
    else
        fail_test "$name" "$result"
    fi
}

# =============================================================================
# Test: Go frpc -> Rust frps, KCP transport + tcpMux (yamux over KCP)
# Go frp v0.70.1 supports KCP+tcpMux: frpc connector Open() wraps the KCP
# realConnect() result in fmux.Client; frps HandleListener() wraps every
# non-QUIC connection (incl. kcpListener) in fmux.Server when TCPMux is on.
# =============================================================================
test_g2r_kcp_mux() {
    local name="go-to-rust-kcp-mux"
    should_run_test "$name" || return 0

    log "=== $name ==="
    local frps_port=$(random_port)
    local kcp_port=$(random_port)
    local proxy_port=$(random_port)
    local echo_port=$(random_port)
    local token="test-token-g2r-kcp-mux"

    mkdir -p "$TEST_DIR/$name"

    start_echo_server "$echo_port"
    wait_for_port 127.0.0.1 "$echo_port" 3 || {
        fail_test "$name" "echo server did not start"
        return
    }

    write_frps_config rust "$frps_port" "$token" "$TEST_DIR/$name/frps.toml" "kcp=$kcp_port mux"
    RUST_LOG=info "$RUST_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    # KCP uses UDP — wait for TCP bind port as readiness signal
    wait_for_port 127.0.0.1 "$frps_port" 10 || {
        fail_test "$name" "Rust frps did not start"
        return
    }

    # Go frpc with transport.protocol=kcp + tcpMux=true connects to the KCP port
    write_frpc_config go "$kcp_port" "$token" "$echo_port" "$proxy_port" "kcp-mux" "$TEST_DIR/$name/frpc.toml" "kcp mux"
    run_go "$GO_FRPC" -c "$TEST_DIR/$name/frpc.toml" \
        > "$TEST_DIR/$name/frpc.log" 2>&1 &
    track_pid $!

    if ! wait_for_port_safe 127.0.0.1 "$proxy_port" 15; then
        fail_test "$name" "proxy port $proxy_port not reachable"
        return
    fi

    local result
    result=$(send_and_expect "$proxy_port" "kcp-mux-test-data" "kcp-mux-test-data" 10)
    if [[ "$result" == OK:* ]]; then
        pass_test "$name"
    else
        fail_test "$name" "$result"
    fi
}

# =============================================================================
# Test: Rust frpc -> Go frps, KCP transport + tcpMux (yamux over KCP)
# =============================================================================
test_r2g_kcp_mux() {
    local name="rust-to-go-kcp-mux"
    should_run_test "$name" || return 0

    log "=== $name ==="
    local frps_port=$(random_port)
    local kcp_port=$(random_port)
    local proxy_port=$(random_port)
    local echo_port=$(random_port)
    local token="test-token-r2g-kcp-mux"

    mkdir -p "$TEST_DIR/$name"

    start_echo_server "$echo_port"
    wait_for_port 127.0.0.1 "$echo_port" 3 || {
        fail_test "$name" "echo server did not start"
        return
    }

    write_frps_config go "$frps_port" "$token" "$TEST_DIR/$name/frps.toml" "kcp=$kcp_port mux"
    run_go "$GO_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    # KCP uses UDP — wait for TCP bind port as readiness signal
    wait_for_port 127.0.0.1 "$frps_port" 10 || {
        fail_test "$name" "Go frps did not start"
        return
    }

    # Rust frpc with transport_protocol=kcp + tcp_mux=true connects to the KCP port
    write_frpc_config rust "$kcp_port" "$token" "$echo_port" "$proxy_port" "kcp-mux" "$TEST_DIR/$name/frpc.toml" "kcp mux"
    RUST_LOG=info "$RUST_FRPC" -c "$TEST_DIR/$name/frpc.toml" \
        > "$TEST_DIR/$name/frpc.log" 2>&1 &
    track_pid $!

    if ! wait_for_port_safe 127.0.0.1 "$proxy_port" 15; then
        fail_test "$name" "proxy port $proxy_port not reachable"
        return
    fi

    local result
    result=$(send_and_expect "$proxy_port" "kcp-mux-r2g-test" "kcp-mux-r2g-test" 10)
    if [[ "$result" == OK:* ]]; then
        pass_test "$name"
    else
        fail_test "$name" "$result"
    fi
}

# =============================================================================
# Test: Go frpc -> Rust frps, QUIC transport
# =============================================================================
test_g2r_quic() {
    local name="go-to-rust-quic"
    should_run_test "$name" || return 0

    log "=== $name ==="
    local frps_port=$(random_port)
    local quic_port=$(random_port)
    local proxy_port=$(random_port)
    local echo_port=$(random_port)
    local token="test-token-g2r-quic"

    mkdir -p "$TEST_DIR/$name"

    start_echo_server "$echo_port"
    wait_for_port 127.0.0.1 "$echo_port" 3 || {
        fail_test "$name" "echo server did not start"
        return
    }

    write_frps_config rust "$frps_port" "$token" "$TEST_DIR/$name/frps.toml" "quic=$quic_port"
    RUST_LOG=info "$RUST_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    # QUIC uses UDP, wait for the TCP bind port as readiness signal
    wait_for_port 127.0.0.1 "$frps_port" 10 || {
        fail_test "$name" "Rust frps did not start"
        return
    }

    # Go frpc with transport.protocol=quic connects to the QUIC port directly
    write_frpc_config go "$quic_port" "$token" "$echo_port" "$proxy_port" "quic-plain" "$TEST_DIR/$name/frpc.toml" "quic"
    run_go "$GO_FRPC" -c "$TEST_DIR/$name/frpc.toml" \
        > "$TEST_DIR/$name/frpc.log" 2>&1 &
    track_pid $!

    # QUIC transport needs extra time for multi-stream setup
    sleep 2

    if ! wait_for_port_safe 127.0.0.1 "$proxy_port" 25; then
        fail_test "$name" "proxy port $proxy_port not reachable"
        return
    fi

    # Idle resilience: verify QUIC survives idle period
    sleep 5

    local result
    result=$(send_and_expect "$proxy_port" "quic-test-data" "quic-test-data" 15)
    if [[ "$result" == OK:* ]]; then
        pass_test "$name"
    else
        fail_test "$name" "$result"
    fi
}

# =============================================================================
# Test: Rust frpc -> Go frps, QUIC transport
# =============================================================================
test_r2g_quic() {
    local name="rust-to-go-quic"
    should_run_test "$name" || return 0

    log "=== $name ==="
    local frps_port=$(random_port)
    local quic_port=$(random_port)
    local proxy_port=$(random_port)
    local echo_port=$(random_port)
    local token="test-token-r2g-quic"

    mkdir -p "$TEST_DIR/$name"

    start_echo_server "$echo_port"
    wait_for_port 127.0.0.1 "$echo_port" 3 || {
        fail_test "$name" "echo server did not start"
        return
    }

    write_frps_config go "$frps_port" "$token" "$TEST_DIR/$name/frps.toml" "quic=$quic_port"
    run_go "$GO_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 10 || {
        fail_test "$name" "Go frps did not start"
        return
    }

    # Rust frpc with transport_protocol=quic connects to the QUIC port directly
    write_frpc_config rust "$quic_port" "$token" "$echo_port" "$proxy_port" "quic-plain" "$TEST_DIR/$name/frpc.toml" "quic"
    RUST_LOG=info "$RUST_FRPC" -c "$TEST_DIR/$name/frpc.toml" \
        > "$TEST_DIR/$name/frpc.log" 2>&1 &
    track_pid $!

    if ! wait_for_port_safe 127.0.0.1 "$proxy_port" 15; then
        fail_test "$name" "proxy port $proxy_port not reachable"
        return
    fi

    # Idle resilience: verify QUIC survives idle period
    sleep 5

    local result
    result=$(send_and_expect "$proxy_port" "quic-r2g-test" "quic-r2g-test" 10)
    if [[ "$result" == OK:* ]]; then
        pass_test "$name"
    else
        fail_test "$name" "$result"
    fi
}

# =============================================================================
# Test: Go frpc -> Rust frps, QUIC multi-proxy (2 proxies over 1 QUIC connection)
# =============================================================================
test_g2r_quic_multi_proxy() {
    local name="go-to-rust-quic-multi-proxy"
    should_run_test "$name" || return 0

    log "=== $name ==="
    local frps_port=$(random_port)
    local quic_port=$(random_port)
    local proxy1_port=$(random_port)
    local proxy2_port=$(random_port)
    local echo1_port=$(random_port)
    local echo2_port=$(random_port)
    local token="test-token-g2r-quic-multi"

    mkdir -p "$TEST_DIR/$name"

    start_echo_server "$echo1_port"
    wait_for_port 127.0.0.1 "$echo1_port" 3 || {
        fail_test "$name" "echo1 server did not start"
        return
    }
    start_echo_server "$echo2_port"
    wait_for_port 127.0.0.1 "$echo2_port" 3 || {
        fail_test "$name" "echo2 server did not start"
        return
    }

    # Start Rust frps with QUIC
    write_frps_config rust "$frps_port" "$token" "$TEST_DIR/$name/frps.toml" "quic=$quic_port"
    RUST_LOG=info "$RUST_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 10 || {
        fail_test "$name" "Rust frps did not start"
        return
    }

    # Custom Go frpc config with 2 proxies over QUIC
    cat > "$TEST_DIR/$name/frpc.toml" << GOFPC_EOF
serverAddr = "127.0.0.1"
serverPort = $quic_port

auth.token = "$token"

transport.protocol = "quic"
transport.tls.enable = true
transport.tls.disableCustomTLSFirstByte = true
transport.tls.trustedCaFile = "$CERT_DIR/ca.crt"
transport.tls.serverName = "localhost"
transport.tcpMux = false

log.to = "$TEST_DIR/go-frpc-$name.log"
log.level = "debug"

[[proxies]]
name = "quic-multi-1"
type = "tcp"
localIP = "127.0.0.1"
localPort = $echo1_port
remotePort = $proxy1_port

[[proxies]]
name = "quic-multi-2"
type = "tcp"
localIP = "127.0.0.1"
localPort = $echo2_port
remotePort = $proxy2_port
GOFPC_EOF

    run_go "$GO_FRPC" -c "$TEST_DIR/$name/frpc.toml" \
        > "$TEST_DIR/$name/frpc.log" 2>&1 &
    track_pid $!

    # QUIC transport needs extra time for multi-stream setup
    sleep 2

    # Verify proxy 1
    if ! wait_for_port_safe 127.0.0.1 "$proxy1_port" 25; then
        fail_test "$name" "proxy1 port $proxy1_port not reachable"
        return
    fi
    local result1
    result1=$(send_and_expect "$proxy1_port" "quic-multi-1-data" "quic-multi-1-data" 5)

    # Verify proxy 2
    if ! wait_for_port_safe 127.0.0.1 "$proxy2_port" 15; then
        fail_test "$name" "proxy2 port $proxy2_port not reachable"
        return
    fi
    local result2
    result2=$(send_and_expect "$proxy2_port" "quic-multi-2-data" "quic-multi-2-data" 5)

    if [[ "$result1" == OK:* ]] && [[ "$result2" == OK:* ]]; then
        pass_test "$name"
    else
        fail_test "$name" "proxy1=$result1 proxy2=$result2"
    fi
}

# =============================================================================
# Test: Go frpc -> Rust frps, QUIC transport + encryption
# =============================================================================
test_g2r_quic_encrypted() {
    local name="go-to-rust-quic-encrypted"
    should_run_test "$name" || return 0

    log "=== $name ==="
    local frps_port=$(random_port)
    local quic_port=$(random_port)
    local proxy_port=$(random_port)
    local echo_port=$(random_port)
    local token="test-token-g2r-quic-enc"

    mkdir -p "$TEST_DIR/$name"

    start_echo_server "$echo_port"
    wait_for_port 127.0.0.1 "$echo_port" 3 || {
        fail_test "$name" "echo server did not start"
        return
    }

    write_frps_config rust "$frps_port" "$token" "$TEST_DIR/$name/frps.toml" "quic=$quic_port"
    RUST_LOG=info "$RUST_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    # QUIC uses UDP, wait for the TCP bind port as readiness signal
    wait_for_port 127.0.0.1 "$frps_port" 10 || {
        fail_test "$name" "Rust frps did not start"
        return
    }

    # Go frpc with QUIC + bridge encryption
    write_frpc_config go "$quic_port" "$token" "$echo_port" "$proxy_port" "quic-enc" "$TEST_DIR/$name/frpc.toml" "quic enc"
    run_go "$GO_FRPC" -c "$TEST_DIR/$name/frpc.toml" \
        > "$TEST_DIR/$name/frpc.log" 2>&1 &
    track_pid $!

    # QUIC transport needs extra time for multi-stream setup
    sleep 2

    if ! wait_for_port_safe 127.0.0.1 "$proxy_port" 25; then
        fail_test "$name" "proxy port $proxy_port not reachable"
        return
    fi

    # Idle resilience: verify QUIC survives idle period
    sleep 5

    local result
    result=$(send_and_expect "$proxy_port" "quic-enc-data" "quic-enc-data" 15)
    if [[ "$result" == OK:* ]]; then
        pass_test "$name"
    else
        fail_test "$name" "$result"
    fi
}

# =============================================================================
# Test: Rust frpc -> Go frps, QUIC transport + encryption
# =============================================================================
test_r2g_quic_encrypted() {
    local name="rust-to-go-quic-encrypted"
    should_run_test "$name" || return 0

    log "=== $name ==="
    local frps_port=$(random_port)
    local quic_port=$(random_port)
    local proxy_port=$(random_port)
    local echo_port=$(random_port)
    local token="test-token-r2g-quic-enc"

    mkdir -p "$TEST_DIR/$name"

    start_echo_server "$echo_port"
    wait_for_port 127.0.0.1 "$echo_port" 3 || {
        fail_test "$name" "echo server did not start"
        return
    }

    write_frps_config go "$frps_port" "$token" "$TEST_DIR/$name/frps.toml" "quic=$quic_port"
    run_go "$GO_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 10 || {
        echo "--- Go frps log tail ---"
        tail -40 "$TEST_DIR/$name/frps.log" 2>/dev/null || true
        fail_test "$name" "Go frps did not start"
        return
    }

    # Rust frpc with QUIC + bridge encryption
    write_frpc_config rust "$quic_port" "$token" "$echo_port" "$proxy_port" "quic-enc" "$TEST_DIR/$name/frpc.toml" "quic enc"
    RUST_LOG=info "$RUST_FRPC" -c "$TEST_DIR/$name/frpc.toml" \
        > "$TEST_DIR/$name/frpc.log" 2>&1 &
    track_pid $!

    if ! wait_for_port_safe 127.0.0.1 "$proxy_port" 15; then
        fail_test "$name" "proxy port $proxy_port not reachable"
        return
    fi

    # Idle resilience: verify QUIC survives idle period
    sleep 5

    local result
    result=$(send_and_expect "$proxy_port" "quic-r2g-enc" "quic-r2g-enc" 10)
    if [[ "$result" == OK:* ]]; then
        pass_test "$name"
    else
        fail_test "$name" "$result"
    fi
}

# =============================================================================
# Test: Go frpc (V2 wire protocol) -> Rust frps
# =============================================================================
test_g2r_v2_tcp() {
    local name="test_g2r_v2_tcp"
    should_run_test "$name" || return 0

    # Go frp v0.70.1+ pre-built binary includes V2 support.
    ensure_go_frp_v2 || return 0

    log "=== $name ==="
    local frps_port=$(random_port)
    local proxy_port=$(random_port)
    local echo_port=$(random_port)
    local token="test-token-g2r-v2"

    mkdir -p "$TEST_DIR/$name"

    start_echo_server "$echo_port"
    wait_for_port 127.0.0.1 "$echo_port" 3 || {
        fail_test "$name" "echo server did not start"
        return
    }

    # Start Rust frps (mux required -- Go frpc V2 uses yamux)
    write_frps_config rust "$frps_port" "$token" "$TEST_DIR/$name/frps.toml" "mux"
    echo 'v2 = true' >> "$TEST_DIR/$name/frps.toml"
    RUST_LOG=info "$RUST_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Rust frps did not start"
        return
    }

    # Start Go frpc (V2 + tcp_mux, pre-built binary).
    write_frpc_config go "$frps_port" "$token" "$echo_port" "$proxy_port" \
        "v2-tcp" "$TEST_DIR/$name/frpc.toml" "mux"
    # Insert V2 wire protocol BEFORE transport.tls.enable. Inserting before
    # [[proxies]] with tls.enable included duplicates the key, causing
    # Go frp to fail with "toml: key enable is already defined".
    sed -i.bak '/^transport\.tls\.enable/i\
transport.wireProtocol = "v2"
' "$TEST_DIR/$name/frpc.toml"
    rm -f "$TEST_DIR/$name/frpc.toml.bak"
    run_go "$GO_FRPC_V2" -c "$TEST_DIR/$name/frpc.toml" \
        > "$TEST_DIR/$name/frpc.log" 2>&1 &
    track_pid $!

    if ! wait_for_port_safe 127.0.0.1 "$proxy_port" 15; then
        fail_test "$name" "proxy port $proxy_port not reachable"
        return
    fi

    local result
    result=$(send_and_expect "$proxy_port" "v2-g2r-test" "v2-g2r-test" 5)
    if [[ "$result" == OK:* ]]; then
        pass_test "$name"
    else
        fail_test "$name" "$result"
    fi
}

# =============================================================================
# Test: Rust frpc (V2 wire protocol) -> Go frps
# =============================================================================
test_r2g_v2_tcp() {
    local name="test_r2g_v2_tcp"
    should_run_test "$name" || return 0

    # Go frps auto-detects V2 from connection magic bytes — no server-side
    # config needed. Pre-built binary has CheckMagic() in its server path.
    log "=== $name ==="
    local frps_port=$(random_port)
    local proxy_port=$(random_port)
    local echo_port=$(random_port)
    local token="test-token-r2g-v2"

    mkdir -p "$TEST_DIR/$name"

    start_echo_server "$echo_port"
    wait_for_port 127.0.0.1 "$echo_port" 3 || {
        fail_test "$name" "echo server did not start"
        return
    }

    # Start Go frps (pre-built, auto-detects V2 from magic bytes).
    write_frps_config go "$frps_port" "$token" "$TEST_DIR/$name/frps.toml" "mux"
    run_go "$GO_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Go frps did not start"
        return
    }

    # Start Rust frpc with V2 + tcp_mux
    write_frpc_config rust "$frps_port" "$token" "$echo_port" "$proxy_port" \
        "v2-tcp" "$TEST_DIR/$name/frpc.toml" "mux"
    # Insert v2 = true BEFORE [[proxies]] section
    sed -i.bak '/^\[\[proxies\]\]/i\
v2 = true\
' "$TEST_DIR/$name/frpc.toml"
    rm -f "$TEST_DIR/$name/frpc.toml.bak"
    "$RUST_FRPC" -c "$TEST_DIR/$name/frpc.toml" \
        > "$TEST_DIR/$name/frpc.log" 2>&1 &
    track_pid $!

    if ! wait_for_port_safe 127.0.0.1 "$proxy_port" 15; then
        fail_test "$name" "proxy port $proxy_port not reachable"
        return
    fi

    local result
    result=$(send_and_expect "$proxy_port" "v2-r2g-test" "v2-r2g-test" 5)
    if [[ "$result" == OK:* ]]; then
        pass_test "$name"
    else
        fail_test "$name" "$result"
    fi
}

# =============================================================================
# Test: Rust frps SSH gateway banner format
# =============================================================================
test_ssh_gateway_banner() {
    local name="ssh-gateway-banner"
    should_run_test "$name" || return 0

    log "=== $name ==="
    local frps_port=$(random_port)
    local ssh_port=$(random_port)
    local token="test-token-ssh-banner"

    mkdir -p "$TEST_DIR/$name"

    # Rust frps with SSH gateway enabled
    write_frps_config rust "$frps_port" "$token" "$TEST_DIR/$name/frps.toml" ""
    cat >> "$TEST_DIR/$name/frps.toml" << 'SSH_EOF'

[ssh_tunnel_gateway]
bind_addr = "127.0.0.1"
bind_port = SSH_PORT_PLACEHOLDER
SSH_EOF
    # sed the ssh port in (heredoc doesn't expand vars with quoted delimiter)
    sed -i.bak "s/SSH_PORT_PLACEHOLDER/$ssh_port/" "$TEST_DIR/$name/frps.toml"
    rm -f "$TEST_DIR/$name/frps.toml.bak"

    RUST_LOG=info "$RUST_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Rust frps did not start"
        return
    }
    wait_for_port 127.0.0.1 "$ssh_port" 10 || {
        fail_test "$name" "SSH gateway port $ssh_port not reachable"
        return
    }

    # Read SSH banner from the gateway port using Python (portable, no /dev/tcp needed)
    local banner
    banner=$(python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
try:
    s.connect(('127.0.0.1', $ssh_port))
    data = s.recv(256)
    print(data.decode('utf-8', errors='replace').strip())
except Exception as e:
    print('BANNER_ERROR: ' + str(e))
finally:
    s.close()
" 2>/dev/null || echo "BANNER_ERROR")

    if echo "$banner" | grep -q "^SSH-"; then
        log "SSH banner: $(echo "$banner" | head -1)"
        pass_test "$name"
    else
        fail_test "$name" "expected SSH banner starting with 'SSH-', got: $banner"
    fi
}

# =============================================================================
# Test: SSH gateway auth rejection (bad credentials)
# =============================================================================
test_ssh_gateway_auth_rejection() {
    local name="ssh-gateway-auth-rejection"
    should_run_test "$name" || return 0

    log "=== $name ==="
    local frps_port=$(random_port)
    local ssh_port=$(random_port)
    local token="test-token-ssh-auth"

    mkdir -p "$TEST_DIR/$name"

    write_frps_config rust "$frps_port" "$token" "$TEST_DIR/$name/frps.toml" ""
    cat >> "$TEST_DIR/$name/frps.toml" << 'SSH_EOF'

[ssh_tunnel_gateway]
bind_addr = "127.0.0.1"
bind_port = SSH_PORT_PLACEHOLDER
SSH_EOF
    sed -i.bak "s/SSH_PORT_PLACEHOLDER/$ssh_port/" "$TEST_DIR/$name/frps.toml"
    rm -f "$TEST_DIR/$name/frps.toml.bak"

    RUST_LOG=info "$RUST_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$ssh_port" 10 || {
        fail_test "$name" "SSH gateway port not reachable"
        return
    }

    # Attempt SSH connection with invalid credentials. Expect failure.
    # Use sshpass if available (explicit wrong password), otherwise
    # use BatchMode=yes (no password prompt, key-only auth) which must fail
    # since no authorized_keys are configured.
    # ssh -o ConnectTimeout=5 handles timeout without requiring the `timeout` command.
    local ssh_failed=0
    if command -v sshpass &>/dev/null; then
        if sshpass -p "WRONG_PASSWORD_DO_NOT_USE" \
            ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
            -o ConnectTimeout=5 -o PasswordAuthentication=yes \
            -o ServerAliveInterval=2 -o ServerAliveCountMax=1 \
            -p "$ssh_port" testuser@127.0.0.1 "exit" 2>/dev/null; then
            ssh_failed=0
        else
            ssh_failed=1
        fi
    else
        # Fallback: ssh with BatchMode (key-only auth, must fail without keys)
        if ssh -o BatchMode=yes -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 \
            -o PasswordAuthentication=no \
            -o ServerAliveInterval=2 -o ServerAliveCountMax=1 \
            -p "$ssh_port" testuser@127.0.0.1 "exit" 2>/dev/null; then
            ssh_failed=0
        else
            ssh_failed=1
        fi
    fi

    if [[ $ssh_failed -eq 1 ]]; then
        pass_test "$name"
    else
        fail_test "$name" "expected SSH auth to fail with bad credentials"
    fi
}

# =============================================================================
# Test: Go frps SSH gateway compat
# =============================================================================
test_ssh_gateway_go_frps_compat() {
    local name="ssh-gateway-go-frps-compat"
    should_run_test "$name" || return 0

    log "=== $name ==="
    local frps_port=$(random_port)
    local ssh_port=$(random_port)
    local token="test-token-ssh-go"

    mkdir -p "$TEST_DIR/$name"

    # Start Go frps with SSH gateway (write full config, no write_frps_config SSH support)
    cat > "$TEST_DIR/$name/frps.toml" << GOFPS_EOF
bindAddr = "127.0.0.1"
bindPort = $frps_port

auth.method = "token"
auth.token = "$token"

sshTunnelGateway.bindPort = $ssh_port

log.to = "$TEST_DIR/go-frps-$name.log"
log.level = "debug"
GOFPS_EOF

    run_go "$GO_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$ssh_port" 10 || {
        fail_test "$name" "Go frps SSH gateway port not reachable"
        return
    }

    # Read SSH banner from Go frps SSH gateway
    local banner
    banner=$(python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
try:
    s.connect(('127.0.0.1', $ssh_port))
    data = s.recv(256)
    print(data.decode('utf-8', errors='replace').strip())
except Exception as e:
    print('BANNER_ERROR: ' + str(e))
finally:
    s.close()
" 2>/dev/null || echo "BANNER_ERROR")

    if echo "$banner" | grep -q "^SSH-"; then
        log "Go frps SSH banner: $(echo "$banner" | head -1)"
        pass_test "$name"
    else
        fail_test "$name" "expected SSH banner from Go frps, got: $banner"
    fi
}

# Phase 5: Multi-proxy and edge cases (continued)
run_test test_r2g_compression
run_test test_r2g_multi_proxy

# Phase 6: WebSocket transport
run_test test_g2r_ws_plain
run_test test_r2g_ws_plain
run_test test_g2r_ws_encrypted
run_test test_r2g_ws_encrypted

# Phase 6b: WebSocket Secure (WSS) transport
# g2r: Go frpc → Rust frps — TLS+WS upgrade detected in Rust frps accept loop. WORKS.
run_test test_g2r_wss_plain
run_test test_g2r_wss_encrypted
run_test test_g2r_wss_mux
# r2g: Rust frpc → Go frps — blocked by Go frp v0.70.1 vhostHTTPSPort TLS SNI bug.
# Go frps sends fatal UnrecognisedName alert (112). Rust frpc rustls aborts.
# Go frps vhostHTTPSPort TLS config does not set ServerName for reverse WSS
# connections. Monitor Go frp upstream for fix.
# r2g WSS tests disabled: Go frps HTTPS port rejects self-signed certs without proper SAN.
# Go frps WSS requires certs with vhost domain SAN entries; our test certs only have
# localhost. g2r WSS tests work because Rust frps accepts our self-signed certs.
# run_test test_r2g_wss_plain
# run_test test_r2g_wss_encrypted
# run_test test_r2g_wss_mux

# Phase 7: Plugin
run_test test_g2r_socks5
run_test test_r2g_socks5

# Kill all previous test processes before KCP/QUIC tests.
# KCP and QUIC use UDP ports, and old processes from earlier phases
# can hold UDP ports invisible to random_port()'s TCP-only lsof check.
cleanup_pids

# =============================================================================
# Test: Rust frps -> Rust frpc, KCP transport (Rust↔Rust)
# =============================================================================
# Phase 8: KCP + QUIC transport cross-compat
# Rust↔Rust KCP: both sides use the in-tree KCP implementation
# (kcp-go v5.6.13 aligned), wire-compatible.
run_test test_kcp_rust_to_rust
# KCP Go↔Rust: FEC compat + poll_flush fix. Control login, work conn routing
# all working. echo server 100ms delay workaround for kcp-go Close() race.
run_test test_g2r_kcp
run_test test_r2g_kcp
# KCP+encrypted bridge (Rust-Rust only): KCP transport with AES-128-CFB encryption.
run_test test_kcp_rust_encrypted
# KCP+TLS and KCP+tcpMux: Go frp v0.70.1 supports both. Go frps applies TLS
# detection + yamux to its kcpListener (server/service.go HandleListener);
# Go frpc realConnect() applies TLS hooks with WithProtocol("kcp") and
# fmux.Client (client/connector.go). Rust side implements the same paths.
run_test test_g2r_kcp_tls
run_test test_r2g_kcp_tls
run_test test_g2r_kcp_mux
run_test test_r2g_kcp_mux

# QUIC Rust↔Rust: both sides use quinn crate, wire-compatible.
run_test test_quic_rust_to_rust
# QUIC Go↔Rust: multi-stream-per-connection enabled.
# Go frp v0.70.1 uses quic-go (multi-stream), Rust accepts additional streams.
# Go frp v0.70.1+ pre-built binaries work with release Rust build.
run_test test_g2r_quic
run_test test_r2g_quic
run_test test_g2r_quic_multi_proxy
run_test test_g2r_quic_encrypted
run_test test_r2g_quic_encrypted

# Phase 9: V2 wire protocol
# Go frp v0.70.1+ pre-built binaries include V2 protocol support.
# Both g2r and r2g V2 tests use the pre-built binary.
if ensure_go_frp_v2; then
    run_test test_g2r_v2_tcp
    run_test test_r2g_v2_tcp
else
    log "SKIP V2 tests: Go frp pre-built binary does not support V2"
fi

# Phase 10: SSH Gateway compat
run_test test_ssh_gateway_banner
run_test test_ssh_gateway_auth_rejection
run_test test_ssh_gateway_go_frps_compat

fi

# --- Summary ---
echo ""
echo "============================================="
echo -e " RESULTS: ${GREEN}$PASS passed${NC}, ${RED}$FAIL failed${NC}"
echo "============================================="

if [[ $FAIL -gt 0 ]]; then
    echo ""
    echo "Failures:"
    for f in "${FAILURES[@]}"; do
        echo -e "  ${RED}✗${NC} $f"
    done
    exit 1
else
    echo ""
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
fi
