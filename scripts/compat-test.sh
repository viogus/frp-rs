#!/usr/bin/env bash
# =============================================================================
# frp-rs Cross-Compatibility Test Suite
# Tests Go frp v0.69.1 <-> Rust frp-rs interoperability
# =============================================================================
set -euo pipefail

# --- Paths ---
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
GO_FRP_DIR="/tmp/frp_0.69.1_darwin_arm64"
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
PIDS=""

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# --- Parse args ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        --test) SELECTED_TEST="$2"; shift 2 ;;
        --verbose|-v) VERBOSE=true; shift ;;
        --keep-tmp) KEEP_TMP=true; shift ;;
        --help|-h)
            echo "Usage: $0 [--test <name>] [--verbose] [--keep-tmp]"
            echo "  --test <name>   Run only the named test"
            echo "  --verbose        Show full logs on failure"
            echo "  --keep-tmp       Don't clean up test directory"
            exit 0
            ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
done

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

cleanup() {
    for pid in $PIDS; do
        kill "$pid" 2>/dev/null || true
    done
    if ! $KEEP_TMP; then
        rm -rf "$TEST_DIR"
    fi
}
trap cleanup EXIT

random_port() {
    # Find an unused port in range
    local port
    while true; do
        port=$(( (RANDOM % 10000) + 17000 ))
        if ! lsof -iTCP:$port -sTCP:LISTEN 2>/dev/null | grep -q LISTEN; then
            echo "$port"
            return
        fi
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
    while true; do
        if lsof -nP -iTCP@"$host":"$port" -sTCP:LISTEN -t >/dev/null 2>&1; then
            return 0
        fi
        if [[ $(date +%s) -gt $deadline ]]; then
            return 1
        fi
        sleep 0.1
    done
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
import socket, sys
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
        conn.close()
    except:
        break
" &
    track_pid $!
}

send_and_expect() {
    local port="$1" data="$2" expected="$3" timeout="${4:-5}"
    python3 -c "
import socket, sys, time
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout($timeout)
deadline = time.time() + $timeout
while True:
    try:
        s.connect(('127.0.0.1', $port))
        break
    except (ConnectionRefusedError, OSError):
        if time.time() > deadline:
            print('FAIL:CONNECT_TIMEOUT')
            sys.exit(0)
        time.sleep(0.1)
try:
    s.sendall('$data'.encode())
    reply = s.recv(4096).decode()
    if reply == '$expected':
        print('OK:' + repr(reply))
    else:
        print('FAIL:MISMATCH expected=' + repr('$expected') + ' got=' + repr(reply))
except Exception as e:
    print('FAIL:ERROR ' + str(e))
finally:
    s.close()
" || echo "FAIL:PYTHON_ERROR"
}

# Write config files in the test directory
write_rust_frps_config() {
    local port="$1" token="$2" out="$3"
    local extra="${4:-}"  # optional extra TOML
    cat > "$out" <<TOML
bind_addr = "127.0.0.1"
bind_port = $port

[auth]
method = "token"
token = "$token"

[transport]
tcp_mux = false

$extra
TOML
}

write_rust_frps_config_tls() {
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
tcp_mux = false

$extra
TOML
}

write_go_frps_config() {
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

write_go_frps_config_tls() {
    local port="$1" token="$2" out="$3"
    cat > "$out" <<TOML
bindAddr = "127.0.0.1"
bindPort = $port

auth.method = "token"
auth.token = "$token"

transport.tls.force = true
transport.tls.certFile = "$CERT_DIR/server.crt"
transport.tls.keyFile = "$CERT_DIR/server.key"
transport.tcpMux = false

log.to = "$TEST_DIR/go-frps.log"
log.level = "debug"
TOML
}

write_go_frpc_config() {
    local server_port="$1" token="$2" echo_port="$3" proxy_port="$4" name="$5" out="$6"
    local extra="${7:-}"
    cat > "$out" <<TOML
serverAddr = "127.0.0.1"
serverPort = $server_port

auth.token = "$token"

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

write_go_frpc_config_tls() {
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

write_rust_frpc_config() {
    local server_port="$1" token="$2" echo_port="$3" proxy_port="$4" name="$5" out="$6"
    local extra="${7:-}"
    cat > "$out" <<TOML
server_addr = "127.0.0.1"
server_port = $server_port
token = "$token"
tcp_mux = false
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

write_rust_frpc_config_tls() {
    local server_port="$1" token="$2" echo_port="$3" proxy_port="$4" name="$5" out="$6"
    local extra="${7:-}"
    cat > "$out" <<TOML
server_addr = "127.0.0.1"
server_port = $server_port
token = "$token"
tcp_mux = false
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

log() {
    echo -e "${YELLOW}[LOG]${NC} $*" >&2
}

pass_test() {
    local name="$1"
    echo -e "${GREEN}[PASS]${NC} $name"
    PASS=$((PASS + 1))
}

fail_test() {
    local name="$1" reason="$2"
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

should_run_test() {
    if [[ -z "$SELECTED_TEST" ]]; then
        return 0
    fi
    [[ "$SELECTED_TEST" == "$1" ]]
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
    write_rust_frps_config "$frps_port" "$token" "$TEST_DIR/$name/frps.toml"
    RUST_LOG=info "$RUST_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Rust frps did not start"
        return
    }

    # Start Go frpc
    write_go_frpc_config "$frps_port" "$token" "$echo_port" "$proxy_port" \
        "tcp-plain" "$TEST_DIR/$name/frpc.toml"
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

    write_rust_frps_config "$frps_port" "$token" "$TEST_DIR/$name/frps.toml"
    RUST_LOG=info "$RUST_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Rust frps did not start"
        return
    }

    write_go_frpc_config "$frps_port" "$token" "$echo_port" "$proxy_port" \
        "tcp-enc" "$TEST_DIR/$name/frpc.toml" \
        "transport.useEncryption = true"
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

    write_rust_frps_config_tls "$frps_port" "$token" "$TEST_DIR/$name/frps.toml"
    RUST_LOG=info "$RUST_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Rust frps did not start"
        return
    }

    write_go_frpc_config_tls "$frps_port" "$token" "$echo_port" "$proxy_port" \
        "tcp-tls" "$TEST_DIR/$name/frpc.toml"
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

    write_rust_frps_config_tls "$frps_port" "$token" "$TEST_DIR/$name/frps.toml"
    RUST_LOG=info "$RUST_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Rust frps did not start"
        return
    }

    write_go_frpc_config_tls "$frps_port" "$token" "$echo_port" "$proxy_port" \
        "tcp-tls-enc" "$TEST_DIR/$name/frpc.toml" \
        "transport.useEncryption = true"
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
    write_go_frps_config "$frps_port" "$token" "$TEST_DIR/$name/frps.toml"
    run_go "$GO_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Go frps did not start"
        return
    }

    # Start Rust frpc
    write_rust_frpc_config "$frps_port" "$token" "$echo_port" "$proxy_port" \
        "tcp-plain" "$TEST_DIR/$name/frpc.toml"
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

    write_go_frps_config "$frps_port" "$token" "$TEST_DIR/$name/frps.toml"
    run_go "$GO_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Go frps did not start"
        return
    }

    write_rust_frpc_config "$frps_port" "$token" "$echo_port" "$proxy_port" \
        "tcp-enc" "$TEST_DIR/$name/frpc.toml" \
        "use_encryption = true"
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

    write_go_frps_config_tls "$frps_port" "$token" "$TEST_DIR/$name/frps.toml"
    run_go "$GO_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Go frps did not start"
        return
    }

    write_rust_frpc_config_tls "$frps_port" "$token" "$echo_port" "$proxy_port" \
        "tcp-tls" "$TEST_DIR/$name/frpc.toml"
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

    write_go_frps_config_tls "$frps_port" "$token" "$TEST_DIR/$name/frps.toml"
    run_go "$GO_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Go frps did not start"
        return
    }

    write_rust_frpc_config_tls "$frps_port" "$token" "$echo_port" "$proxy_port" \
        "tcp-tls-enc" "$TEST_DIR/$name/frpc.toml" \
        "use_encryption = true"
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
    python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('127.0.0.1', $echo_port))
while True:
    try:
        data, addr = s.recvfrom(4096)
        s.sendto(data, addr)
    except:
        break
" &
    track_pid $!
    sleep 0.5

    # Start Rust frps
    write_rust_frps_config "$frps_port" "$token" "$TEST_DIR/$name/frps.toml"
    RUST_LOG=info "$RUST_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Rust frps did not start"
        return
    }

    # Start Go frpc with UDP proxy
    cat > "$TEST_DIR/$name/frpc.toml" <<TOML
serverAddr = "127.0.0.1"
serverPort = $frps_port
auth.token = "$token"
transport.tls.enable = false
transport.tcpMux = false
log.to = "$TEST_DIR/go-frpc-$name.log"
log.level = "debug"

[[proxies]]
name = "udp-echo"
type = "udp"
localIP = "127.0.0.1"
localPort = $echo_port
remotePort = $proxy_port
TOML
    run_go "$GO_FRPC" -c "$TEST_DIR/$name/frpc.toml" \
        > "$TEST_DIR/$name/frpc.log" 2>&1 &
    track_pid $!

    sleep 2  # UDP takes a moment to set up

    # Test UDP data round-trip
    local result
    result=$(python3 -c "
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(5)
test_data = b'udp-test-data'
try:
    s.sendto(test_data, ('127.0.0.1', $proxy_port))
    data, addr = s.recvfrom(4096)
    if data == test_data:
        print('OK')
    else:
        print('FAIL:MISMATCH expected=' + repr(test_data) + ' got=' + repr(data))
except Exception as e:
    print('FAIL:ERROR ' + str(e))
finally:
    s.close()
" 2>&1 || echo "FAIL:PYTHON_ERROR")
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
    python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('127.0.0.1', $echo_port))
while True:
    try:
        data, addr = s.recvfrom(4096)
        s.sendto(data, addr)
    except:
        break
" &
    track_pid $!
    sleep 0.5

    # Start Go frps
    write_go_frps_config "$frps_port" "$token" "$TEST_DIR/$name/frps.toml"
    run_go "$GO_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Go frps did not start"
        return
    }

    # Start Rust frpc with UDP proxy
    cat > "$TEST_DIR/$name/frpc.toml" <<TOML
server_addr = "127.0.0.1"
server_port = $frps_port
token = "$token"
tcp_mux = false
login_fail_exit = true
pool_count = 1

[[proxies]]
name = "udp-echo"
type = "udp"
local_ip = "127.0.0.1"
local_port = $echo_port
remote_port = $proxy_port
TOML
    RUST_LOG=info "$RUST_FRPC" -c "$TEST_DIR/$name/frpc.toml" \
        > "$TEST_DIR/$name/frpc.log" 2>&1 &
    track_pid $!

    sleep 2  # UDP takes a moment to set up

    local result
    result=$(python3 -c "
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(5)
test_data = b'r2g-udp-test'
try:
    s.sendto(test_data, ('127.0.0.1', $proxy_port))
    data, addr = s.recvfrom(4096)
    if data == test_data:
        print('OK')
    else:
        print('FAIL:MISMATCH expected=' + repr(test_data) + ' got=' + repr(data))
except Exception as e:
    print('FAIL:ERROR ' + str(e))
finally:
    s.close()
" 2>&1 || echo "FAIL:PYTHON_ERROR")
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
    python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', $echo_port))
s.listen(5)
while True:
    try:
        conn, _ = s.accept()
        data = conn.recv(4096)
        if data:
            # Simple HTTP response echoing request
            body = b'http-ok:' + data.split(b'\r\n\r\n', 1)[-1] if b'\r\n\r\n' in data else b'http-ok'
            conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body)
        conn.close()
    except:
        break
" &
    track_pid $!
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

    sleep 2

    # Send HTTP request through VHost
    local result
    result=$(python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
s.connect(('127.0.0.1', $vhost_port))
req = b'POST /test HTTP/1.1\r\nHost: http-test.local\r\nContent-Length: 5\r\n\r\nhello'
s.sendall(req)
data = s.recv(4096)
s.close()
if b'http-ok:hello' in data:
    print('OK')
else:
    print('FAIL: unexpected response: ' + repr(data[:200]))
" 2>&1)
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
    python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', $echo_port))
s.listen(5)
while True:
    try:
        conn, _ = s.accept()
        data = conn.recv(4096)
        if data:
            body = b'http-ok:' + data.split(b'\r\n\r\n', 1)[-1] if b'\r\n\r\n' in data else b'http-ok'
            conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body)
        conn.close()
    except:
        break
" &
    track_pid $!
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

    sleep 2

    local result
    result=$(python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
s.connect(('127.0.0.1', $vhost_port))
req = b'POST /test HTTP/1.1\r\nHost: http-test.local\r\nContent-Length: 5\r\n\r\nhello'
s.sendall(req)
data = s.recv(4096)
s.close()
if b'http-ok:hello' in data:
    print('OK')
else:
    print('FAIL: unexpected response: ' + repr(data[:200]))
" 2>&1)
    if [[ "$result" == "OK" ]]; then
        pass_test "$name"
    else
        fail_test "$name" "$result"
    fi
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
    write_rust_frps_config "$frps_port" "$token" "$TEST_DIR/$name/frps.toml"
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
    sleep 2

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
    write_go_frps_config "$frps_port" "$token" "$TEST_DIR/$name/frps.toml"
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
    sleep 2

    # Start Rust frpc visitor (STCP visitor)
    cat > "$TEST_DIR/$name/frpc-visitor.toml" <<TOML
server_addr = "127.0.0.1"
server_port = $frps_port
token = "$token"
tcp_mux = false
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

    write_rust_frps_config "$frps_port" "$token" "$TEST_DIR/$name/frps.toml"
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

    write_rust_frps_config "$frps_port" "$token" "$TEST_DIR/$name/frps.toml"
    RUST_LOG=info "$RUST_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Rust frps did not start"
        return
    }

    write_go_frpc_config "$frps_port" "$token" "$echo_port" "$proxy_port" \
        "tcp-comp" "$TEST_DIR/$name/frpc.toml" \
        "transport.useCompression = true"
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
# Main
# =============================================================================

echo "============================================="
echo " frp-rs Cross-Compatibility Test Suite"
echo " Go frp v0.69.1 <-> Rust frp-rs"
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

# --- Run tests ---
# Phase 2: Go frpc -> Rust frps TCP data plane
test_g2r_tcp_plain
test_g2r_tcp_encrypted
test_g2r_tcp_tls
test_g2r_tcp_tls_encrypt

# Phase 3: Rust frpc -> Go frps TCP data plane
test_r2g_tcp_plain
test_r2g_tcp_encrypted
test_r2g_tcp_tls
test_r2g_tcp_tls_encrypt

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

    write_go_frps_config "$frps_port" "$token" "$TEST_DIR/$name/frps.toml"
    run_go "$GO_FRPS" -c "$TEST_DIR/$name/frps.toml" \
        > "$TEST_DIR/$name/frps.log" 2>&1 &
    track_pid $!
    wait_for_port 127.0.0.1 "$frps_port" 5 || {
        fail_test "$name" "Go frps did not start"
        return
    }

    write_rust_frpc_config "$frps_port" "$token" "$echo_port" "$proxy_port" \
        "tcp-comp" "$TEST_DIR/$name/frpc.toml" \
        "use_compression = true"
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

    write_go_frps_config "$frps_port" "$token" "$TEST_DIR/$name/frps.toml"
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
