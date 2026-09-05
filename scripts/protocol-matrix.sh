#!/usr/bin/env bash
# Protocol connectivity matrix: end-to-end data transfer through frps+frpc
# for every transport protocol / TLS / tcp-mux combination.
#
# Each row starts an echo server, frps, and frpc, then runs the frp-stress
# throughput scenario against the proxy port. A row passes iff data moves
# (mbps > 0) — this catches "connects but bridges zero bytes" regressions
# like the WS-over-TLS lost-wakeup stall.
#
# Usage:
#   bash scripts/protocol-matrix.sh [--verbose]
#   FRPS_BIN=/path/to/frps FRPC_BIN=/path/to/frpc bash scripts/protocol-matrix.sh
#
# Defaults to the local release binaries. TLS rows use the committed
# frp-core/tests/certs. Exit code is non-zero if any row fails.
set -u

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
FRPS_BIN="${FRPS_BIN:-$PROJECT_DIR/target/release/frps}"
FRPC_BIN="${FRPC_BIN:-$PROJECT_DIR/target/release/frpc}"
STRESS_BIN="$PROJECT_DIR/scripts/frp-stress/target/release/frp-stress"
CERT_DIR="$PROJECT_DIR/frp-core/tests/certs"
TEST_DIR="/tmp/frp-protocol-matrix"
TOKEN="matrix-token"
VERBOSE=false
[[ "${1:-}" == "--verbose" ]] && VERBOSE=true

PASS=0
FAIL=0
FAILURES=()

log() { echo "[matrix] $*"; }
vlog() { $VERBOSE && echo "[matrix] $*" || true; }

cleanup() {
    # Kill any stragglers from an interrupted run.
    for pid_file in "$TEST_DIR"/*.pid; do
        [[ -f "$pid_file" ]] && kill "$(cat "$pid_file")" 2>/dev/null
    done
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT

wait_for_port() {
    # $1=host $2=port $3=timeout_s — poll with bash /dev/tcp.
    local host="$1" port="$2" timeout="${3:-10}" i
    for ((i = 0; i < timeout * 10; i++)); do
        (exec 3<>"/dev/tcp/$host/$port") 2>/dev/null && {
            exec 3>&- 3<&-
            return 0
        }
        sleep 0.1
    done
    return 1
}

start_echo() {
    local port="$1"
    "$STRESS_BIN" --scenario echo --port "$port" >/dev/null 2>&1 &
    echo $! > "$TEST_DIR/echo-$port.pid"
    sleep 0.5
    wait_for_port 127.0.0.1 "$port" 5
}

# run_row <name> <proto> <tls:on|off> <mux:on|off>
run_row() {
    local name="$1" proto="$2" tls="$3" mux="$4"
    local base
    base=$((19000 + PASS + FAIL)) # unique port block per row
    local srv_port=$((base))
    local proxy_port=$((base + 1))
    local echo_port=$((base + 2))
    local extra_port=$((base + 3))
    local row_dir="$TEST_DIR/$name"
    mkdir -p "$row_dir"

    log "=== $name (proto=$proto tls=$tls mux=$mux) ==="

    start_echo "$echo_port" || {
        fail_row "$name" "echo server did not start"
        return
    }

    # frps config
    {
        printf 'bind_addr = "127.0.0.1"\nbind_port = %s\n' "$srv_port"
        case "$proto" in
            kcp) printf 'kcp_bind_port = %s\n' "$extra_port" ;;
            quic) printf 'quic_bind_port = %s\n' "$extra_port" ;;
        esac
        if [[ "$tls" == "on" ]] || [[ "$proto" == "quic" ]]; then
            printf 'tls_enable = true\n'
            printf 'tls_cert_file = "%s/server.crt"\n' "$CERT_DIR"
            printf 'tls_key_file = "%s/server.key"\n' "$CERT_DIR"
        fi
        printf '\n[auth]\nmethod = "token"\ntoken = "%s"\n\n[transport]\ntcp_mux = %s\n' "$TOKEN" "$([[ "$mux" == "on" ]] && echo true || echo false)"
        printf '[log]\nlevel = "warn"\n'
    } > "$row_dir/frps.toml"

    # frpc config
    {
        printf 'server_addr = "127.0.0.1"\n'
        case "$proto" in
            kcp | quic)
                # KCP/QUIC dial their own bind ports.
                printf 'server_port = %s\n' "$extra_port"
                ;;
            *)
                printf 'server_port = %s\n' "$srv_port"
                ;;
        esac
        printf 'token = "%s"\nlogin_fail_exit = true\npool_count = 1\n' "$TOKEN"
        printf 'tcp_mux = %s\n' "$([[ "$mux" == "on" ]] && echo true || echo false)"
        [[ "$proto" != "tcp" ]] && printf 'transport_protocol = "%s"\n' "$proto"
        if [[ "$tls" == "on" ]] || [[ "$proto" == "quic" ]]; then
            printf 'tls_enable = true\n'
            printf 'tls_ca_file = "%s/ca.crt"\n' "$CERT_DIR"
            printf 'tls_server_name = "localhost"\n'
            printf 'disable_custom_tls_first_byte = true\n'
        else
            printf 'tls_enable = false\n'
        fi
        printf '\n[[proxies]]\nname = "%s"\ntype = "tcp"\nlocal_ip = "127.0.0.1"\n' "$name"
        printf 'local_port = %s\nremote_port = %s\n' "$echo_port" "$proxy_port"
    } > "$row_dir/frpc.toml"

    RUST_LOG=warn "$FRPS_BIN" -c "$row_dir/frps.toml" > "$row_dir/frps.log" 2>&1 &
    echo $! > "$row_dir/frps.pid"
    wait_for_port 127.0.0.1 "$srv_port" 20 || {
        fail_row "$name" "frps did not start"
        return
    }
    RUST_LOG=warn "$FRPC_BIN" -c "$row_dir/frpc.toml" > "$row_dir/frpc.log" 2>&1 &
    echo $! > "$row_dir/frpc.pid"
    # QUIC: the TCP proxy port only opens after the control conn registers.
    # Generous timeout: a contended CI runner (the parallel Tests job is CPU
    # heavy) can take tens of seconds to start frps+frpc, do the TLS
    # handshake, and register the proxy.
    wait_for_port 127.0.0.1 "$proxy_port" 45 || {
        fail_row "$name" "proxy port not reachable"
        return
    }

    local json="$row_dir/result.jsonl"
    local mbps=0 ok=fail attempt
    # Retry the throughput window: a slow frps/frpc warm-up (first work-conn
    # dial + TLS handshake) on a contended runner can leave the first window
    # empty even though the bridge is healthy. Retries cover the warm-up
    # without masking a genuine stall (a real stall stays at zero across all
    # attempts).
    for attempt in 1 2 3; do
        "$STRESS_BIN" --scenario throughput --port "$proxy_port" --duration 5 --streams 1 \
            --label "$name" --no-floor --json-out "$json" >/dev/null 2>&1
        mbps=$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['mbps'])" "$json" 2>/dev/null || echo 0)
        # Bash cannot compare floats — python decides.
        ok=$(python3 -c "import json,sys; print('pass' if json.load(open(sys.argv[1]))['mbps'] > 0 else 'fail')" "$json" 2>/dev/null || echo fail)
        [[ "$ok" == "pass" ]] && break
        log "retry $attempt/3 $name: zero throughput (mbps=$mbps)"
        sleep 3
    done
    if [[ "$ok" == "pass" ]]; then
        PASS=$((PASS + 1))
        log "PASS $name: $mbps MB/s"
    else
        fail_row "$name" "zero throughput (mbps=$mbps)"
        return
    fi

    # Clean up this row's processes.
    kill "$(cat "$row_dir/frpc.pid")" "$(cat "$row_dir/frps.pid")" "$(cat "$TEST_DIR/echo-$echo_port.pid")" 2>/dev/null
    rm -f "$row_dir/frpc.pid" "$row_dir/frps.pid" "$TEST_DIR/echo-$echo_port.pid"
    sleep 0.5
}

fail_row() {
    local name="$1" reason="$2"
    FAIL=$((FAIL + 1))
    FAILURES+=("$name: $reason")
    log "FAIL $name: $reason"
    vlog "  frps log: $TEST_DIR/$name/frps.log"
    vlog "  frpc log: $TEST_DIR/$name/frpc.log"
}

main() {
    [[ -x "$FRPS_BIN" ]] || { echo "frps not found: $FRPS_BIN (build or set FRPS_BIN)"; exit 2; }
    [[ -x "$FRPC_BIN" ]] || { echo "frpc not found: $FRPC_BIN (build or set FRPC_BIN)"; exit 2; }
    [[ -x "$STRESS_BIN" ]] || { echo "frp-stress not found: $STRESS_BIN (cargo build --release -p frp-stress)"; exit 2; }
    for cert in ca.crt server.crt server.key; do
        [[ -f "$CERT_DIR/$cert" ]] || { echo "cert missing: $CERT_DIR/$cert"; exit 2; }
    done
    rm -rf "$TEST_DIR"
    mkdir -p "$TEST_DIR"

    # name            proto       tls   mux
    run_row "tcp-plain"    tcp        off   off
    run_row "tcp-tls"      tcp        on    off
    run_row "tcp-tls-mux"  tcp        on    on
    run_row "ws-plain"     websocket  off   off
    run_row "ws-tls"       websocket  on    off
    run_row "ws-tls-mux"   websocket  on    on
    run_row "wss"          wss        on    off
    run_row "kcp-plain"    kcp        off   off
    run_row "kcp-tls"      kcp        on    off
    run_row "kcp-tls-mux"  kcp        on    on
    run_row "quic"         quic       on    off

    echo
    echo "=== protocol matrix: $PASS passed, $FAIL failed ==="
    for f in "${FAILURES[@]:-}"; do
        [[ -n "$f" ]] && echo "  FAIL: $f"
    done
    [[ $FAIL -eq 0 ]]
}

main
