#!/usr/bin/env bash
# =============================================================================
# frp-rs stress test orchestration.
# Starts frps + frpc, runs frp-stress, collects results.
#
# Usage:
#   bash scripts/stress-test.sh [scenario] [duration] [concurrency]
#
# Gate: STRESS_TEST=1 must be set (CI-only by default).
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

if [[ "${STRESS_TEST:-0}" != "1" ]]; then
    echo "SKIP: STRESS_TEST not set. Set STRESS_TEST=1 to run stress tests."
    exit 0
fi

SCENARIO="${1:-all}"
DURATION="${2:-60}"
CONCURRENCY="${3:-50}"

FRPS_PORT=17000
FRPC_ADMIN_PORT=17400
TOKEN="stress-test-token-$(date +%s)"

cleanup() {
    echo "=== Cleanup ==="
    kill "$FRPS_PID" 2>/dev/null || true
    kill "$FRPC_PID" 2>/dev/null || true
    rm -f /tmp/stress-frps.toml /tmp/stress-frpc.toml
}
trap cleanup EXIT

# Generate configs
cat > /tmp/stress-frps.toml <<EOF
bind_port = $FRPS_PORT

[auth]
method = "token"
token = "$TOKEN"

[log]
level = "warn"
EOF

cat > /tmp/stress-frpc.toml <<EOF
server_addr = "127.0.0.1"
server_port = $FRPS_PORT
token = "$TOKEN"
login_fail_exit = true
tcp_mux = true

[web_server]
addr = "127.0.0.1"
port = $FRPC_ADMIN_PORT

[[proxies]]
name = "stress-tcp"
type = "tcp"
local_ip = "127.0.0.1"
local_port = 22
remote_port = 17001
EOF

# Build
echo "=== Building ==="
cd "$PROJECT_DIR"
mkdir -p .cargo
printf '[profile.release]\nlto = false\nopt-level = 2\n' >> .cargo/config.toml
cargo build --release --bin frps --bin frpc --bin frp-stress 2>&1

# Start frps
echo "=== Starting frps ==="
./target/release/frps -c /tmp/stress-frps.toml &
FRPS_PID=$!
sleep 2

# Verify frps
if ! kill -0 "$FRPS_PID" 2>/dev/null; then
    echo "FATAL: frps failed to start"
    exit 1
fi

# Start frpc
echo "=== Starting frpc ==="
./target/release/frpc -c /tmp/stress-frpc.toml &
FRPC_PID=$!
sleep 3

# Verify frpc
if ! kill -0 "$FRPC_PID" 2>/dev/null; then
    echo "FATAL: frpc failed to start"
    exit 1
fi

# Run stress tests
echo "=== Running scenario: $SCENARIO ==="
./target/release/frp-stress \
    --scenario "$SCENARIO" \
    --duration "$DURATION" \
    --concurrency "$CONCURRENCY" \
    --port 17001 \
    --frps-addr "127.0.0.1:$FRPS_PORT" \
    --token "$TOKEN"

EXIT_CODE=$?

if [[ $EXIT_CODE -eq 0 ]]; then
    echo "=== PASS: $SCENARIO ==="
else
    echo "=== FAIL: $SCENARIO (exit $EXIT_CODE) ==="
fi

exit $EXIT_CODE
