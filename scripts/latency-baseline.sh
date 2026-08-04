#!/usr/bin/env bash
# =============================================================================
# frp-rs latency baseline: steady-state RTT + connection-setup percentiles.
# Usage: bash scripts/latency-baseline.sh [samples]
# Output: scripts/frp-stress/baselines/latency-<hostname>.jsonl
#
# Numbers are host-specific. Regenerate before an L-item change and diff after;
# any config whose p99 regresses rejects the change. The nodelay win shows up
# as a large steady-mode p99/max drop once L1 lands.
# =============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

SAMPLES="${1:-2000}"
FRPS_PORT=18000
REMOTE_PORT=18001
ECHO_PORT=18002
TOKEN="latency-token"
OUT="scripts/frp-stress/baselines/latency-$(hostname -s).jsonl"

echo "=== Building release binaries ==="
cargo build --release -p frps -p frpc 2>&1 | tail -2
(cd scripts/frp-stress && cargo build --release 2>&1 | tail -2)

FRPS=./target/release/frps
FRPC=./target/release/frpc
STRESS=./scripts/frp-stress/target/release/frp-stress

PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT

mkdir -p "$(dirname "$OUT")"
rm -f "$OUT"

# run_case <label> <mode> <pool_count>
run_case() {
  local label="$1" mode="$2" pool="$3"
  echo "=== case: $label ($mode, pool=$pool) ==="
  {
    echo "bind_addr = \"127.0.0.1\""
    echo "bind_port = $FRPS_PORT"
    echo "[auth]"; echo "method = \"token\""; echo "token = \"$TOKEN\""
    echo "[log]"; echo "level = \"warn\""
  } > /tmp/lat-frps.toml
  {
    echo "server_addr = \"127.0.0.1\""
    echo "server_port = $FRPS_PORT"
    echo "token = \"$TOKEN\""
    echo "login_fail_exit = true"
    echo "pool_count = $pool"
    echo "[[proxies]]"
    echo "name = \"lat-tcp\""
    echo "type = \"tcp\""
    echo "local_ip = \"127.0.0.1\""
    echo "local_port = $ECHO_PORT"
    echo "remote_port = $REMOTE_PORT"
  } > /tmp/lat-frpc.toml

  "$STRESS" --scenario echo --port "$ECHO_PORT" & PIDS+=($!)
  sleep 1
  "$FRPS" -c /tmp/lat-frps.toml & PIDS+=($!)
  sleep 1
  "$FRPC" -c /tmp/lat-frpc.toml & PIDS+=($!)
  # Wait for proxy registration: frps binds remote_port only after the
  # proxy registers, so a connectable port means the pipeline is ready.
  local ready=0
  for i in $(seq 1 10); do
    if python3 -c "
import socket
try:
    s = socket.create_connection(('127.0.0.1', 18001), timeout=0.3); s.close(); exit(0)
except Exception: exit(1)
" 2>/dev/null; then ready=1; break; fi
    sleep 1
  done
  if [ "$ready" != "1" ]; then echo "WARN: proxy port 18001 not ready after 10s"; fi
  sleep 1

  rc=0
  "$STRESS" --scenario latency --mode "$mode" --port "$REMOTE_PORT" \
    --frps-addr "127.0.0.1:$FRPS_PORT" \
    --samples "$SAMPLES" --msg-bytes 64 --label "$label" --json-out "$OUT" || rc=$?
  if [ "$rc" -ne 0 ]; then
    echo "WARNING: latency run for '$label' failed (exit code $rc)" >&2
  fi

  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
  PIDS=()
  sleep 1
}

#         label              mode     pool
run_case "steady"           steady   1
run_case "setup_cold"       setup    0
run_case "setup_warm"       setup    4

echo "=== latency baseline written: $OUT ==="
cat "$OUT"
