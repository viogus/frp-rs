#!/usr/bin/env bash
# =============================================================================
# frp-rs memory baseline: per-connection footprint (idle-hold) + allocation
# churn, measured via the mem-profile counting allocator + ps RSS.
# Usage: bash scripts/memory-baseline.sh [connections]
# Output: scripts/frp-stress/baselines/memory-<hostname>.jsonl
#
# frps/frpc are built with --features mem-profile so they emit `MEMPROFILE
# live=.. total=.. allocs=..` to stderr every second. The driver parses those
# logs (allocator counters, the PRIMARY gate) and samples ps RSS (directional).
# =============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

CONNS="${1:-500}"
FRPS_PORT=18000
REMOTE_PORT=18001
ECHO_PORT=18002
TOKEN="memory-token"
OUT="scripts/frp-stress/baselines/memory-$(hostname -s).jsonl"

echo "=== Building the frp-stress harness ==="
(cd scripts/frp-stress && cargo build --release 2>&1 | tail -2)

# frps/frpc default to a mem-profile build of this tree. Set FRPS_BIN/FRPC_BIN to
# measure a different implementation — e.g. a Go frp release — in which case the
# MEMPROFILE allocator counters are absent and are reported as `null` rather than
# 0 (see the block that emits the JSON below).
if [ -z "${FRPS_BIN:-}" ] || [ -z "${FRPC_BIN:-}" ]; then
  echo "=== Building mem-profile binaries (set FRPS_BIN/FRPC_BIN to skip) ==="
  cargo build --release -p frps -p frpc --features mem-profile 2>&1 | tail -2
fi
FRPS="${FRPS_BIN:-./target/release/frps}"
FRPC="${FRPC_BIN:-./target/release/frpc}"
STRESS=./scripts/frp-stress/target/release/frp-stress

for bin in "$FRPS" "$FRPC" "$STRESS"; do
  if [ ! -x "$bin" ]; then
    echo "error: not executable: $bin" >&2
    exit 1
  fi
done

PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT

mkdir -p "$(dirname "$OUT")"
rm -f "$OUT"

# Peak `live=` from a MEMPROFILE log, or 0 if none.
peak_live() { grep -o 'live=[0-9]*' "$1" 2>/dev/null | cut -d= -f2 | sort -n | tail -1 || echo 0; }
# First `live=` (near-startup baseline), or 0.
base_live() { grep -o 'live=[0-9]*' "$1" 2>/dev/null | head -1 | cut -d= -f2 || echo 0; }
# Max `total=` (cumulative allocations), or 0.
max_total() { grep -o 'total=[0-9]*' "$1" 2>/dev/null | cut -d= -f2 | sort -n | tail -1 || echo 0; }

# run_case <label> <mode> <encrypt:true|false>
run_case() {
  local label="$1" mode="$2" enc="$3"
  echo "=== case: $label ($mode, encrypt=$enc, conns=$CONNS) ==="
  {
    echo "bind_addr = \"127.0.0.1\""
    echo "bind_port = $FRPS_PORT"
    echo "[auth]"; echo "method = \"token\""; echo "token = \"$TOKEN\""
    echo "[log]"; echo "level = \"error\""
  } > /tmp/mem-frps.toml
  {
    echo "server_addr = \"127.0.0.1\""
    echo "server_port = $FRPS_PORT"
    echo "token = \"$TOKEN\""
    echo "login_fail_exit = true"
    echo "[[proxies]]"
    echo "name = \"mem-tcp\""
    echo "type = \"tcp\""
    echo "local_ip = \"127.0.0.1\""
    echo "local_port = $ECHO_PORT"
    echo "remote_port = $REMOTE_PORT"
    echo "use_encryption = $enc"
  } > /tmp/mem-frpc.toml

  "$STRESS" --scenario echo --port "$ECHO_PORT" & PIDS+=($!)
  sleep 1
  "$FRPS" -c /tmp/mem-frps.toml 2>/tmp/mem-frps.log & local frps_pid=$!; PIDS+=($frps_pid)
  sleep 1
  "$FRPC" -c /tmp/mem-frpc.toml 2>/tmp/mem-frpc.log & local frpc_pid=$!; PIDS+=($frpc_pid)
  sleep 2

  # Background RSS sampler (directional cross-check).
  : > /tmp/mem-rss.log
  ( while true; do
      local rs; rs=$(ps -o rss= -p "$frps_pid" 2>/dev/null | tr -d ' ')
      local rc; rc=$(ps -o rss= -p "$frpc_pid" 2>/dev/null | tr -d ' ')
      echo "${rs:-0} ${rc:-0}" >> /tmp/mem-rss.log
      sleep 1
    done ) & local sampler=$!; PIDS+=($sampler)

  "$STRESS" --scenario memory --mode "$mode" --port "$REMOTE_PORT" \
    --frps-addr "127.0.0.1:$FRPS_PORT" --concurrency "$CONNS" \
    --duration 15 --msg-bytes 64 --label "$label" || \
    echo "WARNING: memory run '$label' failed" >&2

  sleep 2 # let the 1 Hz emitter capture the peak
  kill "$sampler" 2>/dev/null || true

  local live_idle live_peak total rss_s rss_c per_conn
  rss_s=$(awk 'BEGIN{m=0}{if($1>m)m=$1}END{print m+0}' /tmp/mem-rss.log)
  rss_c=$(awk 'BEGIN{m=0}{if($2>m)m=$2}END{print m+0}' /tmp/mem-rss.log)
  if grep -q 'live=' /tmp/mem-frps.log 2>/dev/null; then
    live_idle=$(base_live /tmp/mem-frps.log)
    live_peak=$(peak_live /tmp/mem-frps.log)
    total=$(max_total /tmp/mem-frps.log)
    if [ "$mode" = "idle_hold" ] && [ "$CONNS" -gt 0 ]; then
      per_conn=$(( (live_peak - live_idle) / CONNS ))
    else
      per_conn=0
    fi
  else
    # No MEMPROFILE output: frps is not a mem-profile build of frp-rs (a plain
    # release build, or a foreign implementation such as Go frp). RSS above is
    # still measured; the allocator counters are *not measured*, so report null
    # rather than 0 — a 0 here would read as "allocates nothing", which is a
    # different and false claim.
    live_idle=null; live_peak=null; total=null; per_conn=null
  fi

  printf '{"label":"%s","mode":"%s","connections":%s,"encrypt":%s,"live_bytes_idle":%s,"live_bytes_peak":%s,"total_alloc":%s,"rss_kb_frps":%s,"rss_kb_frpc":%s,"live_per_conn":%s}\n' \
    "$label" "$mode" "$CONNS" "$enc" "$live_idle" "$live_peak" "$total" "$rss_s" "$rss_c" "$per_conn" >> "$OUT"

  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
  PIDS=()
  sleep 1
}

#         label               mode        encrypt
run_case "idle_plain"        idle_hold   false
run_case "idle_encrypt"      idle_hold   true
run_case "churn_plain"       churn       false
run_case "churn_encrypt"     churn       true

echo "=== memory baseline written: $OUT ==="
cat "$OUT"
