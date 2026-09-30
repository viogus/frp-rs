#!/usr/bin/env bash
# =============================================================================
# frp-rs RSS soak: a head-to-head resident-memory time series, frp-rs vs Go frp.
#
# Answers the TODO item "The 'no GC => stable RSS over weeks' claim has no
# long-uptime evidence". Both stacks run CONCURRENTLY with the same proxy set
# and the same traffic recipe for the whole window, and RSS is sampled for all
# four processes every `interval` seconds. No process is restarted mid-run; if
# one dies the series is marked aborted instead of silently continued.
#
# Why its own script instead of memory-baseline.sh: that baseline is short,
# runs frp-rs only, and its primary metric is the mem-profile allocator counter
# (`live=`/`total=`), which does not exist in Go. RSS is the only metric both
# implementations can report, so the soak measures PLAIN release binaries and
# leaves memory-baseline.sh's non-soak behaviour untouched.
#
# Usage:
#   bash scripts/rss-soak.sh [duration_s] [interval_s]
#     duration_s   soak window; default 10800 (3 h), minimum 60
#     interval_s   sample interval; default 45 (the item asks for 30-60 s)
#
# Env:
#   FRPS_BIN / FRPC_BIN   frp-rs binaries; set both to skip the cargo build
#   GO_FRP_DIR            Go frp release dir (default /tmp/frp_<ver>_<platform>)
#   SOAK_CHURN_CONNS      short-lived connections in flight (default 8)
#   SOAK_STREAMS          long-lived byte streams per stack (default 3)
#   SOAK_MSG_BYTES        bytes per churn message (default 64)
#
# Output: scripts/frp-stress/baselines/rss-soak-<hostname>.jsonl
#   one JSON object per line: one `meta` record, N `sample` records, one
#   `summary` record. The summary is also printed to stdout.
#
# Guards (abort rather than publish an apples-to-oranges series):
#   * the Go binaries are for THIS os/arch (checked with `file`)
#   * the Go binaries self-report the version frp-rs targets (`--version`)
#   * the frp-rs binaries self-report that same version
# =============================================================================
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR" || exit 1

DURATION="${1:-10800}"
INTERVAL="${2:-45}"
if ! [[ "$DURATION" =~ ^[0-9]+$ ]] || [ "$DURATION" -lt 60 ]; then
  echo "error: duration_s must be an integer >= 60 (got '${1:-}')" >&2
  exit 1
fi
if ! [[ "$INTERVAL" =~ ^[0-9]+$ ]] || [ "$INTERVAL" -lt 1 ]; then
  echo "error: interval_s must be an integer >= 1 (got '${2:-}')" >&2
  exit 1
fi

RS_PORT=18100; RS_REMOTE=18101; RS_ECHO=18102
GO_PORT=18200; GO_REMOTE=18201; GO_ECHO=18202
TOKEN="rss-soak-token"
CHURN_CONNS="${SOAK_CHURN_CONNS:-8}"
STREAMS="${SOAK_STREAMS:-3}"
MSG_BYTES="${SOAK_MSG_BYTES:-64}"
OUT="scripts/frp-stress/baselines/rss-soak-$(hostname -s).jsonl"
RUN_DIR=/tmp/rss-soak
mkdir -p "$RUN_DIR"

echo "=== Building the frp-stress traffic generator ==="
(cd scripts/frp-stress && cargo build --release 2>&1 | tail -2)
STRESS=./scripts/frp-stress/target/release/frp-stress

if [ -z "${FRPS_BIN:-}" ] || [ -z "${FRPC_BIN:-}" ]; then
  echo "=== Building plain release frps/frpc (set FRPS_BIN/FRPC_BIN to skip) ==="
  cargo build --release -p frps -p frpc 2>&1 | tail -2
fi
RS_FRPS="${FRPS_BIN:-./target/release/frps}"
RS_FRPC="${FRPC_BIN:-./target/release/frpc}"

# ---------------------------------------------------------------- versions
rs_version=$(grep -m1 'pub const VERSION' frp-core/src/lib.rs | sed -E 's/.*"([^"]+)".*/\1/')
[ -n "$rs_version" ] || { echo "error: could not read VERSION from frp-core/src/lib.rs" >&2; exit 1; }

host_os=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$(uname -m)" in
  x86_64)        host_arch=amd64; file_marker='x86-64|x86_64' ;;
  arm64|aarch64) host_arch=arm64; file_marker='arm64|aarch64' ;;
  *) echo "error: unsupported host architecture: $(uname -m)" >&2; exit 1 ;;
esac
go_platform="${host_os}_${host_arch}"
GO_DIR="${GO_FRP_DIR:-/tmp/frp_${rs_version}_${go_platform}}"
GO_FRPS="$GO_DIR/frps"
GO_FRPC="$GO_DIR/frpc"

if [ ! -x "$GO_FRPS" ] || [ ! -x "$GO_FRPC" ]; then
  echo "error: Go frp binaries not found in $GO_DIR." >&2
  echo "       Fetch them with: bash scripts/download-go-frp.sh $rs_version $go_platform" >&2
  exit 1
fi

for bin in "$RS_FRPS" "$RS_FRPC" "$GO_FRPS" "$GO_FRPC" "$STRESS"; do
  [ -x "$bin" ] || { echo "error: not executable: $bin" >&2; exit 1; }
done

if command -v file >/dev/null 2>&1; then
  go_desc=$(file -b "$GO_FRPS")
  printf '%s' "$go_desc" | grep -Eqi "$file_marker" \
    || { echo "error: Go binary is not for this host ($go_platform): $go_desc" >&2; exit 1; }
fi

go_version=$("$GO_FRPS" --version 2>/dev/null | head -1 | tr -d 'v \r\n')
[ "$go_version" = "$rs_version" ] \
  || { echo "error: Go frp version '$go_version' != frp-rs target '$rs_version'" >&2; exit 1; }
rs_reported=$("$RS_FRPS" --version 2>/dev/null | head -1 | tr -d 'v \r\n')
case "$rs_reported" in
  *"$rs_version"*) ;;
  *) echo "error: $RS_FRPS reports '$rs_reported', expected $rs_version" >&2; exit 1 ;;
esac

rs_sha=$(git -C "$PROJECT_DIR" rev-parse HEAD 2>/dev/null || echo unknown)
rs_sha_short=$(git -C "$PROJECT_DIR" rev-parse --short HEAD 2>/dev/null || echo unknown)
cpu_cores=$(sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo 0)
echo "frp-rs $rs_version ($rs_sha_short) vs Go frp $go_version on $go_platform, ${cpu_cores} cores"
echo "window ${DURATION}s, sample interval ${INTERVAL}s -> out $OUT"

# ---------------------------------------------------------------- configs
# camelCase TOML: Go's native spelling, and frp-rs's compat layer accepts it
# (the same trick scripts/compare-go-frp.sh uses so ONE config pair drives
# both implementations). Same proxy set on both sides; only ports differ.
write_configs() {
  cat > "$RUN_DIR/rs-frps.toml" <<EOF
bindAddr = "127.0.0.1"
bindPort = $RS_PORT
[auth]
method = "token"
token = "$TOKEN"
[log]
level = "error"
EOF
  cat > "$RUN_DIR/rs-frpc.toml" <<EOF
serverAddr = "127.0.0.1"
serverPort = $RS_PORT
loginFailExit = true
[auth]
method = "token"
token = "$TOKEN"
[log]
level = "error"
[[proxies]]
name = "soak-tcp"
type = "tcp"
localIP = "127.0.0.1"
localPort = $RS_ECHO
remotePort = $RS_REMOTE
EOF
  cat > "$RUN_DIR/go-frps.toml" <<EOF
bindAddr = "127.0.0.1"
bindPort = $GO_PORT
[auth]
method = "token"
token = "$TOKEN"
[log]
level = "error"
EOF
  cat > "$RUN_DIR/go-frpc.toml" <<EOF
serverAddr = "127.0.0.1"
serverPort = $GO_PORT
loginFailExit = true
[auth]
method = "token"
token = "$TOKEN"
[log]
level = "error"
[[proxies]]
name = "soak-tcp"
type = "tcp"
localIP = "127.0.0.1"
localPort = $GO_ECHO
remotePort = $GO_REMOTE
EOF
}
write_configs

PIDS=()
cleanup() {
  for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done
  sleep 1
  for p in "${PIDS[@]:-}"; do kill -9 "$p" 2>/dev/null || true; done
}
trap cleanup EXIT

alive() { kill -0 "$1" 2>/dev/null; }

# port_open <host:port> -> 0 when a TCP connect succeeds (proxy registered).
port_open() { (exec 3<>"/dev/tcp/${1%:*}/${1#*:}") 2>/dev/null; }

rss_kb() { ps -o rss= -p "$1" 2>/dev/null | tr -d ' '; }
load1() { uptime | sed -E 's/.*load average[s]?: ([0-9.]+).*/\1/'; }

# ---------------------------------------------------------------- stand up
"$STRESS" --scenario echo --port "$RS_ECHO" >"$RUN_DIR/rs-echo.log" 2>&1 & PIDS+=($!)
"$STRESS" --scenario echo --port "$GO_ECHO" >"$RUN_DIR/go-echo.log" 2>&1 & PIDS+=($!)
sleep 1

"$RS_FRPS" -c "$RUN_DIR/rs-frps.toml" >"$RUN_DIR/rs-frps.log" 2>&1 & RS_FRPS_PID=$!; PIDS+=("$RS_FRPS_PID")
"$GO_FRPS" -c "$RUN_DIR/go-frps.toml" >"$RUN_DIR/go-frps.log" 2>&1 & GO_FRPS_PID=$!; PIDS+=("$GO_FRPS_PID")
sleep 1
"$RS_FRPC" -c "$RUN_DIR/rs-frpc.toml" >"$RUN_DIR/rs-frpc.log" 2>&1 & RS_FRPC_PID=$!; PIDS+=("$RS_FRPC_PID")
"$GO_FRPC" -c "$RUN_DIR/go-frpc.toml" >"$RUN_DIR/go-frpc.log" 2>&1 & GO_FRPC_PID=$!; PIDS+=("$GO_FRPC_PID")

for p in "$RS_FRPS_PID" "$GO_FRPS_PID" "$RS_FRPC_PID" "$GO_FRPC_PID"; do
  alive "$p" || { echo "error: a frps/frpc process exited during startup; see $RUN_DIR/*.log" >&2; exit 1; }
done

# Wait (bounded) for both proxies to register: frps binds the remote port only
# once frpc's login + NewProxy have succeeded.
register_deadline=$(( $(date +%s) + 30 ))
while :; do
  if port_open "127.0.0.1:$RS_REMOTE" && port_open "127.0.0.1:$GO_REMOTE"; then break; fi
  if [ "$(date +%s)" -ge "$register_deadline" ]; then
    echo "error: proxies did not register within 30s (rs=$RS_REMOTE go=$GO_REMOTE)" >&2
    tail -5 "$RUN_DIR/rs-frpc.log" "$RUN_DIR/go-frpc.log" 2>/dev/null >&2
    exit 1
  fi
  sleep 1
done
echo "both proxies registered"

# ---------------------------------------------------------------- traffic
# Identical recipe on both sides: churn (open->1 msg->close) plus a few
# long-lived streams pushing steady bytes for the whole window.
traffic() {
  local stack="$1" remote="$2" ctrl="$3"
  "$STRESS" --scenario memory --mode churn --port "$remote" --frps-addr "127.0.0.1:$ctrl" \
    --concurrency "$CHURN_CONNS" --duration "$DURATION" --msg-bytes "$MSG_BYTES" \
    --label "soak-churn-$stack" >"$RUN_DIR/$stack-churn.log" 2>&1 & PIDS+=($!)
  "$STRESS" --scenario throughput --port "$remote" --frps-addr "127.0.0.1:$ctrl" \
    --streams "$STREAMS" --duration "$DURATION" --label "soak-steady-$stack" --no-floor \
    >"$RUN_DIR/$stack-steady.log" 2>&1 & PIDS+=($!)
}
traffic rs "$RS_REMOTE" "$RS_PORT"
traffic go "$GO_REMOTE" "$GO_PORT"
sleep 2

# ---------------------------------------------------------------- sample
mkdir -p "$(dirname "$OUT")"
rm -f "$OUT"
start_epoch=$(date +%s)
start_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)
started_load=$(load1)
printf '{"kind":"meta","started_utc":"%s","duration_s":%s,"interval_s":%s,"host":"%s","platform":"%s","cpu_cores":%s,"frp_rs_version":"%s","frp_rs_sha":"%s","go_frp_version":"%s","go_frp_dir":"%s","rs_bin":"%s","rs_frpc_bin":"%s","traffic":{"churn_connections":%s,"churn_msg_bytes":%s,"steady_streams":%s,"generator":"frp-stress","proxy_type":"tcp"},"ports":{"rs_control":%s,"rs_remote":%s,"rs_echo":%s,"go_control":%s,"go_remote":%s,"go_echo":%s},"load1_start":%s}\n' \
  "$start_utc" "$DURATION" "$INTERVAL" "$(hostname -s)" "$go_platform" "$cpu_cores" \
  "$rs_version" "$rs_sha" "$go_version" "$GO_DIR" "$RS_FRPS" "$RS_FRPC" \
  "$CHURN_CONNS" "$MSG_BYTES" "$STREAMS" \
  "$RS_PORT" "$RS_REMOTE" "$RS_ECHO" "$GO_PORT" "$GO_REMOTE" "$GO_ECHO" "$started_load" >> "$OUT"

echo "=== soak running: $(date -u +%H:%M:%SZ), load1=$started_load ==="
aborted=""
samples=0
while :; do
  elapsed=$(( $(date +%s) - start_epoch ))
  if [ "$elapsed" -ge "$DURATION" ]; then break; fi

  dead=""
  alive "$RS_FRPS_PID" || dead="${dead}frp-rs-frps "
  alive "$RS_FRPC_PID" || dead="${dead}frp-rs-frpc "
  alive "$GO_FRPS_PID" || dead="${dead}go-frps "
  alive "$GO_FRPC_PID" || dead="${dead}go-frpc "
  if [ -n "$dead" ]; then
    aborted="process died at ${elapsed}s: ${dead}"
    echo "error: $aborted" >&2
    break
  fi

  printf '{"kind":"sample","elapsed_s":%s,"ts":"%s","load1":%s,"frp_rs_frps_kb":%s,"frp_rs_frpc_kb":%s,"go_frps_kb":%s,"go_frpc_kb":%s}\n' \
    "$elapsed" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$(load1)" \
    "$(rss_kb "$RS_FRPS_PID")" "$(rss_kb "$RS_FRPC_PID")" \
    "$(rss_kb "$GO_FRPS_PID")" "$(rss_kb "$GO_FRPC_PID")" >> "$OUT"
  samples=$((samples + 1))
  sleep "$INTERVAL"
done

# ---------------------------------------------------------------- teardown
cleanup
trap - EXIT

summary_rc=0
python3 - "$OUT" "$aborted" <<'PY' || summary_rc=$?
import json, statistics, sys

path, aborted = sys.argv[1], (sys.argv[2] if len(sys.argv) > 2 else "")
rows = [json.loads(l) for l in open(path) if l.strip()]
samples = [r for r in rows if r.get("kind") == "sample"]
meta = next((r for r in rows if r.get("kind") == "meta"), {})
cols = [
    ("frp_rs_frps_kb", "frp-rs frps"),
    ("frp_rs_frpc_kb", "frp-rs frpc"),
    ("go_frps_kb", "Go frps"),
    ("go_frpc_kb", "Go frpc"),
]

def block(vals):
    if not vals:
        return None
    return {
        "first": vals[0], "last": vals[-1], "min": min(vals), "max": max(vals),
        "mean": round(statistics.fmean(vals), 1),
        "first_hour_mean": round(statistics.fmean(vals[:3600 // max(1, meta.get("interval_s", 45))]), 1),
        "last_hour_mean": round(statistics.fmean(vals[-(3600 // max(1, meta.get("interval_s", 45))):]), 1),
        "growth_pct_first_to_last": round(100.0 * (vals[-1] - vals[0]) / vals[0], 1) if vals[0] else None,
    }

data = {key: block([r[key] for r in samples if key in r]) for key, _ in cols}
loads = [r["load1"] for r in samples if "load1" in r]
summary = {
    "kind": "summary",
    "samples": len(samples),
    "aborted": aborted,
    "load1": {"min": min(loads), "max": max(loads), "mean": round(statistics.fmean(loads), 2)} if loads else None,
    "rss_kb": data,
}
with open(path, "a") as fh:
    fh.write(json.dumps(summary, sort_keys=True) + "\n")

print("=== RSS soak summary (KB) ===")
print(f"{'process':<12} {'first':>8} {'last':>8} {'min':>8} {'max':>8} {'mean':>9} {'1st-h mean':>11} {'last-h mean':>12}")
for key, label in cols:
    b = data[key] or {}
    print(f"{label:<12} {b.get('first', 0):>8} {b.get('last', 0):>8} {b.get('min', 0):>8} "
          f"{b.get('max', 0):>8} {b.get('mean', 0):>9} {b.get('first_hour_mean', 0):>11} "
          f"{b.get('last_hour_mean', 0):>12}")
print(f"samples: {len(samples)}; " + (f"ABORTED: {aborted}" if aborted else "run completed"))
if summary["load1"]:
    print(f"host load1: min {summary['load1']['min']} mean {summary['load1']['mean']} max {summary['load1']['max']}")
PY

echo "=== soak artifact written: $OUT ($samples samples) ==="
[ -n "$aborted" ] && exit 1
exit "$summary_rc"
