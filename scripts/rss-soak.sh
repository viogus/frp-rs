#!/usr/bin/env bash
# =============================================================================
# frp-rs RSS soak: a head-to-head resident-memory time series, frp-rs vs Go frp.
#
# Answers the TODO item "The 'no GC => stable RSS over weeks' claim has no
# long-uptime evidence". Both stacks run CONCURRENTLY with the same proxy set
# and the same traffic recipe for the whole window, and RSS is sampled for all
# four processes every `interval` seconds. No process is restarted mid-run; if
# one dies, or if either side's traffic moved nothing, the series is marked
# aborted instead of silently published.
#
# What the numbers DO show:
#   * how each implementation's RSS moves over hours under identical, paced
#     offered load on one host, sampled side by side.
# What they DO NOT show:
#   * RSS is not live heap. It includes allocator retention, page-fault and
#     page-cache effects, and memory the OS has not reclaimed yet; a flat RSS
#     is consistent with both "no leak" and "allocator never returned memory".
#   * weeks. A multi-hour window bounds growth over hours, not over weeks —
#     the claim it tests is directional, and the positioning docs must not be
#     stronger than the window.
#   * an isolated stack. Both stacks share the host, so a machine-level effect
#     (thermal, memory pressure, another tenant) moves BOTH series; running
#     them concurrently is what makes that a shared, not a differential,
#     confound, and host load is logged on every sample so a reader can see it.
#   * full proxy surface. One TCP proxy per stack; UDP/HTTP/STCP/XTCP and the
#     encryption/compression/mux paths are not exercised here.
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
#   SOAK_OUT              artifact path (default scripts/frp-stress/baselines/
#                         rss-soak-<host>.jsonl). Set it for a throwaway
#                         validation run so a real soak's artifact is not
#                         clobbered.
#   SOAK_RUN_DIR          scratch dir for configs/logs (default /tmp/rss-soak)
#   SOAK_CHURN_CONNS      short-lived connections in flight (default 8)
#   SOAK_CHURN_RATE       churn connection starts/s per stack (default 40;
#                         0 = unpaced, which will exhaust ephemeral ports).
#                         Keep this modest: every closed connection parks
#                         sockets in TIME_WAIT for ~30 s on macOS, so the
#                         rate x TIME_WAIT x 2 stacks must stay well inside
#                         the 16 384-port ephemeral range. The per-sample
#                         `time_wait` count is the check.
#   SOAK_STREAMS          long-lived byte streams per stack (default 3)
#   SOAK_STREAM_MBPS      per-stream cap in MB/s (default 5; 0 = unpaced)
#   SOAK_MSG_BYTES        bytes per churn message (default 64)
#
# Output: scripts/frp-stress/baselines/rss-soak-<hostname>.jsonl
#   one JSON object per line: one `meta` record, N `sample` records, one
#   `summary` record. The summary is also printed to stdout. An artifact
#   WITHOUT a trailing `summary` record is an incomplete (aborted) run.
#
# Guards (abort rather than publish an apples-to-oranges series):
#   * only one soak runs at a time (lock file), so a short validation run
#     cannot steal the ports of, or overwrite the artifact of, a live soak
#   * the Go binaries are for THIS os/arch (checked with `file`)
#   * the Go binaries self-report the version frp-rs targets (`--version`)
#   * the frp-rs binaries self-report that same version
#   * a pre-flight churn on each side must complete at least one echo round
#     trip before the window opens — a bridge that accepts but moves no bytes
#     fails here rather than after three hours
#   * any of the four frp processes, the two echo backends or the six traffic
#     generators dying mid-window aborts the series
#   * after the window, each side must have completed churn round trips and
#     moved bytes on its long-lived streams
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
CHURN_RATE="${SOAK_CHURN_RATE:-40}"
STREAMS="${SOAK_STREAMS:-3}"
STREAM_MBPS="${SOAK_STREAM_MBPS:-5}"
MSG_BYTES="${SOAK_MSG_BYTES:-64}"
OUT="${SOAK_OUT:-scripts/frp-stress/baselines/rss-soak-$(hostname -s).jsonl}"
RUN_DIR="${SOAK_RUN_DIR:-/tmp/rss-soak}"
LOCK_FILE="/tmp/rss-soak.lock"

# ------------------------------------------------------------ one soak only
# Two soaks would fight over the fixed ports and the last writer would own the
# artifact. A stale lock from a SIGKILLed run is reclaimed, a live one is not.
if [ -f "$LOCK_FILE" ]; then
  old_lock=$(cat "$LOCK_FILE" 2>/dev/null || true)
  if [ -n "$old_lock" ] && kill -0 "$old_lock" 2>/dev/null; then
    echo "error: another rss-soak is already running (pid $old_lock)." >&2
    echo "       Refusing to start; stop it or remove $LOCK_FILE if it is stale." >&2
    exit 1
  fi
  echo "warning: reclaiming stale lock $LOCK_FILE (pid ${old_lock:-unknown} is gone)" >&2
fi
echo $$ > "$LOCK_FILE"

mkdir -p "$RUN_DIR"
mkdir -p "$(dirname "$OUT")"

FRP_NAMES=(); FRP_PIDS=()
GEN_NAMES=(); GEN_PIDS=()
ALL_PIDS=()
add_frp() { FRP_NAMES+=("$1"); FRP_PIDS+=("$2"); ALL_PIDS+=("$2"); }
add_gen() { GEN_NAMES+=("$1"); GEN_PIDS+=("$2"); ALL_PIDS+=("$2"); }

cleanup() {
  local p
  for p in "${ALL_PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null; done
  sleep 1
  for p in "${ALL_PIDS[@]:-}"; do [ -n "$p" ] && kill -9 "$p" 2>/dev/null; done
  if [ -f "$LOCK_FILE" ] && [ "$(cat "$LOCK_FILE" 2>/dev/null || true)" = "$$" ]; then
    rm -f "$LOCK_FILE"
  fi
  return 0
}

# SIGINT/SIGTERM are handled so the loop can stop, write an aborted summary and
# still leave no orphan processes (the EXIT trap runs on normal exit and after
# the signal handler returns). A second signal exits immediately.
SIGNALLED=0
on_signal() {
  if [ "$SIGNALLED" = 1 ]; then
    echo "second signal: exiting immediately" >&2
    exit 130
  fi
  SIGNALLED=1
  echo "signal received: stopping after this iteration" >&2
}
trap cleanup EXIT
trap on_signal INT TERM

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

# Binary digests so a later reader can tell exactly which builds produced the
# series (the version guard alone cannot distinguish two builds of 0.71.0).
sha256_of() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" 2>/dev/null | cut -d' ' -f1
  elif command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" 2>/dev/null | cut -d' ' -f1
  else
    echo "unavailable"
  fi
}

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

alive() { kill -0 "$1" 2>/dev/null; }

# port_open <host:port> -> 0 when a TCP connect succeeds (proxy registered).
port_open() { (exec 3<>"/dev/tcp/${1%:*}/${1#*:}") 2>/dev/null; }

# RSS in KB, or the JSON literal `null` when the process is momentarily
# unreadable. Emitting an empty string here would corrupt the JSONL line and
# make the whole published artifact unparseable.
rss_kb() {
  local v
  v=$(ps -o rss= -p "$1" 2>/dev/null | tr -d ' ')
  if [ -z "$v" ]; then printf 'null'; else printf '%s' "$v"; fi
}
load1() {
  local v
  v=$(uptime | sed -E 's/.*load average[s]?: ([0-9.]+).*/\1/')
  case "$v" in
    [0-9]*) printf '%s' "$v" ;;
    *) printf 'null' ;;
  esac
}
time_wait_count() {
  local n
  n=$(netstat -an -p tcp 2>/dev/null | grep -c TIME_WAIT || true)
  printf '%s' "${n:-0}"
}

# json_field <file> <key> -> value or 0. Used to read a generator's result row.
json_field() {
  python3 -c 'import json,sys
try:
    print(json.load(open(sys.argv[1]))[sys.argv[2]])
except Exception:
    print(0)' "$1" "$2" 2>/dev/null || echo 0
}

# ---------------------------------------------------------------- stand up
"$STRESS" --scenario echo --port "$RS_ECHO" >"$RUN_DIR/rs-echo.log" 2>&1 & add_gen "rs-echo" $!
"$STRESS" --scenario echo --port "$GO_ECHO" >"$RUN_DIR/go-echo.log" 2>&1 & add_gen "go-echo" $!
sleep 1

"$RS_FRPS" -c "$RUN_DIR/rs-frps.toml" >"$RUN_DIR/rs-frps.log" 2>&1 & add_frp "frp-rs-frps" $!
"$GO_FRPS" -c "$RUN_DIR/go-frps.toml" >"$RUN_DIR/go-frps.log" 2>&1 & add_frp "go-frps" $!
sleep 1
"$RS_FRPC" -c "$RUN_DIR/rs-frpc.toml" >"$RUN_DIR/rs-frpc.log" 2>&1 & add_frp "frp-rs-frpc" $!
"$GO_FRPC" -c "$RUN_DIR/go-frpc.toml" >"$RUN_DIR/go-frpc.log" 2>&1 & add_frp "go-frpc" $!

RS_FRPS_PID="${FRP_PIDS[0]}"; GO_FRPS_PID="${FRP_PIDS[1]}"
RS_FRPC_PID="${FRP_PIDS[2]}"; GO_FRPC_PID="${FRP_PIDS[3]}"

for p in "${FRP_PIDS[@]}"; do
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

# --------------------------------------------------- pre-flight data check
# Registration proves a listener exists, not that bytes cross the bridge. A
# half-open bridge would otherwise produce a beautiful flat RSS series.
preflight() {
  local stack="$1" remote="$2" ctrl="$3"
  local file="$RUN_DIR/$stack-preflight.json"
  rm -f "$file"
  "$STRESS" --scenario memory --mode churn --port "$remote" --frps-addr "127.0.0.1:$ctrl" \
    --concurrency 2 --rate 50 --duration 3 --msg-bytes "$MSG_BYTES" --label "preflight-$stack" \
    --json-out "$file" --json-truncate >"$RUN_DIR/$stack-preflight.log" 2>&1 || true
  local rt
  rt=$(json_field "$file" round_trips)
  echo "pre-flight $stack: $rt echo round trips"
  [ "${rt:-0}" -gt 0 ] 2>/dev/null
}
preflight rs "$RS_REMOTE" "$RS_PORT" \
  || { echo "error: frp-rs bridge moved no bytes during pre-flight (see $RUN_DIR/rs-preflight.log)" >&2; exit 1; }
preflight go "$GO_REMOTE" "$GO_PORT" \
  || { echo "error: Go bridge moved no bytes during pre-flight (see $RUN_DIR/go-preflight.log)" >&2; exit 1; }
echo "pre-flight OK: both bridges completed echo round trips"

# ---------------------------------------------------------------- traffic
# Identical recipe on both sides: paced short-lived connection churn plus a few
# long-lived, rate-capped byte streams for the whole window. The churn rate is
# fixed per stack so both are OFFERED the same connections/second; the achieved
# round trips are recorded per side so a reader can check that both accepted it.
traffic() {
  local stack="$1" remote="$2" ctrl="$3"
  "$STRESS" --scenario memory --mode churn --port "$remote" --frps-addr "127.0.0.1:$ctrl" \
    --concurrency "$CHURN_CONNS" --rate "$CHURN_RATE" --duration "$DURATION" --msg-bytes "$MSG_BYTES" \
    --label "soak-churn-$stack" --json-out "$RUN_DIR/$stack-churn.json" --json-truncate \
    >"$RUN_DIR/$stack-churn.log" 2>&1 & add_gen "$stack-churn" $!
  "$STRESS" --scenario throughput --port "$remote" --frps-addr "127.0.0.1:$ctrl" \
    --streams "$STREAMS" --mbps "$STREAM_MBPS" --duration "$DURATION" --label "soak-steady-$stack" --no-floor \
    --json-out "$RUN_DIR/$stack-steady.json" --json-truncate \
    >"$RUN_DIR/$stack-steady.log" 2>&1 & add_gen "$stack-steady" $!
}
traffic rs "$RS_REMOTE" "$RS_PORT"
traffic go "$GO_REMOTE" "$GO_PORT"
sleep 2

# ---------------------------------------------------------------- sample
rm -f "$OUT"
start_epoch=$(date +%s)
start_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)
started_load=$(load1)
printf '{"kind":"meta","started_utc":"%s","duration_s":%s,"interval_s":%s,"host":"%s","platform":"%s","cpu_cores":%s,"frp_rs_version":"%s","frp_rs_sha":"%s","go_frp_version":"%s","go_frp_dir":"%s","rs_bin":"%s","rs_frpc_bin":"%s","traffic":{"churn_connections":%s,"churn_rate_per_stack":%s,"churn_msg_bytes":%s,"steady_streams":%s,"steady_mbps_per_stream":%s,"generator":"frp-stress","proxy_type":"tcp"},"ports":{"rs_control":%s,"rs_remote":%s,"rs_echo":%s,"go_control":%s,"go_remote":%s,"go_echo":%s},"bin_sha256":{"rs_frps":"%s","rs_frpc":"%s","go_frps":"%s","go_frpc":"%s"},"load1_start":%s,"caveats":["RSS is not live heap; it includes allocator retention and page-cache effects","both stacks share this host, so a machine-level effect moves both series","identical offered recipe, not guaranteed identical achieved volume; achieved round trips are recorded in the traffic summary","one TCP proxy per stack; other proxy types and encryption/compression/mux paths are not exercised"]}\n' \
  "$start_utc" "$DURATION" "$INTERVAL" "$(hostname -s)" "$go_platform" "$cpu_cores" \
  "$rs_version" "$rs_sha" "$go_version" "$GO_DIR" "$RS_FRPS" "$RS_FRPC" \
  "$CHURN_CONNS" "$CHURN_RATE" "$MSG_BYTES" "$STREAMS" "$STREAM_MBPS" \
  "$RS_PORT" "$RS_REMOTE" "$RS_ECHO" "$GO_PORT" "$GO_REMOTE" "$GO_ECHO" \
  "$(sha256_of "$RS_FRPS")" "$(sha256_of "$RS_FRPC")" "$(sha256_of "$GO_FRPS")" "$(sha256_of "$GO_FRPC")" \
  "$started_load" >> "$OUT"

echo "=== soak running: $(date -u +%H:%M:%SZ), load1=$started_load ==="
aborted=""
samples=0
# Generators stop on their own at ~duration-2 s; only their EARLY death is a
# fault, hence the grace window on the generator check.
generator_check_until=$(( DURATION - INTERVAL - 5 ))
while :; do
  if [ "$SIGNALLED" = 1 ]; then
    aborted="interrupted by signal (SIGINT/SIGTERM)"
    break
  fi
  elapsed=$(( $(date +%s) - start_epoch ))
  if [ "$elapsed" -ge "$DURATION" ]; then break; fi

  # Report HOW each dead process died, not just that it is gone: `wait` still
  # yields the remembered status of a child bash has reaped, and 128+N vs a
  # small code separates "someone sent a signal" from "the process exited".
  dead=""
  for i in "${!FRP_PIDS[@]}"; do
    p="${FRP_PIDS[$i]}"
    if ! alive "$p"; then
      wait "$p" 2>/dev/null
      st=$?
      if [ "$st" = 127 ]; then dead="${dead}${FRP_NAMES[$i]} "
      else dead="${dead}${FRP_NAMES[$i]}(exit $st) "; fi
    fi
  done
  if [ "$elapsed" -lt "$generator_check_until" ]; then
    for i in "${!GEN_PIDS[@]}"; do
      p="${GEN_PIDS[$i]}"
      if ! alive "$p"; then
        wait "$p" 2>/dev/null
        st=$?
        if [ "$st" = 127 ]; then dead="${dead}${GEN_NAMES[$i]} "
        else dead="${dead}${GEN_NAMES[$i]}(exit $st) "; fi
      fi
    done
  fi
  if [ -n "$dead" ]; then
    aborted="process died at ${elapsed}s: ${dead}"
    echo "error: $aborted" >&2
    break
  fi

  printf '{"kind":"sample","elapsed_s":%s,"ts":"%s","load1":%s,"time_wait":%s,"frp_rs_frps_kb":%s,"frp_rs_frpc_kb":%s,"go_frps_kb":%s,"go_frpc_kb":%s}\n' \
    "$elapsed" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$(load1)" "$(time_wait_count)" \
    "$(rss_kb "$RS_FRPS_PID")" "$(rss_kb "$RS_FRPC_PID")" \
    "$(rss_kb "$GO_FRPS_PID")" "$(rss_kb "$GO_FRPC_PID")" >> "$OUT"
  samples=$((samples + 1))
  sleep "$INTERVAL"
done

# ---------------------------------------------------------------- teardown
cleanup
trap - EXIT INT TERM

summary_rc=0
python3 - "$OUT" "$aborted" "$RUN_DIR/rs-churn.json" "$RUN_DIR/go-churn.json" \
  "$RUN_DIR/rs-steady.json" "$RUN_DIR/go-steady.json" <<'PY' || summary_rc=$?
import json, statistics, sys

path, aborted = sys.argv[1], sys.argv[2]
traffic_paths = {
    "frp_rs_churn": sys.argv[3],
    "go_churn": sys.argv[4],
    "frp_rs_steady": sys.argv[5],
    "go_steady": sys.argv[6],
}

def load_json(p):
    try:
        with open(p) as fh:
            lines = [l for l in fh.read().splitlines() if l.strip()]
        return json.loads(lines[-1]) if lines else None
    except Exception:
        return None

rows = []
with open(path) as fh:
    for line in fh:
        line = line.strip()
        if line:
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                pass
samples = [r for r in rows if r.get("kind") == "sample"]
meta = next((r for r in rows if r.get("kind") == "meta"), {})
# Window for the first/last-hour means. max(1, ...) keeps the slice non-empty
# when the sample interval is itself an hour or longer (fmean([]) would raise).
window = max(1, 3600 // max(1, int(meta.get("interval_s") or 45)))
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
        "first_hour_mean": round(statistics.fmean(vals[:window]), 1),
        "last_hour_mean": round(statistics.fmean(vals[-window:]), 1),
        "growth_pct_first_to_last": round(100.0 * (vals[-1] - vals[0]) / vals[0], 1) if vals[0] else None,
    }

data = {
    key: block([r.get(key) for r in samples if r.get(key) is not None])
    for key, _ in cols
}
loads = [r.get("load1") for r in samples if r.get("load1") is not None]
waits = [r.get("time_wait") for r in samples if r.get("time_wait") is not None]

traffic = {}
for name, p in traffic_paths.items():
    d = load_json(p)
    if d:
        traffic[name] = {
            "connections": d.get("connections"),
            "round_trips": d.get("round_trips"),
            "bytes": d.get("bytes"),
            "total_bytes": d.get("total_bytes"),
            "mbps": d.get("mbps"),
        }
    else:
        traffic[name] = None

# A flat RSS line only means something if load was actually delivered on BOTH
# sides. Refuse to stamp a series whose traffic evidence is missing or zero.
if not aborted:
    problems = []
    for key, label in (("frp_rs_churn", "frp-rs"), ("go_churn", "Go")):
        d = traffic.get(key)
        if not d or not d.get("round_trips"):
            problems.append(f"{label} churn completed no echo round trips")
    for key, label in (("frp_rs_steady", "frp-rs"), ("go_steady", "Go")):
        d = traffic.get(key)
        if not d or not d.get("total_bytes"):
            problems.append(f"{label} steady stream moved no bytes")
    if problems:
        aborted = "insufficient traffic evidence: " + "; ".join(problems)

summary = {
    "kind": "summary",
    "samples": len(samples),
    "aborted": aborted or None,
    "load1": {"min": min(loads), "max": max(loads), "mean": round(statistics.fmean(loads), 2)} if loads else None,
    "time_wait": {"min": min(waits), "max": max(waits), "mean": round(statistics.fmean(waits), 1)} if waits else None,
    "traffic": traffic,
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
if summary["time_wait"]:
    print(f"TIME_WAIT: min {summary['time_wait']['min']} mean {summary['time_wait']['mean']} max {summary['time_wait']['max']}")
for name, d in traffic.items():
    if d:
        print(f"traffic {name}: round_trips={d.get('round_trips')} bytes={d.get('bytes')} "
              f"total_bytes={d.get('total_bytes')} mbps={d.get('mbps')}")
    else:
        print(f"traffic {name}: MISSING")
sys.exit(3 if aborted else 0)
PY

echo "=== soak artifact written: $OUT ($samples samples) ==="
exit "$summary_rc"
