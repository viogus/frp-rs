#!/usr/bin/env bash
# One-way streaming throughput, frp-rs against Go frp, with the CPU time each
# side spends to move the bytes.
#
# Shape: N connections each `write_all` a 64 KiB payload in a loop until the
# deadline and never read back; the peer reads and discards. That is the shape
# a file transfer or a bulk upload has. The ping-pong shape in
# `frp-stress --scenario throughput` is a latency measurement in disguise — it
# reports ~320 MiB/s where this shape reports over 1 GiB/s at one flow — so the
# two are not comparable and both are worth having.
#
# Why CPU as well as MiB/s: this script is meant to be run on a developer
# machine, which is never idle. Wall-clock MiB/s moves by 30% with whatever else
# is running (see `docs/archive/notes/2026-11-21-worker-migration-mux.md` for a
# 5% effect that changed sign on a loaded host), while CPU time per byte is a
# property of the code path. A cell that is slower in MiB/s but spends less CPU
# per byte is losing the wall-clock race to the host, not to the other
# implementation.
#
# Arms are interleaved and the order flips every rep, so host drift smears
# across arms instead of landing on whichever ran last.
#
# Usage: bash scripts/stream-vs-go.sh [REPS] [DUR] [STREAMS]
# Requires: cargo build --release -p frps -p frpc (or point FRPS_BIN/FRPC_BIN
#           at pre-built frp-rs binaries; building into a shared CARGO_TARGET_DIR
#           and exporting the two paths is faster than rebuilding here. The
#           harness path below is fixed: build it in the repo.)
#           (cd scripts/frp-stress && cargo build --release)
#           Go frp binaries in GO_FRP_DIR (default: /tmp/frp_0.72.0_darwin_arm64)
set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 1

STRESS=./scripts/frp-stress/target/release/frp-stress
RUST_FRPS=${FRPS_BIN:-./target/release/frps}
RUST_FRPC=${FRPC_BIN:-./target/release/frpc}
# Go frp binaries: `bash scripts/download-go-frp.sh` puts them under /tmp on
# macOS arm64; point GO_FRP_DIR elsewhere for another platform or download.
GO_DIR=${GO_FRP_DIR:-/tmp/frp_0.72.0_darwin_arm64}
GO_FRPS=$GO_DIR/frps
GO_FRPC=$GO_DIR/frpc
for b in "$STRESS" "$RUST_FRPS" "$RUST_FRPC" "$GO_FRPS" "$GO_FRPC"; do
  [[ -x "$b" ]] || { echo "missing $b — build it first (see the header)" >&2; exit 1; }
done
command -v ps >/dev/null || { echo "missing ps" >&2; exit 1; }
command -v python3 >/dev/null || { echo "missing python3 (used to read the harness JSON)" >&2; exit 1; }

REPS=${1:-3}
DUR=${2:-10}
if (( DUR < 5 )) 2>/dev/null; then
  echo "warning: DUR=$DUR is short — CPU seconds are coarse (1 s on Linux), so" >&2
  echo "         MiB per CPU-second will be noisy; 10 s is the documented run" >&2
fi
STREAMS=${3:-8}
TOKEN=stream-token
FRPS_PORT=${FRPS_PORT:-18900}
SINK_PORT=$((FRPS_PORT + 1))
REMOTE_PORT=$((FRPS_PORT + 2))
WORK=$(mktemp -d "${TMPDIR:-/tmp}/stream-vs-go.XXXXXX")
PIDS=()
FAILED=0
cleanup() {
  for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null; wait "$p" 2>/dev/null; done
  PIDS=()
}
trap 'cleanup; rm -rf "$WORK"' EXIT

# After killing the processes, wait for the port to close. Without this a
# killed frps can still be answering the next arm's wait_port, and that arm
# measures the previous configuration.
wait_port_closed() { # <port> [tries]
  local port="$1" tries="${2:-40}" i=0
  while (( i < tries )); do
    (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null || return 0
    sleep 0.05; i=$((i + 1))
  done
  echo "  ! port $port still open after cleanup" >&2
  return 1
}

wait_port() { # <port> [tries]
  local port="$1" tries="${2:-200}" i=0
  while (( i < tries )); do
    (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null && return 0
    sleep 0.1; i=$((i + 1))
  done
  echo "  ! port $port never opened" >&2
  return 1
}

# CPU seconds a process has used, as a float. macOS `ps -o time=` prints
# `M:SS.ss` (or `D-HH:MM:SS` past a day); Linux prints `HH:MM:SS`.
cpu_seconds() { # <pid>
  local out parts
  out=$(ps -o time= -p "$1" 2>/dev/null | tr -d ' ') || return 1
  [[ -n "$out" ]] || return 1
  out=${out#*-}            # days: not reachable in a 10 s cell, strip anyway
  IFS=: read -r -a parts <<<"$out"
  case ${#parts[@]} in
    3) awk -v h="${parts[0]}" -v m="${parts[1]}" -v s="${parts[2]}" 'BEGIN{printf "%.2f", h*3600+m*60+s}' ;;
    2) awk -v m="${parts[0]}" -v s="${parts[1]}" 'BEGIN{printf "%.2f", m*60+s}' ;;
    *) return 1 ;;
  esac
}

# frp-rs and Go frp spell the same knobs differently in TOML (Go uses
# camelCase keys and `[auth]`, frp-rs accepts both but is written snake_case
# here), so the two configs are written separately rather than templated.
write_configs() { # <impl: rust|go> <mux: true|false>
  local impl="$1" mux="$2"
  if [[ $impl == go ]]; then
    cat >"$WORK/frps.toml" <<EOF
bindAddr = "127.0.0.1"
bindPort = $FRPS_PORT
transport.tcpMux = $mux
[auth]
method = "token"
token = "$TOKEN"
[log]
level = "warn"
EOF
    cat >"$WORK/frpc.toml" <<EOF
serverAddr = "127.0.0.1"
serverPort = $FRPS_PORT
transport.tcpMux = $mux
[auth]
method = "token"
token = "$TOKEN"
[log]
level = "warn"
[[proxies]]
name = "stream"
type = "tcp"
localIP = "127.0.0.1"
localPort = $SINK_PORT
remotePort = $REMOTE_PORT
EOF
  else
    cat >"$WORK/frps.toml" <<EOF
bind_addr = "127.0.0.1"
bind_port = $FRPS_PORT
tcp_mux = $mux
[auth]
method = "token"
token = "$TOKEN"
[log]
level = "warn"
EOF
    cat >"$WORK/frpc.toml" <<EOF
server_addr = "127.0.0.1"
server_port = $FRPS_PORT
tcp_mux = $mux
token = "$TOKEN"
pool_count = 1
[log]
level = "warn"
[[proxies]]
name = "stream"
type = "tcp"
local_ip = "127.0.0.1"
local_port = $SINK_PORT
remote_port = $REMOTE_PORT
EOF
  fi
}

# Colour codes from tracing: strip them with an escape byte that bash and both
# seds agree on (`sed 's/\\x1b…'` is GNU-only and leaves the codes on macOS).
strip_ansi() { # <file>
  local esc esc_re
  esc=$(printf '\033')
  esc_re=$(printf '\033\[[0-9;]*m')
  sed -e "s/${esc_re}//g" -e "s/${esc}//g" "$1"
}

# Kill this arm's processes and make sure their ports are free before the next
# arm starts. Every early return goes through here.
cleanup_arm() {
  cleanup
  wait_port_closed "$SINK_PORT" || true
  wait_port_closed "$FRPS_PORT" || true
  wait_port_closed "$REMOTE_PORT" || true
}

one_rep() { # <impl> <mux> <rep>; prints one line, non-zero on a bad rep
  local impl="$1" mux="$2" rep="$3"
  local out="$WORK/stream-$impl-$mux-$rep.json"
  local frps frpc
  if [[ $impl == go ]]; then frps=$GO_FRPS; frpc=$GO_FRPC; else frps=$RUST_FRPS; frpc=$RUST_FRPC; fi
  write_configs "$impl" "$mux"

  "$STRESS" --scenario sink --port "$SINK_PORT" >/dev/null 2>&1 & PIDS+=("$!")
  wait_port "$SINK_PORT" || { cleanup_arm; return 1; }
  "$frps" -c "$WORK/frps.toml" >"$WORK/frps-$impl-$mux.log" 2>&1 & local sp=$!
  PIDS+=("$sp")
  wait_port "$FRPS_PORT" || { cleanup_arm; return 1; }
  "$frpc" -c "$WORK/frpc.toml" >"$WORK/frpc-$impl-$mux.log" 2>&1 & local cp=$!
  PIDS+=("$cp")
  wait_port "$REMOTE_PORT" || {
    echo "  ! $impl (mux=$mux): the proxy port never opened" >&2
    strip_ansi "$WORK/frpc-$impl-$mux.log" | tail -3 >&2
    cleanup_arm
    return 1
  }
  sleep 0.4
  local s0 c0 s1 c1
  s0=$(cpu_seconds "$sp") && c0=$(cpu_seconds "$cp") || { cleanup_arm; return 1; }
  rm -f "$out"     # the harness APPENDS to --json-out
  "$STRESS" --scenario stream --port "$REMOTE_PORT" --frps-addr "127.0.0.1:$FRPS_PORT" \
    --token "$TOKEN" --streams "$STREAMS" --duration "$DUR" --label "$impl-mux$mux" \
    --no-floor --json-out "$out" >/dev/null 2>&1
  local rc=$?
  s1=$(cpu_seconds "$sp") && c1=$(cpu_seconds "$cp") || { cleanup_arm; return 1; }
  python3 - "$out" "$impl" "$mux" "$rep" "$s0" "$s1" "$c0" "$c1" "$DUR" "$WORK/arm-rates.txt" <<'PY'
import json, sys
path, impl, mux, rep, s0, s1, c0, c1, dur, arms = sys.argv[1:11]
try:
    d = json.load(open(path))
except Exception as exc:                       # the harness wrote nothing
    print(f"{impl:4s} mux={mux:5s} rep{rep} FAILED: {exc}")
    raise SystemExit(1)
mbps = d["mbps"]
failed = d.get("failed_streams", 0)
cpu = (float(s1) - float(s0)) + (float(c1) - float(c0))
if cpu <= 0.01:                 # coarse clocks can round the window to zero
    print(f"{impl:4s} mux={mux:5s} rep{rep} FAILED: cpu window was {cpu:.2f}s")
    raise SystemExit(1)
# MiB moved per CPU-second spent: bytes over the window, not bytes/second over
# CPU-seconds (that would be a rate per rate and off by the window length).
per = mbps * float(dur) / cpu
open(arms, "a").write(f"{mbps}\n")
tag = "" if not failed else f"  FAILED_STREAMS"
print(f"{impl:4s} mux={mux:5s} rep{rep} mbps={mbps:7.1f} cpu_s={cpu:5.2f} "
      f"MiB_per_cpu_s={per:6.1f} failed_streams={failed}{tag}")
raise SystemExit(1 if failed else 0)
PY
  local prc=$?
  cleanup_arm
  return $(( rc | prc ))
}

# Harness ceiling with no frp in the path. An arm reporting more than half of
# this is mis-counting bytes (a doubled counter, or a pre-write increment),
# not moving data faster than loopback.
LOOPBACK=0
loopback_ceiling() {
  local port=$((FRPS_PORT + 3)) out="$WORK/loopback.json"
  "$STRESS" --scenario sink --port "$port" >/dev/null 2>&1 & PIDS+=("$!")
  wait_port "$port" || { cleanup_arm; return 1; }
  rm -f "$out"
  "$STRESS" --scenario stream --port "$port" --streams "$STREAMS" --duration "$DUR" \
    --label loopback --no-floor --json-out "$out" >/dev/null 2>&1 || true
  cleanup_arm
  LOOPBACK=$(python3 -c 'import json,sys; print(int(json.load(open(sys.argv[1]))["mbps"]))' "$out" 2>/dev/null || echo 0)
  echo "loopback ceiling (no frp): ${LOOPBACK} MiB/s"
}

echo "streaming shape: $STREAMS streams, ${DUR}s, 64 KiB writes, one direction"
loopback_ceiling || { echo "could not measure the loopback ceiling" >&2; exit 1; }
for rep in $(seq 1 "$REPS"); do
  echo "--- rep $rep"
  if (( rep % 2 )); then order="rust go"; muxes="false true"; else order="go rust"; muxes="true false"; fi
  for impl in $order; do
    for mux in $muxes; do
      if ! one_rep "$impl" "$mux" "$rep"; then
        echo "  arm $impl mux=$mux rep$rep FAILED (see above)" >&2
        FAILED=1
      fi
    done
  done
done
# Every arm must stay below half the no-frp ceiling: the ceiling is measured on
# the same machine in the same run, so an arm above it is a counting bug, not a
# fast tunnel.
if [[ -s "$WORK/arm-rates.txt" ]] && (( LOOPBACK > 0 )); then
  if ! awk -v l="$LOOPBACK" '{ if ($1 * 2 > l) { printf "  arm rate %.0f MiB/s is over half the no-frp ceiling (%d) — bytes are being miscounted\n", $1, l; bad = 1 } } END { exit bad ? 1 : 0 }' "$WORK/arm-rates.txt"; then
    FAILED=1
  fi
fi
if (( FAILED )); then
  echo "at least one arm failed — the table above is incomplete" >&2
  exit 1
fi
echo "done — compare MiB_per_cpu_s across impls; treat MiB/s as host-dependent"
