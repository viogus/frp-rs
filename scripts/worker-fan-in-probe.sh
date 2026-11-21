#!/usr/bin/env bash
# Probe for TODO.md § P2 "One session's pipeline migrates between runtime workers":
# does the one-worker fan-in penalty change when a yamux task is in the path?
#
# Arms: tcp_mux ∈ {false, true} × frpc worker_threads ∈ {1, 8}; STREAMS
# connections; REPS reps of DUR seconds. The echo sink and frps keep their
# defaults in every arm — only the client's worker count varies, because that is
# the side the item's trigger is stated on.
#
# Usage: bash scripts/worker-fan-in-probe.sh [STREAMS] [REPS] [DUR]
# Requires: cargo build --release -p frps -p frpc
#           (cd scripts/frp-stress && cargo build --release)
# Numbers and the reading of them: docs/archive/notes/2026-11-21-worker-migration-mux.md
set -uo pipefail
cd "$(git rev-parse --show-toplevel)"
STRESS=./scripts/frp-stress/target/release/frp-stress
FRPS=./target/release/frps
FRPC=./target/release/frpc
TOKEN=disc-token
FRPS_PORT=18700
ECHO_PORT=18701
REMOTE_PORT=18702
DUR=${3:-10}
STREAMS=${1:-8}
PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT

arm() { # <mux> <workers>
  local mux="$1" workers="$2" rep out
  for rep in $(seq 1 "${REPS:-3}"); do
    {
      echo "bind_addr = \"127.0.0.1\""
      echo "bind_port = $FRPS_PORT"
      echo "tcp_mux = $mux"
      echo "[auth]"
      echo "method = \"token\""
      echo "token = \"$TOKEN\""
      echo "[log]"
      echo "level = \"warn\""
    } > /tmp/disc-frps.toml
    {
      echo "server_addr = \"127.0.0.1\""
      echo "server_port = $FRPS_PORT"
      echo "token = \"$TOKEN\""
      echo "login_fail_exit = true"
      echo "pool_count = 1"
      echo "tcp_mux = $mux"
      echo "[transport]"
      echo "worker_threads = $workers"
      echo "[[proxies]]"
      echo "name = \"disc\""
      echo "type = \"tcp\""
      echo "local_ip = \"127.0.0.1\""
      echo "local_port = $ECHO_PORT"
      echo "remote_port = $REMOTE_PORT"
    } > /tmp/disc-frpc.toml

    "$STRESS" --scenario echo --port "$ECHO_PORT" >/dev/null 2>&1 & PIDS+=($!)
    sleep 1
    "$FRPS" -c /tmp/disc-frps.toml >/dev/null 2>&1 & PIDS+=($!)
    sleep 1
    "$FRPC" -c /tmp/disc-frpc.toml >/dev/null 2>&1 & PIDS+=($!)
    sleep 2
    out="/tmp/disc-$mux-$workers-$rep.json"
    "$STRESS" --scenario throughput --port "$REMOTE_PORT" \
      --frps-addr "127.0.0.1:$FRPS_PORT" --token "$TOKEN" \
      --streams "$STREAMS" --duration "$DUR" --label "mux=$mux w=$workers" \
      --no-floor --json-out "$out" >/dev/null 2>&1 || true
    python3 - "$out" <<'PY'
import json,sys
try: d=json.load(open(sys.argv[1]))
except Exception: print("  <no json>"); raise SystemExit
def walk(o):
    if isinstance(o,dict):
        for k,v in o.items():
            if k in ("mbps","throughput_mbps","best_mbps") and isinstance(v,(int,float)): yield float(v)
            yield from walk(v)
    elif isinstance(o,list):
        for v in o: yield from walk(v)
vals=list(walk(d))
print(f"  {sys.argv[1].split('/')[-1]}: mbps={vals}")
PY
    cleanup; PIDS=(); sleep 1
  done
}

for mux in false true; do
  for w in 1 8; do
    echo "=== tcp_mux=$mux workers=$w streams=$STREAMS"
    arm "$mux" "$w"
  done
done
