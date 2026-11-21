#!/usr/bin/env bash
# Probe for TODO.md § P2 "One session's pipeline migrates between runtime workers":
# does the one-worker fan-in penalty change when a yamux task is in the path?
#
# Arms: tcp_mux ∈ {false, true} × frpc worker_threads ∈ {1, <pool>}; STREAMS
# connections; REPS reps of DUR seconds. The echo sink and frps keep their
# defaults in every arm — only the client's worker count varies, because that is
# the side the item's trigger is stated on.
#
# The arms are interleaved, not blocked: each rep runs the two mux values
# back to back and the order flips every rep, so a host that drifts over the run
# smears across both arms instead of landing on whichever arm came last.
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
for b in "$STRESS" "$FRPS" "$FRPC"; do
  [[ -x "$b" ]] || { echo "missing $b — build it first (see the header)" >&2; exit 1; }
done

TOKEN=probe-token
FRPS_PORT=18700
ECHO_PORT=18701
REMOTE_PORT=18702
STREAMS=${1:-8}
REPS=${2:-3}
DUR=${3:-10}
POOL=${POOL:-8}   # the "pool" arm: frpc runs one runtime thread per CPU by default
WORK=$(mktemp -d "${TMPDIR:-/tmp}/fan-in-probe.XXXXXX")
PIDS=()
cleanup() {
  for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null; wait "$p" 2>/dev/null; done
  PIDS=()
}
trap 'cleanup; rm -rf "$WORK"' EXIT

wait_port() { # <port> [tries]
  local port="$1" tries="${2:-100}" i=0
  while (( i < tries )); do
    (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null && return 0
    sleep 0.1; i=$((i + 1))
  done
  echo "  ! port $port never opened" >&2
  return 1
}

one_rep() { # <mux> <workers> <rep> ; prints one line, exits non-zero on a bad rep
  local mux="$1" workers="$2" rep="$3" out="$WORK/disc-$mux-$workers-$rep.json"
  {
    echo "bind_addr = \"127.0.0.1\""
    echo "bind_port = $FRPS_PORT"
    echo "tcp_mux = $mux"
    echo "[auth]"
    echo "method = \"token\""
    echo "token = \"$TOKEN\""
    echo "[log]"
    echo "level = \"warn\""
  } > "$WORK/frps.toml"
  {
    echo "server_addr = \"127.0.0.1\""
    echo "server_port = $FRPS_PORT"
    echo "token = \"$TOKEN\""
    echo "login_fail_exit = true"
    echo "pool_count = 1"
    echo "tcp_mux = $mux"
    echo "[transport]"
    echo "worker_threads = $workers"
    echo "[log]"
    echo "level = \"warn\""
    echo "[[proxies]]"
    echo "name = \"probe\""
    echo "type = \"tcp\""
    echo "local_ip = \"127.0.0.1\""
    echo "local_port = $ECHO_PORT"
    echo "remote_port = $REMOTE_PORT"
  } > "$WORK/frpc.toml"

  "$STRESS" --scenario echo --port "$ECHO_PORT" >/dev/null 2>&1 & PIDS+=($!)
  wait_port "$ECHO_PORT" || return 1
  "$FRPS" -c "$WORK/frps.toml" >/dev/null 2>&1 & PIDS+=($!)
  wait_port "$FRPS_PORT" || return 1
  "$FRPC" -c "$WORK/frpc.toml" >/dev/null 2>&1 & PIDS+=($!)
  wait_port "$REMOTE_PORT" || return 1

  # --json-out appends when the file exists; a stale rep would then make the
  # parser read two documents (the first version of this probe did exactly that).
  rm -f "$out"
  "$STRESS" --scenario throughput --port "$REMOTE_PORT" \
    --frps-addr "127.0.0.1:$FRPS_PORT" --token "$TOKEN" \
    --streams "$STREAMS" --duration "$DUR" --label "mux=$mux w=$workers" \
    --no-floor --json-out "$out" >/dev/null 2>&1

  local line
  line=$(python3 - "$out" "$mux" "$workers" <<'PY'
import json, sys
path, mux, workers = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    d = json.load(open(path))
except Exception as exc:                      # missing or malformed: a failed rep
    print(f"FAIL mux={mux} w={workers} {exc}")
    raise SystemExit(1)
mbps = d.get("mbps")
failed = d.get("failed_streams")
print(f"mux={mux} w={workers} mbps={mbps:.1f} failed_streams={failed}")
raise SystemExit(1 if (mbps is None or (failed or 0) > 0) else 0)
PY
)
  local rc=$?
  cleanup
  printf '  %s\n' "$line"
  return "$rc"
}

fail=0
for rep in $(seq 1 "$REPS"); do
  if (( rep % 2 == 1 )); then order=(false true); else order=(true false); fi
  for mux in "${order[@]}"; do
    for workers in 1 "$POOL"; do
      echo "=== rep $rep: tcp_mux=$mux workers=$workers streams=$STREAMS dur=${DUR}s"
      one_rep "$mux" "$workers" "$rep" || fail=$((fail + 1))
    done
  done
done

echo "=== ${REPS} reps per cell, $((REPS * 4)) cells run, $fail failed"
exit $(( fail > 0 ))
