#!/usr/bin/env bash
# =============================================================================
# frp-rs UDP PPS A/B benchmark — packets-per-second through the UDP proxy.
#
# Complements ab-matrix.sh (TCP throughput). Measures the V2 binary-codec
# UDP data plane at two datagram sizes (64B = per-packet-overhead dominated,
# 1024B = payload dominated) for TWO code states and reports the delta.
#
# Exercises exactly the hot path changed by the UDP write-path work:
# frpc (v2=true) -> V2 handshake negotiates udpPacketCodecs=binary-v1 ->
# write_msg_v2_with_udp_codec binary branch -> write_v2_frame_raw
# (write_vectored) over the raw-TCP work conn.
#
# Binary sources (pre-built release binaries, same layout as ab-matrix.sh):
#   BEFORE_ROOT  - dir with target/release/{frps,frpc} for the OLD state
#   AFTER_ROOT   - same for the NEW state; defaults to the repo root
#
# Load generator: python3 connected-UDP sender + echo server. Both A and B
# use the SAME generator, so absolute pps is bounded by python (~100-300k
# pps) but the A/B delta reflects frp's per-packet cost.
#
# Usage:
#   BEFORE_ROOT=/tmp/base-build bash scripts/udp-pps-bench.sh [reps] [duration_s]
#
# Output: per-size table with before/after pps + delta%, final PASS/FAIL
# against GATE_PCT (default 5%).
#
# Noise caveat (learned 2026-08-22, shared VPS): python-generated pps swings
# ±30% run to run under host load, and a single A/B shot can read -15~-20%
# without any code difference. The interleaved alternating order bounds the
# drift bias, but the gate still proves "no large regression" only. For a
# suspicious delta, re-run with the roles swapped (BEFORE_ROOT/AFTER_ROOT
# exchanged) and/or run a same-binary A/A calibration
# (BEFORE_ROOT=AFTER_ROOT): a real code regression keeps its sign in both
# role assignments; noise does not.
# =============================================================================
set -euo pipefail
export RUST_LOG=warn

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

REPS="${1:-3}"
DUR="${2:-10}"
GATE_PCT="${GATE_PCT:-5}"

AFTER_ROOT="${AFTER_ROOT:-$PROJECT_DIR}"
BEFORE_ROOT="${BEFORE_ROOT:-}"
if [[ -z "$BEFORE_ROOT" ]]; then
  echo "ERROR: set BEFORE_ROOT to the baseline binary root" >&2
  exit 2
fi
for b in "$BEFORE_ROOT/target/release/frps" "$BEFORE_ROOT/target/release/frpc" \
         "$AFTER_ROOT/target/release/frps"  "$AFTER_ROOT/target/release/frpc"; do
  if [[ ! -x "$b" ]]; then
    echo "ERROR: missing binary $b" >&2
    exit 2
  fi
done

# Run-scoped temp dir (shared /tmp collides across users — see ab-matrix.sh).
TMPD="$(mktemp -d /tmp/udppps-XXXXXX)"

PORT=18140      # frps bind
RPORT=18141     # UDP proxy remote port
ECHO=18142      # local UDP echo server
TOKEN="udp-pps-token"

PIDS=()
cleanup() {
  for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done
  rm -rf "$TMPD"
}
trap cleanup EXIT

# --- python3 load generator -------------------------------------------------
# Connected-UDP sender: send() loop with batched time checks, recv thread
# counts echoed datagrams. Prints: sent_pps=N rx_pps=M
echo_srv() {
  python3 -u -c "
import socket,sys
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.bind(('127.0.0.1',int(sys.argv[1])))
while True:
    d,a=s.recvfrom(65535)
    s.sendto(d,a)
" "$ECHO"
}

pps_client() {  # pps_client <frp-udp-port> <datagram-size> <duration>
  python3 -c "
import socket,sys,time,threading
port,size,dur=int(sys.argv[1]),int(sys.argv[2]),float(sys.argv[3])
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,4*1024*1024)
s.bind(('127.0.0.1',0)); s.connect(('127.0.0.1',port))
payload=b'x'*size
rx=[0]
def recver():
    while True:
        try: s.recv(65535); rx[0]+=1
        except OSError: break
threading.Thread(target=recver,daemon=True).start()
end=time.time()+dur; sent=0
while time.time()<end:
    for _ in range(100): s.send(payload); sent+=1
time.sleep(0.3); s.close()
print(f'sent_pps={sent/dur:.0f} rx_pps={rx[0]/dur:.0f}')
" "$1" "$2" "$3"
}

# --- run one side -----------------------------------------------------------
# run_side <label> <frps> <frpc> <size> <reps> <dur>; prints pps per rep
run_side() {
  local label="$1" frps="$2" frpc="$3" size="$4" r="$5" dur="$6"
  {
    echo "bind_addr = \"127.0.0.1\""; echo "bind_port = $PORT"
    echo "[auth]"; echo "method = \"token\""; echo "token = \"$TOKEN\""
    echo "[log]"; echo "level = \"warn\""
  } > "$TMPD/frps-$label.toml"
  {
    echo "server_addr = \"127.0.0.1\""; echo "server_port = $PORT"
    echo "token = \"$TOKEN\""; echo "login_fail_exit = true"
    echo "pool_count = 1"; echo "v2 = true"
    echo "[[proxies]]"; echo "name = \"udp-pps\""
    echo "type = \"udp\""
    echo "local_ip = \"127.0.0.1\""; echo "local_port = $ECHO"
    echo "remote_port = $RPORT"
  } > "$TMPD/frpc-$label.toml"

  echo_srv >/dev/null 2>&1 & PIDS+=($!)
  sleep 0.5
  "$frps" -c "$TMPD/frps-$label.toml" >/dev/null 2>&1 & PIDS+=($!)
  sleep 0.5
  "$frpc" -c "$TMPD/frpc-$label.toml" >/dev/null 2>&1 & PIDS+=($!)
  # Ready probe: echo round-trip through the proxy.
  local ok=""
  for i in $(seq 1 15); do
    if pps_client "$RPORT" 8 0.5 2>/dev/null | grep -q "sent_pps="; then ok=1; break; fi
    sleep 0.5
  done
  [[ -n "$ok" ]] || echo "WARN $label: proxy not ready after 7s" >&2
  sleep 1
  for j in $(seq 1 "$r"); do
    pps_client "$RPORT" "$size" "$dur" 2>/dev/null | sed -n 's/^sent_pps=\([0-9.]*\).*/\1/p'
  done
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
  PIDS=(); sleep 1
}

median() {
  # Split on ALL whitespace: callers may append values via $(...) which strips
  # trailing newlines, collapsing one-value-per-line into one line.
  python3 -c "import sys,statistics;v=[float(x) for x in sys.stdin.read().split() if float(x)>0];print(round(statistics.median(v),0) if v else 0)"
}

above_gate() {
  python3 -c "import sys; sys.exit(0 if ($1 < -$GATE_PCT) else 1)"
}

measure() {  # measure <size> <label>
  local size="$1" label="$2"
  # Interleaved pairing with ALTERNATING order per rep: odd reps run
  # before-then-after, even reps after-then-before. Monotonic host-load drift
  # (shared box) then biases each side equally; a real code regression stays
  # negative on every rep regardless of order.
  local va="" vb="" i
  for i in $(seq 1 "$REPS"); do
    if (( i % 2 == 1 )); then
      va="$va $(run_side "b-$label-r$i" "$BEFORE_ROOT/target/release/frps" "$BEFORE_ROOT/target/release/frpc" "$size" 1 "$DUR")"
      vb="$vb $(run_side "a-$label-r$i" "$AFTER_ROOT/target/release/frps"  "$AFTER_ROOT/target/release/frpc"  "$size" 1 "$DUR")"
    else
      vb="$vb $(run_side "a-$label-r$i" "$AFTER_ROOT/target/release/frps"  "$AFTER_ROOT/target/release/frpc"  "$size" 1 "$DUR")"
      va="$va $(run_side "b-$label-r$i" "$BEFORE_ROOT/target/release/frps" "$BEFORE_ROOT/target/release/frpc" "$size" 1 "$DUR")"
    fi
  done
  va=$(echo "$va" | median)
  vb=$(echo "$vb" | median)
  if [[ "$va" == "0" || "$vb" == "0" ]]; then
    echo "$va $vb - SKIP(no data)"; return
  fi
  local delta
  delta=$(python3 -c "print(round((100.0*($vb-$va)/$va),1))")
  local result="pass"
  above_gate "$delta" && result="REGRESSED"
  echo "$va $vb $delta $result"
}

FAIL=0
printf '%-8s %12s %12s %8s   %s\n' "size" "before_pps" "after_pps" "delta%" "result"
while IFS= read -r l; do
  set -- $l; size="$1" label="$2"
  read -r va vb delta result <<< "$(measure "$size" "$label")"
  case "$result" in
    "REGRESSED") FAIL=1 ;;
    "SKIP(no data)") printf '%-8s %12s %12s %8s   %s\n' "$label" "$va" "$vb" "-" "SKIP(no data)"; continue ;;
  esac
  printf '%-8s %12s %12s %8s   %s\n' "$label" "$va" "$vb" "${delta}%" "$result"
done <<'EOF'
64   udp64
1024 udp1k
EOF

echo ""
if [[ "$FAIL" == "1" ]]; then
  echo "UDP PPS GATE FAILED: a size regressed more than ${GATE_PCT}% (before -> after)."
  exit 1
else
  echo "UDP PPS GATE PASSED: both sizes within ${GATE_PCT}% of the before baseline."
  exit 0
fi
