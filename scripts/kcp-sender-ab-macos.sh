#!/usr/bin/env bash
# =============================================================================
# macOS A/B for the KCP sender-pool default ([transport.kcp] senderThread).
#
# Shape: N concurrent streams -> frpc (KCP + TLS + tcpMux) -> frps -> sink.
# The traffic is unidirectional, so the process under test is frpc's KCP send
# path; frps stays at its default and its own sends are only ACKs.
#
# The script moves a fixed byte budget per arm instead of running a fixed wall
# clock, and reads frpc's own CPU seconds from `ps` around the payload window.
# That matters off Linux: the worker has no `sendmmsg` there and a `WouldBlock`
# waits a fixed 5 ms slice, so the question is as much "what does it cost in
# CPU" as "what rate does it reach" — and on a contended laptop the wall-clock
# rate moves by tens of percent between neighbours while CPU per MiB does not.
#
# Usage: bash scripts/kcp-sender-ab-macos.sh [reps] [streams] [total_mib] [max_s]
#   FRPS=/path FRPC=/path to test another build (default: this tree's release).
# Prints one line per arm and a summary; exits 1 if a stream failed.
# Reference result and its caveats:
#   docs/archive/notes/2026-11-23-kcp-send-thread.md § Limits
# =============================================================================
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

FRPS=${FRPS:-$PROJECT_DIR/target/release/frps}
FRPC=${FRPC:-$PROJECT_DIR/target/release/frpc}
REPS=${1:-6}
STREAMS=${2:-8}
MIB=${3:-1024}
MAX_SECONDS=${4:-120}
DIR=$(mktemp -d /tmp/kcp-sender-ab.XXXXXX)
TOKEN=ab-token
BIND=17000
KCP=17001
REMOTE=17002
SINK=17003

[[ -x $FRPS && -x $FRPC ]] || { echo "need frps/frpc binaries: $FRPS $FRPC" >&2; exit 1; }

cat > "$DIR/sink.py" <<'PY'
import socket, sys, threading
PORT, BUF = int(sys.argv[1]), bytearray(1 << 20)
def serve(conn):
    try:
        conn.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
        while conn.recv_into(BUF):
            pass
    except OSError:
        pass
    finally:
        conn.close()
listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(("127.0.0.1", PORT)); listener.listen(128)
while True:
    conn, _ = listener.accept()
    threading.Thread(target=serve, args=(conn,), daemon=True).start()
PY

cat > "$DIR/client.py" <<'PY'
import socket, sys, threading, time
HOST, PORT = sys.argv[1], int(sys.argv[2])
STREAMS, MAX_SECONDS, MIB = int(sys.argv[3]), float(sys.argv[4]), float(sys.argv[5])
CHUNK, SHARE = bytes(64 * 1024), int(MIB * (1 << 20) / int(sys.argv[3]))
start, counts, errors = threading.Barrier(STREAMS + 1), [0] * STREAMS, [None] * STREAMS
def stream(idx):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1 << 20)
    try:
        sock.connect((HOST, PORT))
    except OSError as exc:
        errors[idx] = f"connect: {exc}"; start.wait(); return
    start.wait()
    deadline, sent = time.monotonic() + MAX_SECONDS, 0
    try:
        while time.monotonic() < deadline and sent < SHARE:
            sent += sock.send(CHUNK[: min(len(CHUNK), SHARE - sent)])
    except OSError as exc:
        errors[idx] = f"send: {exc}"
    finally:
        counts[idx] = sent
        sock.close()
threads = [threading.Thread(target=stream, args=(i,)) for i in range(STREAMS)]
for t in threads: t.start()
start.wait(); window = time.monotonic()
for t in threads: t.join()
elapsed = time.monotonic() - window
for i, err in enumerate(errors):
    if err: print(f"stream {i}: {err}", file=sys.stderr)
total = sum(counts) / (1 << 20)
ok = sum(1 for c in counts if c > 0)
short = int(any(c < SHARE for c in counts))
print(f"{total / elapsed:.1f} {ok} {STREAMS - ok} {total:.1f} {elapsed:.2f} {short}")
PY

cleanup() {
  [[ -n ${FRPS_PID:-} ]] && kill "$FRPS_PID" 2>/dev/null
  [[ -n ${FRPC_PID:-} ]] && kill "$FRPC_PID" 2>/dev/null
  [[ -n ${SINK_PID:-} ]] && kill "$SINK_PID" 2>/dev/null
  wait 2>/dev/null
}
trap cleanup EXIT

cat > "$DIR/frps.toml" <<EOF
bindPort = $BIND
kcpBindPort = $KCP
auth.token = "$TOKEN"
log.level = "warn"
EOF

wait_port() {
  local port=$1 tries=${2:-150}
  for _ in $(seq "$tries"); do
    python3 -c "import socket;socket.create_connection(('127.0.0.1',$port),0.2).close()" 2>/dev/null && return 0
    sleep 0.2
  done
  return 1
}

# ps prints CPU time as [H:]MM:SS.ss; fold it into seconds.
cpu_seconds() {
  ps -o time= -p "$1" 2>/dev/null | tr -d ' ' \
    | awk -F: 'NF { s = 0; for (i = 1; i <= NF; i++) s = s * 60 + $i; printf "%.2f", s }'
}

run_arm() {
  local flag=$1 rep=$2
  cat > "$DIR/frpc.toml" <<EOF
serverAddr = "127.0.0.1"
serverPort = $KCP
auth.token = "$TOKEN"
log.level = "warn"
transport.protocol = "kcp"
transport.tcpMux = true
transport.tls.enable = true

[transport.kcp]
senderThread = $flag

[[proxies]]
name = "ab"
type = "tcp"
localIP = "127.0.0.1"
localPort = $SINK
remotePort = $REMOTE
EOF
  "$FRPS" -c "$DIR/frps.toml" > "$DIR/frps-$rep-$flag.log" 2>&1 &
  FRPS_PID=$!
  wait_port "$BIND" 100 || { echo "frps never bound $BIND" >&2; return 1; }
  "$FRPC" -c "$DIR/frpc.toml" > "$DIR/frpc-$rep-$flag.log" 2>&1 &
  FRPC_PID=$!
  if ! wait_port "$REMOTE" 150; then
    echo "frpc never published $REMOTE (flag=$flag rep=$rep)" >&2
    tail -5 "$DIR/frpc-$rep-$flag.log" >&2
    kill "$FRPC_PID" "$FRPS_PID" 2>/dev/null
    return 1
  fi
  # A separate one-second connection warms the tunnel without spending the budget.
  python3 "$DIR/client.py" 127.0.0.1 "$REMOTE" "$STREAMS" 1 16 > /dev/null 2>&1
  local before after line mibps ok bad mib wall short cpu
  before=$(cpu_seconds "$FRPC_PID")
  line=$(python3 "$DIR/client.py" 127.0.0.1 "$REMOTE" "$STREAMS" "$MAX_SECONDS" "$MIB" 2>&1)
  after=$(cpu_seconds "$FRPC_PID")
  read -r mibps ok bad mib wall short <<< "$(tail -1 <<< "$line")"
  if [[ -z ${mibps:-} || ! ${mibps:-x} =~ ^[0-9.]+$ ]]; then
    echo "rep=$rep flag=$flag: no result from the client:" >&2
    echo "$line" >&2
    kill "$FRPC_PID" "$FRPS_PID" 2>/dev/null
    return 1
  fi
  cpu=$(awk -v a="${before:-0}" -v b="${after:-0}" 'BEGIN { printf "%.2f", b - a }')
  printf 'rep=%s flag=%-5s mibps=%s mib=%s wall=%s frpc_cpu_s=%s ok=%s failed=%s short=%s load=%s\n' \
    "$rep" "$flag" "$mibps" "$mib" "$wall" "$cpu" "$ok" "$bad" "$short" \
    "$(sysctl -n vm.loadavg 2>/dev/null | awk '{print $2}')" | tee -a "$DIR/results.txt"
  kill "$FRPC_PID" "$FRPS_PID" 2>/dev/null
  wait "$FRPC_PID" "$FRPS_PID" 2>/dev/null
  sleep 1
}

python3 "$DIR/sink.py" "$SINK" > "$DIR/sink.log" 2>&1 &
SINK_PID=$!
wait_port "$SINK" 50 || { echo "sink never bound $SINK" >&2; exit 1; }

: > "$DIR/results.txt"
# Alternate so a monotonic drift (thermal or background load) cannot favour an arm.
for rep in $(seq 1 "$REPS"); do
  if (( rep % 2 == 1 )); then run_arm true "$rep"; run_arm false "$rep"
  else run_arm false "$rep"; run_arm true "$rep"; fi
done

python3 - "$DIR/results.txt" <<'PY'
import re, statistics, sys
rows = {"true": [], "false": []}
for line in open(sys.argv[1]):
    m = re.search(r"flag=(\w+)\s+mibps=([\d.]+) mib=([\d.]+) wall=([\d.]+) frpc_cpu_s=([\d.]+)", line)
    if m:
        rows[m.group(1)].append(tuple(float(x) for x in m.groups()[1:]))
print()
for name, vals in rows.items():
    if not vals:
        continue
    rates = [v[0] for v in vals]
    ms_per_mib = [v[3] / v[1] * 1000 for v in vals if v[1]]
    print(f"senderThread={name:<5} n={len(vals)} mibps median={statistics.median(rates):.1f} "
          f"mean={statistics.mean(rates):.1f} reps={[round(r, 1) for r in rates]}")
    if ms_per_mib:
        print(f"{'':19}ms CPU/MiB median={statistics.median(ms_per_mib):.2f} "
              f"reps={[round(x, 2) for x in ms_per_mib]}")
if all(rows.values()):
    tr = [v[0] for v in rows["true"]]
    fr = [v[0] for v in rows["false"]]
    tc = [v[3] / v[1] * 1000 for v in rows["true"] if v[1]]
    fc = [v[3] / v[1] * 1000 for v in rows["false"] if v[1]]
    t, f = statistics.median(tr), statistics.median(fr)
    print(f"\npooled vs inline throughput: {t:.1f} vs {f:.1f} MiB/s ({100 * (t - f) / f:+.1f}%)")
    if tc and fc:
        tc_m, fc_m = statistics.median(tc), statistics.median(fc)
        cheaper = sum(1 for a, b in zip(tc, fc) if a < b)
        print(f"pooled vs inline CPU:        {tc_m:.2f} vs {fc_m:.2f} ms/MiB "
              f"({100 * (tc_m - fc_m) / fc_m:+.1f}%), pooled cheaper in "
              f"{cheaper}/{min(len(tc), len(fc))} paired reps")
PY

echo "logs: $DIR"
