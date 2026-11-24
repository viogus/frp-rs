#!/usr/bin/env bash
# KCP transport, tcpMux = false, one proxied flow: TLS off vs TLS on, interleaved,
# with the sender pool flipped per arm and the client's write size settable.
#
# For the "bare KCP trails its own TLS shape" item — the measurement and its
# reading are in docs/archive/notes/2026-11-25-kcp-naked-write-granularity.md.
# `CHUNK` is the point of the harness: the naked arm's rate follows it, the TLS
# arm's does not (rustls re-blocks to ~16 KiB records before KCP sees the bytes).
#
#   bash scripts/kcp-tls-ab.sh [reps] [mib]                  # 64 KiB writes
#   CHUNK=16384 bash scripts/kcp-tls-ab.sh 3 768             # 16 KiB writes
#   CHUNKS="65536 16384" bash scripts/kcp-tls-ab.sh 5 768    # both, interleaved
#
# Needs a release build of both binaries (default: this checkout's target/release).
# Linux only — it reads /proc/net/snmp and /proc/<pid>/stat and probes with `ss`.
# The macOS counterpart for the sender pool is scripts/kcp-sender-ab-macos.sh.
set -uo pipefail
REPS=${1:-3}
MIB=${2:-768}
CHUNKS=${CHUNKS:-${CHUNK:-65536}}
BIND=${BIND:-17000}
TOKEN=abc123
PROJECT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
DIR=$(mktemp -d /tmp/kcp-tls-ab.XXXXXX)
SHA=$(git -C "$PROJECT_DIR" rev-parse --short HEAD 2>/dev/null || echo unknown)
FRPS=${FRPS:-$PROJECT_DIR/target/release/frps}
FRPC=${FRPC:-$PROJECT_DIR/target/release/frpc}
HZ=${HZ:-$(getconf CLK_TCK 2>/dev/null || echo 100)}

[[ -x $FRPS && -x $FRPC ]] || {
  echo "need frps and frpc release binaries (looked for $FRPS and $FRPC);" >&2
  echo "build them with: cargo build --release -p frps -p frpc" >&2
  exit 1
}

cleanup() {
  [[ -n ${frpc_pid:-} ]] && kill "$frpc_pid" 2>/dev/null
  [[ -n ${frps_pid:-} ]] && kill "$frps_pid" 2>/dev/null
  [[ -n ${sink_pid:-} ]] && kill "$sink_pid" 2>/dev/null
  return 0
}
trap cleanup EXIT INT TERM

cat > "$DIR/sink.py" <<'PY'
import socket, sys, threading
port = int(sys.argv[1])
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port)); srv.listen(8)
def serve(c):
    try:
        while True:
            if not c.recv(1 << 20):
                break
    except OSError:
        pass
    finally:
        c.close()
while True:
    c, _ = srv.accept()
    threading.Thread(target=serve, args=(c,), daemon=True).start()
PY

cat > "$DIR/client.py" <<'PY'
import socket, sys, time
port, mib = int(sys.argv[1]), int(sys.argv[2])
chunk = b"x" * int(sys.argv[3] if len(sys.argv) > 3 else 65536)
s = socket.create_connection(("127.0.0.1", port))
s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
total = mib << 20
sent = 0
end_warm = time.time() + 1.0
while time.time() < end_warm:
    s.sendall(chunk); sent += len(chunk)
start = time.time(); base = sent
while sent - base < total:
    s.sendall(chunk); sent += len(chunk)
wall = time.time() - start
s.shutdown(socket.SHUT_WR); s.close()
print("%.3f" % wall)
PY

udp_err() { awk '/^Udp:/{ if (++n == 2) { print $4, $6, $7 } }' /proc/net/snmp; }
wait_tcp() { for _ in $(seq 1 "${2:-150}"); do (exec 3<>/dev/tcp/127.0.0.1/"$1") 2>/dev/null && return 0; sleep 0.1; done; return 1; }
wait_udp() { for _ in $(seq 1 "${2:-100}"); do grep -q ":$1 " <<<"$(ss -lun)" && return 0; sleep 0.1; done; return 1; }

results="$DIR/results.txt"
printf '# session=%s sha=%s reps=%s mib=%s chunks=%s\n' \
  "$(basename "$DIR")" "$SHA" "$REPS" "$MIB" "$CHUNKS" > "$results"

idx=0
run_arm() {
  local tls=$1 pool=$2 rep=$3
  idx=$((idx + 1))
  local sink=$((18100 + idx)) remote=$((17100 + idx))
  cat > "$DIR/frps.toml" <<EOF
bindPort = $BIND
kcp_bind_port = $BIND
auth.token = "$TOKEN"
log.level = "warn"
transport.tcp_mux = false
EOF
  cat > "$DIR/frpc.toml" <<EOF
serverAddr = "127.0.0.1"
serverPort = $BIND
auth.token = "$TOKEN"
log.level = "warn"
transport.protocol = "kcp"
transport.tcpMux = false
transport.tls.enable = $( [[ $tls == on ]] && echo true || echo false )

[transport.kcp]
sender_thread = $pool

[[proxies]]
name = "ab"
type = "tcp"
localIP = "127.0.0.1"
localPort = $sink
remotePort = $remote
EOF
  python3 "$DIR/sink.py" "$sink" & sink_pid=$!
  "$FRPS" -c "$DIR/frps.toml" > "$DIR/frps-$rep-$tls-$pool.log" 2>&1 & frps_pid=$!
  if ! wait_udp "$BIND" 100; then
    echo "FATAL frps never bound $BIND (tls=$tls rep=$rep)"; tail -3 "$DIR/frps-$rep-$tls-$pool.log"
    kill "$frps_pid" "$sink_pid" 2>/dev/null; exit 1
  fi
  "$FRPC" -c "$DIR/frpc.toml" > "$DIR/frpc-$rep-$tls-$pool.log" 2>&1 & frpc_pid=$!
  if ! wait_tcp "$remote" 150; then
    echo "FATAL frpc never published $remote (tls=$tls rep=$rep)"; tail -3 "$DIR/frpc-$rep-$tls-$pool.log"
    kill "$frpc_pid" "$frps_pid" "$sink_pid" 2>/dev/null; exit 1
  fi
  sleep 1
  local cpu0 cpu1 wall rate cpu e0 e1
  e0=$(udp_err)
  cpu0=$(awk '{print $14+$15}' /proc/$frpc_pid/stat)
  wall=$(python3 "$DIR/client.py" "$remote" "$MIB" "$CHUNK")
  cpu1=$(awk '{print $14+$15}' /proc/$frpc_pid/stat 2>/dev/null || echo "$cpu0")
  e1=$(udp_err)
  rate=$(awk -v m="$MIB" -v w="$wall" 'BEGIN{printf "%.1f", m/w}')
  cpu=$(awk -v a="$cpu0" -v b="$cpu1" -v m="$MIB" -v hz="$HZ" 'BEGIN{printf "%.2f", (b-a)*1000/(hz*m)}')
  local err0 err1 rcv_err0 rcv_err1
  read -r err0 rcv_err0 _ <<<"$e0"
  read -r err1 rcv_err1 _ <<<"$e1"
  # InErrors is reported for the record only: teardown traffic lands in it too,
  # so it is a hint, not a drop counter (see the note's "What is not proven").
  echo "rep=$rep chunk=$CHUNK tls=$tls pool=$pool mibps=$rate wall=$wall frpc_cpu_ms_per_mib=$cpu udp_in_err=$((err1 - err0)) udp_rcvbuf_err=$((rcv_err1 - rcv_err0))" | tee -a "$results"
  kill "$frpc_pid" "$frps_pid" "$sink_pid" 2>/dev/null
  wait "$frpc_pid" "$frps_pid" "$sink_pid" 2>/dev/null
  sleep 0.5
}

# Every cell gets the same number of reps, and the arms rotate order per rep so a
# drift in host load lands on all of them. CHUNKS is a space-separated list, so
# write sizes are compared inside one session rather than across two runs.
ARMS=()
for chunk in $CHUNKS; do
  for tls in off on; do
    for pool in true false; do
      ARMS+=("$tls:$pool:$chunk")
    done
  done
done
n_arms=${#ARMS[@]}
for rep in $(seq 1 "$REPS"); do
  for i in $(seq 0 $((n_arms - 1))); do
    idx=$(( (i + rep - 1) % n_arms ))
    IFS=: read -r tls pool chunk <<<"${ARMS[$idx]}"
    CHUNK=$chunk run_arm "$tls" "$pool" "$rep"
  done
done

echo "--- summary"
python3 - "$results" <<'PY'
import sys, statistics
rows = {}
for line in open(sys.argv[1]):
    if "mibps=" not in line:
        continue
    f = dict(p.split("=", 1) for p in line.split() if "=" in p)
    k = f"chunk={f.get('chunk','?')},tls={f['tls']},pool={f['pool']}"
    rows.setdefault(k, {"rate": [], "cpu": [], "err": []})
    rows[k]["rate"].append(float(f["mibps"]))
    rows[k]["cpu"].append(float(f["frpc_cpu_ms_per_mib"]))
    rows[k]["err"].append(int(f.get("udp_in_err", "0")))
    rows[k].setdefault("rcv_err", []).append(int(f.get("udp_rcvbuf_err", "0")))
for k in sorted(rows):
    r, c, e = rows[k]["rate"], rows[k]["cpu"], rows[k]["err"]
    rcv = sum(rows[k]["rcv_err"])
    print(f"{k:<32} n={len(r)} mean={statistics.mean(r):6.1f} median={statistics.median(r):6.1f} cpu_med={statistics.median(c):5.2f} udp_in_err={sum(e)} udp_rcvbuf_err={rcv} reps={r}")
chunks = sorted({k.split(",")[0].split("=")[1] for k in rows}, key=int)
for chunk in chunks:
    for pool in ("true", "false"):
        a = rows.get(f"chunk={chunk},tls=off,pool={pool}")
        b = rows.get(f"chunk={chunk},tls=on,pool={pool}")
        if a and b:
            print(f"chunk={chunk} pool={pool}: naked/tls = "
                  f"{statistics.mean(a['rate']) / statistics.mean(b['rate']):.3f}x")
PY
echo "logs: $DIR"
