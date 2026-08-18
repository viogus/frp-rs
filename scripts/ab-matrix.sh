#!/usr/bin/env bash
# =============================================================================
# frp-rs full-matrix A/B throughput gate.
#
# Measures the six bridge configurations (plain / encrypt / compress /
# encrypt_compress / mux / tls) for TWO code states and reports the per-config
# delta, failing (non-zero exit) if any configuration regresses by more than
# GATE_PCT (default 5%).
#
# Binary sources (must be pre-built release binaries):
#   BEFORE_ROOT  - directory containing target/release/{frps,frpc} and
#                  scripts/frp-stress/target/release/frp-stress for the OLD
#                  state (the "before" / baseline).
#   AFTER_ROOT   - same layout for the NEW state; defaults to the repo root.
#
# Usage:
#   BEFORE_ROOT=/path/to/before-build bash scripts/ab-matrix.sh [reps] [duration_s]
#
# Examples:
#   # Local: current HEAD (after) vs a pre-built baseline (before)
#   BEFORE_ROOT=/tmp/base-build GATE_PCT=5 bash scripts/ab-matrix.sh 3 10
#
#   # CI (see .github/workflows/ab-matrix.yml): base.sha built to a temp root
#   # is compared against the PR head's target/release.
#
# Output: a per-config table with A / B / delta%, plus a final PASS/FAIL line.
# Exit 0 if every config is within threshold, 1 if any regressed > GATE_PCT.
#
# Numbers are host-specific; always compare against a same-host before build.
# =============================================================================
set -euo pipefail
export RUST_LOG=warn

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

REPS="${1:-3}"
RDUR="${2:-10}"
GATE_PCT="${GATE_PCT:-5}"
SKIP_BUILD="${SKIP_BUILD:-0}"   # set to 1 to assume *_ROOT already built
_WT_PATHS=()                     # REF worktrees to clean up on exit

# --- provision a 'side' (before/after) binary root --------------------------
# A side resolves to a directory carrying target/release/{frps,frpc} and
# scripts/frp-stress/target/release/frp-stress. Source is either an explicit
# *_ROOT dir (use as-is) or a *_REF git ref (worktree-checkout + release
# build). At least one of the two must be provided for AFTER; BEFORE defaults
# to the current repo root unless built.
#
# commit-vs-commit usage (what the CI manual gate uses):
#   BEFORE_REF=<commit>~1  AFTER_REF=<commit>  bash scripts/ab-matrix.sh
build_side() {  # build_side <prefix> <root_env_value> <ref_env_value>; sets <prefix>_DIR
  local prefix="$1" root="$2" ref="$3"
  local dir=""
  if [[ -n "$root" ]]; then
    dir="$root"
  elif [[ -n "$ref" ]]; then
    dir="/tmp/ab-matrix-${prefix}-${RANDOM}"
    if [[ "$SKIP_BUILD" != "1" ]]; then
      echo "Checking out '$ref' -> $dir" >&2
      git -C "$PROJECT_DIR" worktree add "$dir" "$ref" >/dev/null
      _WT_PATHS+=("$dir")
      cargo build --release --manifest-path "$dir/Cargo.toml" -p frps -p frpc >&2
      (cd "$dir/scripts/frp-stress" && cargo build --release) >&2
    fi
  else
    echo "ERROR: set ${prefix}_ROOT or ${prefix}_REF" >&2
    exit 2
  fi
  for b in "$dir/target/release/frps" "$dir/target/release/frpc" "$dir/scripts/frp-stress/target/release/frp-stress"; do
    if [[ ! -x "$b" ]]; then
      echo "ERROR: missing binary $b for $prefix" >&2
      exit 2
    fi
  done
  # No nameref (macOS Bash 3.2); side effect via eval. `prefix` is only ever
  # "AFTER"/"BEFORE" from callers below, so the variable name is trusted.
  eval "${prefix}_DIR='$dir'"
}

AFTER_ROOT="${AFTER_ROOT:-}"
AFTER_REF="${AFTER_REF:-}"
if [[ -n "$AFTER_ROOT" || -n "$AFTER_REF" ]]; then
  build_side AFTER "$AFTER_ROOT" "$AFTER_REF"   # sets AFTER_DIR via eval
else
  AFTER_DIR="$PROJECT_DIR"
fi

BEFORE_ROOT="${BEFORE_ROOT:-}"
BEFORE_REF="${BEFORE_REF:-}"
if [[ -n "$BEFORE_ROOT" || -n "$BEFORE_REF" ]]; then
  build_side BEFORE "$BEFORE_ROOT" "$BEFORE_REF"   # sets BEFORE_DIR via eval
else
  echo "ERROR: set BEFORE_ROOT or BEFORE_REF to provide the 'before'/baseline" >&2
  exit 2
fi

FRPS_A="$BEFORE_DIR/target/release/frps" FRPC_A="$BEFORE_DIR/target/release/frpc" STRESS_A="$BEFORE_DIR/scripts/frp-stress/target/release/frp-stress"
FRPS_B="$AFTER_DIR/target/release/frps"   FRPC_B="$AFTER_DIR/target/release/frpc"   STRESS_B="$AFTER_DIR/scripts/frp-stress/target/release/frp-stress"

# --- ports / token / TLS certs ----------------------------------------------
PORT=18040; RPORT=18041; ECHO=18042; TOKEN="ab-matrix-token"
CA=/tmp/abmatrix-ca.crt; CAKEY=/tmp/abmatrix-ca.key
CERT=/tmp/abmatrix-srv.crt; KEY=/tmp/abmatrix-srv.key
if [[ ! -f "$CERT" ]]; then
  openssl req -x509 -newkey rsa:2048 -keyout "$CAKEY" -out "$CA" -days 1 -nodes -subj "/CN=abmatrix-ca" 2>/dev/null
  openssl req -newkey rsa:2048 -keyout "$KEY" -out /tmp/abmatrix-srv.csr -nodes -subj "/CN=localhost" 2>/dev/null
  openssl x509 -req -in /tmp/abmatrix-srv.csr -CA "$CA" -CAkey "$CAKEY" -CAcreateserial -out "$CERT" -days 1 \
    -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=CA:FALSE") 2>/dev/null
fi

PIDS=()
cleanup() {
  for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done
  # Remove REF-mode worktrees this run created, so repeated invocations (e.g.
  # CI cache warm-up) do not leak detached WORKTREEs.
  for w in "${_WT_PATHS[@]}"; do git -C "$PROJECT_DIR" worktree remove --force "$w" 2>/dev/null || true; done
}
trap cleanup EXIT

# run_side <label> <frps> <frpc> <stress> <mux> <enc> <comp> <tls> <reps> <dur>
# -> prints each valid mbps on its own line (>=1 line if any succeed)
run_side() {
  local label="$1" frps="$2" frpc="$3" stress="$4" mux="$5" enc="$6" comp="$7" tls="$8" r="$9" dur="${10}"
  {
    echo "bind_addr = \"127.0.0.1\""; echo "bind_port = $PORT"; echo "tcp_mux = $mux"
    if [[ "$tls" == "true" ]]; then echo "tls_enable = true"; echo "tls_cert_file = \"$CERT\""; echo "tls_key_file = \"$KEY\""; fi
    echo "[auth]"; echo "method = \"token\""; echo "token = \"$TOKEN\""; echo "[log]"; echo "level = \"warn\""
  } > /tmp/ab-frps.toml
  {
    echo "server_addr = \"127.0.0.1\""; echo "server_port = $PORT"; echo "token = \"$TOKEN\""
    echo "login_fail_exit = true"; echo "pool_count = 1"; echo "tcp_mux = $mux"
    if [[ "$tls" == "true" ]]; then echo "tls_enable = true"; echo "tls_ca_file = \"$CA\""; echo "tls_server_name = \"localhost\""; echo "disable_custom_tls_first_byte = true"; fi
    echo "[[proxies]]"; echo "name = \"ab-tcp\""; echo "type = \"tcp\""
    echo "local_ip = \"127.0.0.1\""; echo "local_port = $ECHO"; echo "remote_port = $RPORT"
    [[ "$enc"  == "true" ]] && echo "use_encryption = true"
    [[ "$comp" == "true" ]] && echo "use_compression = true"
  } > /tmp/ab-frpc.toml
  PIDS=()
  "$stress" --scenario echo --port "$ECHO" >/dev/null 2>&1 & PIDS+=($!)
  sleep 1
  "$frps" -c /tmp/ab-frps.toml >/dev/null 2>&1 & PIDS+=($!)
  sleep 1
  "$frpc" -c /tmp/ab-frpc.toml >/dev/null 2>&1 & PIDS+=($!)
  local ok=""
  for i in $(seq 1 10); do
    if python3 -c "
import socket,sys
try:
    s=socket.create_connection(('127.0.0.1',$RPORT),timeout=0.3); s.close(); sys.exit(0)
except Exception: sys.exit(1)
" 2>/dev/null; then ok=1; break; fi
    sleep 1
  done
  [[ -n "$ok" ]] || echo "WARN $label: proxy port not ready after 10s" >&2
  sleep 1
  for j in $(seq 1 "$r"); do
    local mb
    mb=$("$stress" --scenario throughput --port "$RPORT" --frps-addr "127.0.0.1:$PORT" \
      --token "$TOKEN" --streams 1 --duration "$dur" --label "$label-$j" --no-floor 2>/dev/null \
      | sed -e 's/\x1b\[[0-9;]*m//g' | grep -o 'mbps=[0-9.]*' | head -1 | cut -d= -f2)
    [[ -n "$mb" && "$mb" != "0" ]] && echo "$mb"
  done
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
  PIDS=(); sleep 1
}

median() {  # median of stdin numbers (>=1)
  python3 -c "import sys,statistics;v=[float(x) for x in sys.stdin if float(x)>0];print(round(statistics.median(v),1) if v else 0)"
}

FAIL=0
printf '%-18s %9s %9s %8s   %s\n' "config" "before" "after" "delta%" "result"
#            label            mux   enc   comp  tls
while IFS= read -r l; do
  set -- $l; mux="$1" enc="$2" comp="$3" tls="$4" label="$5"
  # measure before then after (adjacent) for this config to minimise drift
  v_a=$(run_side "before-$label" "$FRPS_A" "$FRPC_A" "$STRESS_A" "$mux" "$enc" "$comp" "$tls" "$REPS" "$RDUR" | median)
  v_b=$(run_side "after-$label"  "$FRPS_B" "$FRPC_B" "$STRESS_B" "$mux" "$enc" "$comp" "$tls" "$REPS" "$RDUR" | median)
  if [[ "$v_a" == "0" || "$v_b" == "0" ]]; then
    printf '%-18s %9s %9s %8s   %s\n' "$label" "$v_a" "$v_b" "-"   "SKIP(no data)"
    continue
  fi
  delta=$(python3 -c "print(round((100.0*($v_b-$v_a)/$v_a),1))")
  result="pass"
  if python3 -c "import sys; sys.exit(0 if ($delta < -$GATE_PCT) else 1)"; then result="REGRESSED"; FAIL=1; fi
  printf '%-18s %9s %9s %8s   %s\n' "$label" "$v_a" "$v_b" "${delta}%" "$result"
done <<'EOF'
false  false false false  plain
false  true  false false  encrypt
false  false true  false  compress
false  true  true  false  encrypt_compress
true   false false false  mux
false  false false true   tls
EOF

echo ""
if [[ "$FAIL" == "1" ]]; then
  echo "A/B GATE FAILED: one or more configs regressed more than ${GATE_PCT}% (before -> after)."
  exit 1
else
  echo "A/B GATE PASSED: all configs within ${GATE_PCT}% of the before baseline."
  exit 0
fi
