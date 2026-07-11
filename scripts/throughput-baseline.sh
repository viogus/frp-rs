#!/usr/bin/env bash
# =============================================================================
# frp-rs throughput baseline: sweep bridge-config matrix, record MB/s per config.
#   plain | encrypt | compress | encrypt+compress | mux | tls
# Usage: bash scripts/throughput-baseline.sh [duration_s] [streams]
# Output: scripts/frp-stress/baselines/throughput-<hostname>.jsonl
#
# Numbers are host-specific. Regenerate before a Phase 2 change and diff after;
# any config dropping >5% MB/s rejects the change.
# =============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

DURATION="${1:-10}"
STREAMS="${2:-1}"
FRPS_PORT=18000
REMOTE_PORT=18001
ECHO_PORT=18002
TOKEN="baseline-token"
OUT="scripts/frp-stress/baselines/throughput-$(hostname -s).jsonl"
CA_CERT=/tmp/baseline-ca.crt
CA_KEY=/tmp/baseline-ca.key
CERT=/tmp/baseline-srv.crt
KEY=/tmp/baseline-srv.key

echo "=== Building release binaries ==="
# frps/frpc are the shipped workspace; frp-stress is a standalone workspace
# under scripts/, built separately (keeps its deps out of the release lock).
cargo build --release -p frps -p frpc 2>&1 | tail -2
(cd scripts/frp-stress && cargo build --release 2>&1 | tail -2)

FRPS=./target/release/frps
FRPC=./target/release/frpc
STRESS=./scripts/frp-stress/target/release/frp-stress

# TLS row certs: a CA plus a CA-signed end-entity leaf. rustls (webpki) rejects
# a self-signed CA cert used directly as the server leaf (CaUsedAsEndEntity), and
# ignores the legacy CN — the leaf must carry a SAN matching the TLS server name
# ("localhost"). frps serves the leaf; frpc trusts the CA via tls_ca_file.
if [[ ! -f "$CERT" ]]; then
  openssl req -x509 -newkey rsa:2048 -keyout "$CA_KEY" -out "$CA_CERT" \
    -days 1 -nodes -subj "/CN=baseline-ca" 2>/dev/null
  openssl req -newkey rsa:2048 -keyout "$KEY" -out /tmp/baseline-srv.csr \
    -nodes -subj "/CN=localhost" 2>/dev/null
  openssl x509 -req -in /tmp/baseline-srv.csr -CA "$CA_CERT" -CAkey "$CA_KEY" \
    -CAcreateserial -out "$CERT" -days 1 \
    -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=CA:FALSE") 2>/dev/null
fi

PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT

mkdir -p "$(dirname "$OUT")"
rm -f "$OUT"

# run_config <label> <mux> <enc> <comp> <tls>   (each flag: true|false)
run_config() {
  local label="$1" mux="$2" enc="$3" comp="$4" tls="$5"
  echo "=== config: $label ==="

  # --- frps config (TLS fields + tcp_mux are TOP-LEVEL server keys) ---
  {
    echo "bind_addr = \"127.0.0.1\""
    echo "bind_port = $FRPS_PORT"
    echo "tcp_mux = $mux"
    if [[ "$tls" == "true" ]]; then
      echo "tls_enable = true"
      echo "tls_cert_file = \"$CERT\""
      echo "tls_key_file = \"$KEY\""
    fi
    echo "[auth]"
    echo "method = \"token\""
    echo "token = \"$TOKEN\""
    echo "[log]"
    echo "level = \"warn\""
  } > /tmp/bl-frps.toml

  # --- frpc config (TLS fields are TOP-LEVEL client keys, not [transport.tls]) ---
  {
    echo "server_addr = \"127.0.0.1\""
    echo "server_port = $FRPS_PORT"
    echo "token = \"$TOKEN\""
    echo "login_fail_exit = true"
    echo "pool_count = 1"
    echo "tcp_mux = $mux"
    if [[ "$tls" == "true" ]]; then
      echo "tls_enable = true"
      echo "tls_ca_file = \"$CA_CERT\""
      echo "tls_server_name = \"localhost\""
      echo "disable_custom_tls_first_byte = true"
    fi
    echo "[[proxies]]"
    echo "name = \"bl-tcp\""
    echo "type = \"tcp\""
    echo "local_ip = \"127.0.0.1\""
    echo "local_port = $ECHO_PORT"
    echo "remote_port = $REMOTE_PORT"
    [[ "$enc"  == "true" ]] && echo "use_encryption = true"
    [[ "$comp" == "true" ]] && echo "use_compression = true"
  } > /tmp/bl-frpc.toml

  "$STRESS" --scenario echo --port "$ECHO_PORT" & PIDS+=($!)
  sleep 1
  "$FRPS" -c /tmp/bl-frps.toml & PIDS+=($!)
  sleep 1
  "$FRPC" -c /tmp/bl-frpc.toml & PIDS+=($!)
  sleep 2

  "$STRESS" --scenario throughput --port "$REMOTE_PORT" \
    --frps-addr "127.0.0.1:$FRPS_PORT" --token "$TOKEN" --streams "$STREAMS" \
    --duration "$DURATION" --label "$label" --no-floor --json-out "$OUT" || true

  # Tear down this config's processes before the next row.
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
  PIDS=()
  sleep 1
}

#           label             mux    enc    comp   tls
run_config "plain"            false  false  false  false
run_config "encrypt"          false  true   false  false
run_config "compress"         false  false  true   false
run_config "encrypt_compress" false  true   true   false
run_config "mux"              true   false  false  false
run_config "tls"              false  false  false  true

echo "=== baseline written: $OUT ==="
cat "$OUT"
