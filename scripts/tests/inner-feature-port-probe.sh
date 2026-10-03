#!/usr/bin/env bash
# inner-feature-port-probe.sh — manual probe for the hand-named inner-feature
# listener-port shape (`TODO.md` item filed from the M-6 records round).
#
# The shape: `--kcp-bind-port` / `--quic-bind-port` and the
# `kcp_bind_port` / `quic_bind_port` / `websocket_port` file keys are gated on
# **frp-core**'s features, while the listeners that read the ports belong to
# **frp-server** (`frp-server/Cargo.toml`: `kcp = ["frp-core/kcp"]`, and the
# same one-way implication for `quic` / `websocket`). A caller who names the
# inner feature by hand —
#
#   cargo build -p frps --no-default-features --features tiny,frp-core/kcp
#
# — therefore gets the field and the flag without the listener. This probe
# builds each of those shapes and asserts the **fixed** behaviour: the flag and
# the file key each print exactly one record naming the missing frp-server
# feature, in the field-present wording. The ordinary `tiny` shape stays the
# control for the field-less wording and for the flag rejection.
#
# Why this is a probe and not a CI step: the assertion that runs on every push
# is the `gated_listener_port_records_follow_this_builds_readers` unit test in
# `frp-server/src/service.rs`, which the existing
# `cargo test -p frp-server --no-default-features --all-targets -j 1` lane runs
# in exactly this feature resolution (frp-core's fields on through the
# `frp-client` dev-dependency, frp-server's listeners off). Adding a step to
# `.github/workflows/ci.yml` would renumber every `ci.yml:NNNN` citation that
# live files carry, and that regeneration is a much larger review surface than
# the behaviour it would witness. This script is the reproducible binary-level
# measurement for a human, deliberately not wired into any lane.
#
# Usage:
#   bash scripts/tests/inner-feature-port-probe.sh
# Exit code: 0 when every probe check holds, 1 otherwise.
set -uo pipefail

self=${BASH_SOURCE[0]:-$0}
ROOT=$(cd -P -- "$(dirname -- "$self")/../.." && pwd)
cd "$ROOT" || exit 1

if ! command -v cargo >/dev/null 2>&1; then
  printf 'FAIL  cargo not on PATH — run with export PATH="$HOME/.cargo/bin:$PATH"\n' >&2
  exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
  printf 'FAIL  python3 not found — the free-port helper needs it\n' >&2
  exit 1
fi

work=$(mktemp -d "${TMPDIR:-/tmp}/inner-feature-port-probe.XXXXXX") || exit 1
trap 'rm -rf "$work"' EXIT

ok=0
fail=0
check() {
  # check <description> <expected> <actual>
  if [ "$2" = "$3" ]; then
    ok=$((ok + 1))
    printf '  ok  %s\n' "$1"
  else
    fail=$((fail + 1))
    printf 'FAIL  %s (expected %s, got %s)\n' "$1" "$2" "$3"
  fi
}

free_port() {
  python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
}

# Build every shape into its own copy: each build overwrites
# `target/debug/frps-tiny`, so the binary is captured immediately. Every shape
# this probe builds includes frps's `tiny`, so the `frps-tiny` artifact is the
# one produced.
build_shape() {
  # build_shape <features> <label>
  local features=$1 label=$2
  printf 'building `%s` ...\n' "$features"
  if ! cargo build -p frps --no-default-features --features "$features" >/dev/null 2>&1; then
    printf 'FAIL  cargo build -p frps --no-default-features --features %s failed\n' \
      "$features" >&2
    exit 1
  fi
  cp target/debug/frps-tiny "$work/$label" || exit 1
}

# Run one binary with a config file in its own directory and capture the output.
# `run_bin <absolute-binary> <config-body> [extra argv...]`.
run_bin() {
  local bin=$1 body=$2
  shift 2
  local dir="$work/run.$$"
  rm -rf "$dir"
  mkdir -p "$dir"
  printf '%s\n' "$body" > "$dir/frps.toml"
  ( cd "$dir" && exec "$bin" "$@" ) > "$dir/out.txt" 2>&1 &
  local pid=$!
  sleep 2
  kill "$pid" 2>/dev/null
  wait "$pid" 2>/dev/null
  cat "$dir/out.txt"
}

# `probe_shape <label> <feature-key> <flag> <file-key-body-fragment>` asserts the
# flag half, the file half and the help advertisement for one hand-named shape.
probe_shape() {
  local label=$1 key=$2 flag=$3 fileline=$4
  local bin="$work/$label"
  local port
  port=$(free_port)

  # 1. `--help` still advertises the flag in this shape.
  local help
  help=$("$bin" --help 2>&1)
  check "$label: --help advertises $flag" 1 "$(printf '%s' "$help" | grep -c -- "$flag")"

  # 2. The flag half: exactly one record, the field-present wording.
  local out records text
  out=$(run_bin "$bin" "bind_port = $port" "$flag" "$((port + 1))")
  records=$(printf '%s' "$out" | grep -c -- "$key" || true)
  check "$label: flag prints exactly one $key record" 1 "$records"
  text=$(printf '%s' "$out" | grep -c 'frp-core compiled the field' || true)
  check "$label: flag record names the missing frp-server feature" 1 "$text"

  # 3. The file-key half: exactly one record, same wording.
  out=$(run_bin "$bin" "bind_port = $port
$fileline")
  records=$(printf '%s' "$out" | grep -c -- "$key" || true)
  check "$label: file key prints exactly one $key record" 1 "$records"
  text=$(printf '%s' "$out" | grep -c 'frp-core compiled the field' || true)
  check "$label: file-key record names the missing frp-server feature" 1 "$text"
}

printf '== hand-named `tiny,frp-core/kcp` ==\n'
build_shape "tiny,frp-core/kcp" frps-tiny-kcp
probe_shape frps-tiny-kcp kcp_bind_port --kcp-bind-port "kcp_bind_port = 41700"

printf '== hand-named `tiny,frp-core/quic` ==\n'
build_shape "tiny,frp-core/quic" frps-tiny-quic
probe_shape frps-tiny-quic quic_bind_port --quic-bind-port "quic_bind_port = 41702"

printf '== hand-named `tiny,frp-core/websocket` (file key only: no flag) ==\n'
build_shape "tiny,frp-core/websocket" frps-tiny-ws
port=$(free_port)
out=$(run_bin "$work/frps-tiny-ws" "bind_port = $port
websocket_port = 41704")
check "frps-tiny-ws: websocket_port file key prints exactly one record" 1 \
  "$(printf '%s' "$out" | grep -c websocket_port || true)"
check "frps-tiny-ws: file-key record names the missing frp-server feature" 1 \
  "$(printf '%s' "$out" | grep -c 'frp-core compiled the field' || true)"

printf '== ordinary `tiny` (control: flag rejected, file key warns) ==\n'
build_shape "tiny" frps-tiny-tiny
port=$(free_port)
out=$(run_bin "$work/frps-tiny-tiny" "bind_port = $port" --kcp-bind-port "$((port + 1))")
check "frps-tiny: --kcp-bind-port is rejected" 1 \
  "$(printf '%s' "$out" | grep -c 'not expected in this context' || true)"
check "frps-tiny: the rejection is not a record" 0 \
  "$(printf '%s' "$out" | grep -c 'kcp_bind_port has no effect' || true)"
out=$(run_bin "$work/frps-tiny-tiny" "bind_port = $port
kcp_bind_port = 41706")
check "frps-tiny: file key prints exactly one record" 1 \
  "$(printf '%s' "$out" | grep -c kcp_bind_port || true)"
check "frps-tiny: file-key record uses the field-less wording" 1 \
  "$(printf '%s' "$out" | grep -c "frp-core's .kcp. feature is off" || true)"

printf '\ninner-feature-port-probe: %d check(s) hold, %d failure(s)\n' "$ok" "$fail"
if [ "$fail" = "0" ]; then
  printf 'RESULT: %d probe check(s) hold\n' "$ok"
  exit 0
fi
printf 'RESULT: %d probe check(s) failed\n' "$fail"
exit 1
