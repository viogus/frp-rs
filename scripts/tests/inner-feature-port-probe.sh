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
# builds **all five** shapes it claims (`tiny,frp-core/kcp`,
# `tiny,frp-core/quic`, `tiny,frp-core/websocket`, `micro,frp-core/kcp`,
# ordinary `tiny`) plus the default `frps` as the honoured converse, and for
# each one asserts:
#
#   * the built artifact is the frps binary **this worktree's manifest**
#     produced, its tier feature is on, and — for the four hand-named shapes —
#     a `frp-core` artifact in the same build carries the named inner feature.
#     The executable is taken from cargo's own `--message-format=json` artifact
#     message, never from a guessed `target/debug/frps-tiny`, and a freshness
#     guard reds if any source file under `frp-core`/`frp-server`/`frps` is
#     newer than that executable. Together those make the probe immune to a
#     stale or linked `target/` that happens to hold a different shape.
#   * the flag half: `--help` advertises the flag (where one exists), the run
#     prints exactly one record naming the missing frp-server feature, and the
#     process binds **no UDP socket** on the port it named.
#   * the file-key half: the same exactly-one-record and no-UDP-socket checks.
#   * the ordinary `tiny` control: the flag is rejected with
#     `not expected in this context`, the file key prints exactly one record in
#     the **field-less** wording, and no UDP socket is bound.
#   * the default `frps` converse: the flag prints **no** record and the KCP
#     UDP socket **is** bound — so "no socket" and "a socket" are both
#     witnessed, not inferred.
#
# The assertion that runs on every push is the
# `gated_listener_port_records_follow_this_builds_readers` unit test in
# `frp-server/src/service.rs`, which the existing
# `cargo test -p frp-server --no-default-features --all-targets -j 1` lane runs
# in exactly this feature resolution (frp-core's fields on through the
# `frp-client` dev-dependency, frp-server's listeners off). This script is the
# reproducible binary-level measurement for a human, deliberately not wired
# into any lane: adding a step to `.github/workflows/ci.yml` would renumber
# every `ci.yml:NNNN` citation that live files carry, a much larger review
# surface than the behaviour it would witness.
#
# Usage:
#   export PATH="$HOME/.cargo/bin:$PATH"
#   bash scripts/tests/inner-feature-port-probe.sh
# Exit code: 0 when every probe check holds, 1 otherwise. Socket checks that
# cannot run (no `lsof` and no `ss`) are reported as `skip` lines and are not
# counted, so the RESULT total always names only reified checks.
set -uo pipefail

self=${BASH_SOURCE[0]:-$0}
ROOT=$(cd -P -- "$(dirname -- "$self")/../.." && pwd)
cd "$ROOT" || exit 1

if ! command -v cargo >/dev/null 2>&1; then
  printf 'FAIL  cargo not on PATH — run with export PATH="$HOME/.cargo/bin:$PATH"\n' >&2
  exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
  printf 'FAIL  python3 not found — the artifact and free-port helpers need it\n' >&2
  exit 1
fi

# The socket observation tool: `lsof` (macOS, most Linux images) or `ss`
# (iproute2). Without one the socket checks are skipped and reported, never
# silently dropped.
udp_tool=''
if command -v lsof >/dev/null 2>&1; then
  udp_tool=lsof
elif command -v ss >/dev/null 2>&1; then
  udp_tool=ss
fi

work=$(mktemp -d "${TMPDIR:-/tmp}/inner-feature-port-probe.XXXXXX") || exit 1
trap 'rm -rf "$work"' EXIT

ok=0
fail=0
skipped=0
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
skip() {
  skipped=$((skipped + 1))
  printf '  skip  %s\n' "$1"
}

free_tcp_port() {
  python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
}
free_udp_port() {
  python3 - <<'PY'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
}

# build_shape <features> <tier-feature> <inner-feature|-> <binary-name> <label>
#
# Passes `--no-default-features` unless <features> is `full`, extracts the
# executable from cargo's JSON artifact message, and asserts the artifact is
# this worktree's frps binary with the requested tier (and, for the hand-named
# shapes, that a frp-core artifact carries the named inner feature).
build_shape() {
  local features=$1 tier=$2 inner=$3 want_bin=$4 label=$5
  local json="$work/$label.json" err="$work/$label.err"
  printf 'building `%s` ...\n' "$features"
  local args=(-p frps)
  if [ "$features" != "full" ]; then
    args+=(--no-default-features --features "$features")
  fi
  if ! cargo build "${args[@]}" --message-format=json >"$json" 2>"$err"; then
    printf 'FAIL  cargo build -p frps %s failed:\n' "$features" >&2
    tail -20 "$err" >&2
    exit 1
  fi
  local exe
  if ! exe=$(python3 - "$json" "$ROOT" "$tier" "$inner" "$want_bin" <<'PY'
import json, os, sys
path, root, tier, inner, want_bin = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]
frps_manifest = os.path.join(root, "frps", "Cargo.toml")
core_prefix = os.path.join(root, "frp-core") + os.sep
bins = []
core_feature_sets = []
for line in open(path, encoding="utf-8"):
    line = line.strip()
    if not line.startswith("{"):
        continue
    try:
        m = json.loads(line)
    except ValueError:
        continue
    if m.get("reason") != "compiler-artifact":
        continue
    manifest = m.get("manifest_path", "")
    if manifest == frps_manifest and m.get("target", {}).get("kind") == ["bin"]:
        if m.get("executable"):
            bins.append(m)
    if manifest.startswith(core_prefix):
        core_feature_sets.append(set(m.get("features") or []))
if len(bins) != 1:
    print("ARTIFACTS:%d" % len(bins)); sys.exit(2)
art = bins[0]
if art["target"]["name"] != want_bin:
    print("BINNAME:%s" % art["target"]["name"]); sys.exit(3)
feats = set(art.get("features") or [])
if tier not in feats:
    print("TIER:%s not in %s" % (tier, sorted(feats))); sys.exit(4)
if inner != "-" and not any(inner in fs for fs in core_feature_sets):
    print("INNER:%s not in any frp-core artifact" % inner); sys.exit(5)
print(art["executable"])
PY
  ); then
    printf 'FAIL  the `%s` build did not produce the expected frps artifact (see %s)\n' \
      "$features" "$json" >&2
    printf '      cargo reported: %s\n' "$exe" >&2
    exit 1
  fi
  if [ ! -x "$exe" ]; then
    printf 'FAIL  cargo reported `%s` as the %s executable, but it is not executable\n' \
      "$exe" "$want_bin" >&2
    exit 1
  fi
  # Freshness guard: a stale or linked `target/` from another tree can leave a
  # binary older than the sources this probe is asserting about. Cargo should
  # rebuild, but the probe does not take that on trust.
  local newer
  newer=$(find frp-core frp-server frps -name '*.rs' -newer "$exe" -print -quit)
  if [ -n "$newer" ]; then
    printf 'FAIL  `%s` is older than %s — the target is stale, refusing to probe it\n' \
      "$exe" "$newer" >&2
    exit 1
  fi
  cp "$exe" "$work/$label" || exit 1
}

LAST_OUT=""
LAST_UDP=""
# Run one binary with a config file in its own directory, snapshot its UDP
# sockets while it is alive, then stop it. `run_snapshot <binary> <config-body>
# [argv...]`.
run_snapshot() {
  local bin=$1 body=$2
  shift 2
  local dir="$work/run.$$"
  rm -rf "$dir"
  mkdir -p "$dir"
  printf '%s\n' "$body" > "$dir/frps.toml"
  ( cd "$dir" && exec "$bin" "$@" ) > "$dir/out.txt" 2>&1 &
  local pid=$!
  sleep 2
  case $udp_tool in
    lsof) LAST_UDP=$(lsof -nP -a -p "$pid" -iUDP 2>/dev/null || true) ;;
    ss) LAST_UDP=$(ss -lunpH 2>/dev/null | grep "pid=$pid" || true) ;;
    *) LAST_UDP='' ;;
  esac
  kill "$pid" 2>/dev/null
  wait "$pid" 2>/dev/null
  LAST_OUT=$(cat "$dir/out.txt")
}

udp_count() {
  # udp_count <port> — ERE, because BSD grep does not treat `\|` as
  # alternation in BRE, which silently made every match count 0.
  if [ -z "$udp_tool" ]; then
    printf '?\n'
    return
  fi
  printf '%s\n' "$LAST_UDP" | grep -cE "[:.]$1(\$| )" || true
}
check_ge() {
  # check_ge <description> <minimum> <actual>
  if [ "$3" -ge "$2" ] 2>/dev/null; then
    ok=$((ok + 1))
    printf '  ok  %s (%s)\n' "$1" "$3"
  else
    fail=$((fail + 1))
    printf 'FAIL  %s (expected >= %s, got %s)\n' "$1" "$2" "$3"
  fi
}
check_udp_absent() {
  if [ -z "$udp_tool" ]; then
    skip "$1 (no lsof/ss on this host)"
    return
  fi
  check "$1" 0 "$(udp_count "$2")"
}
check_udp_present() {
  if [ -z "$udp_tool" ]; then
    skip "$1 (no lsof/ss on this host)"
    return
  fi
  check_ge "$1" 1 "$(udp_count "$2")"
}

# The flag half + file-key half + no-socket checks for one hand-named shape.
probe_flagged_shape() {
  local label=$1 key=$2 flag=$3 fileline=$4
  local bin="$work/$label" port udp
  port=$(free_tcp_port)
  udp=$(free_udp_port)

  check "$label: --help advertises $flag" 1 \
    "$("$bin" --help 2>&1 | grep -c -- "$flag")"

  run_snapshot "$bin" "bind_port = $port" "$flag" "$udp"
  check "$label: flag prints exactly one $key record" 1 \
    "$(printf '%s' "$LAST_OUT" | grep -c -- "$key" || true)"
  check "$label: flag record names the missing frp-server feature" 1 \
    "$(printf '%s' "$LAST_OUT" | grep -c 'frp-core compiled the field' || true)"
  check_udp_absent "$label: flag run binds no UDP socket on its port" "$udp"

  run_snapshot "$bin" "bind_port = $port
$fileline"
  check "$label: file key prints exactly one $key record" 1 \
    "$(printf '%s' "$LAST_OUT" | grep -c -- "$key" || true)"
  check "$label: file-key record names the missing frp-server feature" 1 \
    "$(printf '%s' "$LAST_OUT" | grep -c 'frp-core compiled the field' || true)"
  check_udp_absent "$label: file-key run binds no UDP socket on its port" "$udp"
}

printf '== hand-named `tiny,frp-core/kcp` ==\n'
build_shape "tiny,frp-core/kcp" tiny kcp frps-tiny frps-tiny-kcp
probe_flagged_shape frps-tiny-kcp kcp_bind_port --kcp-bind-port "kcp_bind_port = 41701"

printf '== hand-named `tiny,frp-core/quic` ==\n'
build_shape "tiny,frp-core/quic" tiny quic frps-tiny frps-tiny-quic
probe_flagged_shape frps-tiny-quic quic_bind_port --quic-bind-port "quic_bind_port = 41703"

printf '== hand-named `micro,frp-core/kcp` ==\n'
build_shape "micro,frp-core/kcp" micro kcp frps-micro frps-micro-kcp
probe_flagged_shape frps-micro-kcp kcp_bind_port --kcp-bind-port "kcp_bind_port = 41705"

printf '== hand-named `tiny,frp-core/websocket` (file key only: no flag) ==\n'
build_shape "tiny,frp-core/websocket" tiny websocket frps-tiny frps-tiny-ws
port=$(free_tcp_port)
udp=$(free_udp_port)
run_snapshot "$work/frps-tiny-ws" "bind_port = $port
websocket_port = $udp"
check "frps-tiny-ws: websocket_port file key prints exactly one record" 1 \
  "$(printf '%s' "$LAST_OUT" | grep -c websocket_port || true)"
check "frps-tiny-ws: file-key record names the missing frp-server feature" 1 \
  "$(printf '%s' "$LAST_OUT" | grep -c 'frp-core compiled the field' || true)"
check_udp_absent "frps-tiny-ws: file-key run binds no UDP socket on its port" "$udp"

printf '== ordinary `tiny` (control: flag rejected, file key warns) ==\n'
build_shape "tiny" tiny - frps-tiny frps-tiny-tiny
port=$(free_tcp_port)
udp=$(free_udp_port)
run_snapshot "$work/frps-tiny-tiny" "bind_port = $port" --kcp-bind-port "$udp"
check "frps-tiny: --kcp-bind-port is rejected" 1 \
  "$(printf '%s' "$LAST_OUT" | grep -c 'not expected in this context' || true)"
check "frps-tiny: the rejection is not a record" 0 \
  "$(printf '%s' "$LAST_OUT" | grep -c 'kcp_bind_port has no effect' || true)"
run_snapshot "$work/frps-tiny-tiny" "bind_port = $port
kcp_bind_port = $udp"
check "frps-tiny: file key prints exactly one record" 1 \
  "$(printf '%s' "$LAST_OUT" | grep -c kcp_bind_port || true)"
check "frps-tiny: file-key record uses the field-less wording" 1 \
  "$(printf '%s' "$LAST_OUT" | grep -c "frp-core's .kcp. feature is off" || true)"
check_udp_absent "frps-tiny: file-key run binds no UDP socket on its port" "$udp"

printf '== default `frps` (converse: honoured listener binds, no record) ==\n'
build_shape "full" full - frps frps-full
port=$(free_tcp_port)
udp=$(free_udp_port)
run_snapshot "$work/frps-full" "bind_port = $port
auth.token = \"m10probe\"" --kcp-bind-port "$udp"
check "frps-full: --kcp-bind-port prints no record" 0 \
  "$(printf '%s' "$LAST_OUT" | grep -c 'kcp_bind_port has no effect' || true)"
check_udp_present "frps-full: the honoured KCP port is bound" "$udp"
check_ge "frps-full: the KCP listener started" 1 \
  "$(printf '%s' "$LAST_OUT" | grep -c 'KCP listener started' || true)"

printf '\ninner-feature-port-probe: %d check(s) hold, %d failure(s), %d skipped\n' \
  "$ok" "$fail" "$skipped"
if [ "$fail" = "0" ]; then
  printf 'RESULT: %d probe check(s) hold\n' "$ok"
  exit 0
fi
printf 'RESULT: %d probe check(s) failed\n' "$fail"
exit 1
