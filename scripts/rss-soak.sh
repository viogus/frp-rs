#!/usr/bin/env bash
# =============================================================================
# frp-rs RSS soak: a head-to-head resident-memory time series, frp-rs vs Go frp.
#
# Answers the TODO item "The 'no GC => stable RSS over weeks' claim has no
# long-uptime evidence". Both stacks run CONCURRENTLY with the same proxy set
# and the same traffic recipe for the whole window, and RSS is sampled for all
# four processes every `interval` seconds. No process is restarted mid-run; if
# one dies, or if either side's traffic moved nothing, the series is marked
# aborted instead of silently published.
#
# What the numbers DO show:
#   * how each implementation's RSS moves over hours under identical, paced
#     offered load on one host, sampled side by side.
# What they DO NOT show:
#   * RSS is not live heap. It includes allocator retention, page-fault and
#     page-cache effects, and memory the OS has not reclaimed yet; a flat RSS
#     is consistent with both "no leak" and "allocator never returned memory".
#   * weeks. A multi-hour window bounds growth over hours, not over weeks —
#     the claim it tests is directional, and the positioning docs must not be
#     stronger than the window.
#   * an isolated stack. Both stacks share the host, so a machine-level effect
#     (thermal, memory pressure, another tenant) moves BOTH series; running
#     them concurrently is what makes that a shared, not a differential,
#     confound, and host load is logged on every sample so a reader can see it.
#   * full proxy surface. One TCP proxy per stack; UDP/HTTP/STCP/XTCP and the
#     encryption/compression/mux paths are not exercised here.
#
# Why its own script instead of memory-baseline.sh: that baseline is short,
# runs frp-rs only, and its primary metric is the mem-profile allocator counter
# (`live=`/`total=`), which does not exist in Go. RSS is the only metric both
# implementations can report, so the soak measures PLAIN release binaries and
# leaves memory-baseline.sh's non-soak behaviour untouched.
#
# Usage:
#   bash scripts/rss-soak.sh [duration_s] [interval_s]
#   bash scripts/rss-soak.sh -h | --help
#     duration_s   soak window; default 10800 (3 h), minimum 60
#     interval_s   sample interval; default 45 (the item asks for 30-60 s)
#   -h / --help prints this header and exits 0.
#
# Env:
#   FRPS_BIN / FRPC_BIN   frp-rs binaries; set both to skip the cargo build
#   GO_FRP_DIR            Go frp release dir (default /tmp/frp_<ver>_<platform>)
#   SOAK_OUT              artifact path (default scripts/frp-stress/baselines/
#                         rss-soak-<host>.jsonl). Set it for a throwaway
#                         validation run so a real soak's artifact is not
#                         clobbered.
#   SOAK_RUN_DIR          scratch dir for configs/logs (default /tmp/rss-soak).
#                         Cleared of the previous run's traffic rows before the
#                         window opens (see "traffic evidence" below); "" and "/"
#                         are refused.
#   SOAK_LOCK             single-run lock (default /tmp/rss-soak.lock)
#   SOAK_RS_CONTROL       frp-rs frps control port     (default 18100)
#   SOAK_RS_REMOTE        frp-rs frpc remote port      (default 18101)
#   SOAK_RS_ECHO          frp-rs echo backend port     (default 18102)
#   SOAK_GO_CONTROL       Go frps control port         (default 18200)
#   SOAK_GO_REMOTE        Go frpc remote port          (default 18201)
#   SOAK_GO_ECHO          Go echo backend port         (default 18202)
#                         The six port overrides exist so a validation run can
#                         stand beside a live soak without fighting for ports;
#                         paired with its own SOAK_RUN_DIR/SOAK_OUT/SOAK_LOCK.
#                         All six are validated and recorded in `meta`.
#   SOAK_CHURN_CONNS      short-lived connections in flight (default 8)
#   SOAK_CHURN_RATE       churn connection starts/s per stack (default 40;
#                         0 = unpaced, which will exhaust ephemeral ports).
#                         Keep this modest: every closed connection parks
#                         sockets in TIME_WAIT for ~30 s on macOS, so the
#                         rate x TIME_WAIT x 2 stacks must stay well inside
#                         the 16 384-port ephemeral range. The per-sample
#                         `time_wait` count is the host-level check (it counts
#                         the whole machine, so it is context, not one side's
#                         number — see below).
#   SOAK_STREAMS          long-lived byte streams per stack (default 3)
#   SOAK_STREAM_MBPS      per-stream cap (default 5; 0 = unpaced). NOTE the cap
#                         is applied to a counter that adds bytes SENT and
#                         RECEIVED, so 5 means ~2.5 MiB/s of payload in each
#                         direction, not 5 MiB/s in one.
#   SOAK_MSG_BYTES        bytes per churn message (default 64)
#   SOAK_TRAFFIC_TOLERANCE
#                         allowed relative spread between the two sides'
#                         achieved volume (default 0.10 = 10%). A finite number
#                         in (0, 1]; anything else is refused up front, because
#                         the summary's `spread > tolerance` test is silently
#                         disabled by `nan` (compares false with everything).
#   SOAK_RSS_CEILING_KB   largest RSS reading accepted as real (default
#                         1048576 = 1 GiB). A value outside 1..ceiling, or a
#                         non-integer, is recorded as `null` (a missing reading)
#                         rather than published: a stubbed or misparsing `ps`
#                         that prints a constant, 0, or a huge number must not
#                         produce a "perfectly flat" series. The reader applies
#                         the artifact's OWN recorded ceiling to an artifact it
#                         did not produce, so the verdict does not change with
#                         the reader's environment; this variable is only the
#                         fallback for an artifact that records none. The
#                         default is justified by the committed baselines in
#                         scripts/frp-stress/baselines/README.md.
#
# Output: scripts/frp-stress/baselines/rss-soak-<hostname>.jsonl
#   one JSON object per line: one `meta` record, N `sample` records, one
#   `summary` record. The summary is also printed to stdout. An artifact
#   WITHOUT a trailing `summary` record is an incomplete run — that is a
#   convention for whoever reads the series, NOT an enforced check: the script
#   cannot append a record after a SIGKILL.
#
# Traffic evidence (why the run dir is cleared before the window opens):
#   the achieved-load cross-check reads $SOAK_RUN_DIR/{rs,go}-{churn,steady}.json,
#   and a generator only writes its row when it FINISHES. A generator that dies
#   early would otherwise leave the PREVIOUS run's row in place, and the summary
#   would publish that borrowed row under `"aborted": null`. So the four rows and
#   the artifact are deleted after pre-flight passes and before the first sample,
#   and the generators are given a tail longer than the window so that any one of
#   them dying during the window is a fault with no grace period.
#
# Guards (abort rather than publish an apples-to-oranges series):
#   * only one soak runs at a time (lock file), so a short validation run
#     cannot steal the ports of, or overwrite the artifact of, a live soak
#   * every cargo build used by the run must succeed (a stale binary is never
#     used silently)
#   * the Go binaries are for THIS os/arch (checked with `file`)
#   * the Go binaries self-report the version frp-rs targets (`--version`)
#   * the frp-rs binaries self-report that same version
#   * a pre-flight churn on each side must complete at least one echo round
#     trip before the window opens — a bridge that accepts but moves no bytes
#     fails here rather than after three hours. A pre-flight failure exits 1
#     and writes NO artifact (the artifact is cleared only after pre-flight).
#   * the four frp processes and the two echo backends have no self-imposed end,
#     so they are scanned at EVERY iteration, including the last one — the scan
#     runs before the window-end test, so a death anywhere in the window is a
#     fault (the summary is appended with a non-null `aborted` reason and the
#     script exits 3)
#   * the four traffic generators DO end by design (GENERATOR_TAIL seconds past
#     the window), so they are scanned only while the window is open; one that
#     dies inside the window is a fault, and one that never wrote its result row
#     is caught after the window by the summary's traffic reconciliation
#   * an RSS reading is published only when it is a positive integer within
#     SOAK_RSS_CEILING_KB; anything else becomes `null`, so a stubbed `ps`
#     cannot produce a flat series, and the reader additionally refuses a column
#     in which every reading is identical (see SOAK_RSS_CEILING_KB above)
#   * the frp-rs and Go binaries must not be the same file or carry the same
#     sha256 — running one implementation on both sides would be published as a
#     head-to-head comparison otherwise (the reader re-checks this in `meta`)
#   * after the window, each side must have completed churn round trips and
#     moved bytes on its long-lived streams, with no torn-down stream, with
#     those totals above a documented floor, and the two sides must have
#     achieved comparable volume (they are paced the same, so a large gap means
#     one side was not handed the same work)
#
# Death reasons: `aborted` names each dead process with the raw `wait` status,
# which is NOT a signal classification — frp-rs traps SIGTERM and exits 0, so
# `frps(exit 0)` means "stopped by itself or was asked to stop", and a
# signal-killed process shows 128+N (`137` for SIGKILL). Only the elapsed time
# and the traffic cross-check say which of those it was.
#
# The per-sample `time_wait` field is HOST-WIDE (netstat counts every socket on
# the machine, other tenants included): it is context for the reader, not a
# per-side check. The per-side check is the paced churn rate plus the achieved
# round-trip count reconciled in the summary.
#
# Self-description: `meta` records the git HEAD, whether the HARNESS corpus
# (this script, its helpers and the traffic generator under scripts/frp-stress)
# had uncommitted changes, and sha256 digests of each part, so an artifact can
# be matched to the exact code that produced it even when the commit alone is
# not enough. `rs_bin_source` says whether the measured frp-rs binaries were
# built from that tree or supplied by the caller; `bin_sha256` is the identity
# of the binaries that were actually measured either way.
# =============================================================================
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR" || exit 1

# Run-directory policy (degenerate-path refusal + clearing a previous run's
# traffic rows). Separate file so the fixture scripts/tests/rss-soak-run-dir.sh
# can drive the real thing instead of a copy of it.
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib/rss-soak-run-dir.sh
. "$SCRIPT_DIR/lib/rss-soak-run-dir.sh"

# `-h`/`--help` prints this header (the leading comment block) and stops before
# any side effect: awk strips the `# ` so the text above IS the help.
case "${1:-}" in
  -h|--help)
    awk 'NR == 1 { next } /^#/ { sub(/^# ?/, ""); print; next } { exit }' "$0"
    exit 0
    ;;
esac

DURATION="${1:-10800}"
INTERVAL="${2:-45}"
# Refusal lives in the sourced lib so the fixture can prove it without starting
# a run; see scripts/lib/rss-soak-run-dir.sh.
rss_soak_validate_window "$DURATION" "$INTERVAL" || exit 1

# The traffic generators outlive the window by GENERATOR_TAIL seconds, so that
# every one of them is still alive when the last sample is taken: a generator
# dying inside the window is then a fault with NO grace period, with no
# sensitivity to how late the post-launch `sleep` returned. Their result rows are
# collected in a bounded wait after the window closes. With the old design
# (generators ran ~2 s short of the window, death check disabled near the end) a
# generator could die inside the last INTERVAL+5 s and the run would still say
# "run completed".
GENERATOR_TAIL=20
GEN_DURATION=$(( DURATION + GENERATOR_TAIL ))

validate_port() {
  local name="$1" val="$2"
  if ! [[ "$val" =~ ^[0-9]+$ ]] || [ "$val" -lt 1 ] || [ "$val" -gt 65535 ]; then
    echo "error: $name must be a TCP port 1-65535 (got '$val')" >&2
    exit 1
  fi
}

RS_PORT="${SOAK_RS_CONTROL:-18100}"; validate_port SOAK_RS_CONTROL "$RS_PORT"
RS_REMOTE="${SOAK_RS_REMOTE:-18101}"; validate_port SOAK_RS_REMOTE "$RS_REMOTE"
RS_ECHO="${SOAK_RS_ECHO:-18102}"; validate_port SOAK_RS_ECHO "$RS_ECHO"
GO_PORT="${SOAK_GO_CONTROL:-18200}"; validate_port SOAK_GO_CONTROL "$GO_PORT"
GO_REMOTE="${SOAK_GO_REMOTE:-18201}"; validate_port SOAK_GO_REMOTE "$GO_REMOTE"
GO_ECHO="${SOAK_GO_ECHO:-18202}"; validate_port SOAK_GO_ECHO "$GO_ECHO"
ALL_PORTS="$RS_PORT $RS_REMOTE $RS_ECHO $GO_PORT $GO_REMOTE $GO_ECHO"
for p in $ALL_PORTS; do
  n=0
  for q in $ALL_PORTS; do [ "$p" = "$q" ] && n=$(( n + 1 )); done
  if [ "$n" -gt 1 ]; then
    echo "error: port $p is used by more than one role ($ALL_PORTS)" >&2
    exit 1
  fi
done

TOKEN="rss-soak-token"
CHURN_CONNS="${SOAK_CHURN_CONNS:-8}"
CHURN_RATE="${SOAK_CHURN_RATE:-40}"
STREAMS="${SOAK_STREAMS:-3}"
STREAM_MBPS="${SOAK_STREAM_MBPS:-5}"
MSG_BYTES="${SOAK_MSG_BYTES:-64}"
OUT="${SOAK_OUT:-scripts/frp-stress/baselines/rss-soak-$(hostname -s).jsonl}"
RUN_DIR="${SOAK_RUN_DIR:-/tmp/rss-soak}"
LOCK_FILE="${SOAK_LOCK:-/tmp/rss-soak.lock}"

# Validate every knob that feeds the traffic recipe. A knob that silently means
# something else would make `meta` a lie: SOAK_STREAMS=0 would fall through to
# the generator's clap default (100 streams) while `meta` recorded 0, and
# SOAK_MSG_BYTES=0 becomes 1 byte inside the generator while `meta` recorded 0.
validate_count() {
  local name="$1" val="$2" min="$3"
  if ! [[ "$val" =~ ^[0-9]+$ ]] || [ "$val" -lt "$min" ]; then
    echo "error: $name must be an integer >= $min (got '$val')" >&2
    exit 1
  fi
}
validate_count SOAK_CHURN_CONNS "$CHURN_CONNS" 1
validate_count SOAK_CHURN_RATE "$CHURN_RATE" 0
validate_count SOAK_STREAMS "$STREAMS" 1
validate_count SOAK_STREAM_MBPS "$STREAM_MBPS" 0
validate_count SOAK_MSG_BYTES "$MSG_BYTES" 1
# Refused up front (not only in the reader) so a bad tolerance cannot cost a
# three-hour window; exported so the reader validates the SAME value.
TOLERANCE="${SOAK_TRAFFIC_TOLERANCE:-0.10}"
rss_soak_validate_tolerance "$TOLERANCE" || exit 1
export SOAK_TRAFFIC_TOLERANCE="$TOLERANCE"
RSS_CEILING_KB="${SOAK_RSS_CEILING_KB:-1048576}"
validate_count SOAK_RSS_CEILING_KB "$RSS_CEILING_KB" 1
export SOAK_RSS_CEILING_KB="$RSS_CEILING_KB"

# Resolve + create the run dir, create the artifact's directory, and echo the
# resolved absolute path (recorded in `meta`); refuses "" and "/" outright.
# Done BEFORE the lock: a rejected SOAK_RUN_DIR must not leave a lock file
# behind (the EXIT trap is installed further down).
RUN_DIR=$(rss_soak_prepare_run_dir "$RUN_DIR" "$OUT") || exit 1

# ------------------------------------------------------------ one soak only
# Two soaks would fight over the fixed ports and the last writer would own the
# artifact. The lock is taken with `set -o noclobber` — create-if-absent in ONE
# atomic step: the previous test-then-`echo $$ >` sequence let two simultaneous
# starts both pass the test and both believe they held the lock. A stale lock
# (non-empty pid that is gone) is reclaimed and retried, bounded; an EMPTY lock
# is treated as held, because the winner has a two-command create-then-write
# window and stealing it there is what the atomic create was meant to prevent.
# A validation run sharing the host needs its own SOAK_LOCK and its own ports.
LOCK_ATTEMPTS=0
while :; do
  if ( set -o noclobber; echo $$ > "$LOCK_FILE" ) 2>/dev/null; then
    break
  fi
  old_lock=$(cat "$LOCK_FILE" 2>/dev/null || true)
  # An EMPTY lock is HELD, not stale. The winner creates the file with
  # `set -o noclobber` and writes its pid in the very next command, so a second
  # start that read the file between those two steps used to see `old_lock=''`,
  # call the lock stale, `rm` it and take it — two soaks on the same ports. The
  # cost of refusing is a manual `rm` only when a crash happened inside that same
  # two-command window.
  if [ -z "$old_lock" ]; then
    echo "error: lock $LOCK_FILE exists but is empty (another soak is starting up, or a crash left it)." >&2
    echo "       Refusing to steal it; remove $LOCK_FILE by hand only if no soak is running." >&2
    exit 1
  fi
  if kill -0 "$old_lock" 2>/dev/null; then
    echo "error: another rss-soak is already running (pid $old_lock)." >&2
    echo "       Refusing to start; stop it or remove $LOCK_FILE if it is stale." >&2
    exit 1
  fi
  echo "warning: reclaiming stale lock $LOCK_FILE (pid ${old_lock:-unknown} is gone)" >&2
  rm -f "$LOCK_FILE"
  LOCK_ATTEMPTS=$(( LOCK_ATTEMPTS + 1 ))
  if [ "$LOCK_ATTEMPTS" -gt 5 ]; then
    echo "error: could not acquire lock $LOCK_FILE after $LOCK_ATTEMPTS attempts" >&2
    exit 1
  fi
done

FRP_NAMES=(); FRP_PIDS=()
# Echo backends are tracked separately from the traffic generators: they have no
# self-imposed end, so they are scanned at every iteration (a generator that runs
# past the window is not a fault — see GENERATOR_TAIL).
ECHO_NAMES=(); ECHO_PIDS=()
GEN_NAMES=(); GEN_PIDS=()
TRAFFIC_NAMES=(); TRAFFIC_PIDS=()
ALL_PIDS=()
WATCHDOG_PID=""
add_frp() { FRP_NAMES+=("$1"); FRP_PIDS+=("$2"); ALL_PIDS+=("$2"); }
add_echo() { ECHO_NAMES+=("$1"); ECHO_PIDS+=("$2"); ALL_PIDS+=("$2"); }
add_gen() { GEN_NAMES+=("$1"); GEN_PIDS+=("$2"); ALL_PIDS+=("$2"); }
add_traffic() { TRAFFIC_NAMES+=("$1"); TRAFFIC_PIDS+=("$2"); add_gen "$1" "$2"; }

cleanup() {
  local p
  [ -n "$WATCHDOG_PID" ] && kill "$WATCHDOG_PID" 2>/dev/null
  for p in "${ALL_PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null; done
  sleep 1
  for p in "${ALL_PIDS[@]:-}"; do [ -n "$p" ] && kill -9 "$p" 2>/dev/null; done
  if [ -f "$LOCK_FILE" ] && [ "$(cat "$LOCK_FILE" 2>/dev/null || true)" = "$$" ]; then
    rm -f "$LOCK_FILE"
  fi
  return 0
}

# SIGINT/SIGTERM are handled so the loop can stop, write an aborted summary and
# still leave no orphan processes (the EXIT trap runs on normal exit and after
# the signal handler returns). A second signal exits immediately.
SIGNALLED=0
on_signal() {
  if [ "$SIGNALLED" = 1 ]; then
    echo "second signal: exiting immediately" >&2
    exit 130
  fi
  SIGNALLED=1
  echo "signal received: stopping after this iteration" >&2
}
trap cleanup EXIT
trap on_signal INT TERM

BUILD_LOG="$RUN_DIR/build.log"
echo "=== Building the frp-stress traffic generator ==="
# Output goes to a log and the STATUS is checked: the old `cargo build … | tail -2`
# turned every failure into success (the pipeline's status is tail's) and a stale
# pre-built binary was then used silently.
if ! (cd scripts/frp-stress && cargo build --release) >"$BUILD_LOG" 2>&1; then
  echo "error: cargo build failed for scripts/frp-stress (log: $BUILD_LOG)" >&2
  tail -5 "$BUILD_LOG" >&2
  exit 1
fi
tail -2 "$BUILD_LOG"
STRESS=./scripts/frp-stress/target/release/frp-stress

if [ -z "${FRPS_BIN:-}" ] || [ -z "${FRPC_BIN:-}" ]; then
  echo "=== Building plain release frps/frpc (set FRPS_BIN/FRPC_BIN to skip) ==="
  if ! cargo build --release -p frps -p frpc >"$BUILD_LOG" 2>&1; then
    echo "error: cargo build failed for -p frps -p frpc (log: $BUILD_LOG)" >&2
    tail -5 "$BUILD_LOG" >&2
    exit 1
  fi
  tail -2 "$BUILD_LOG"
else
  echo "=== Using FRPS_BIN=$FRPS_BIN FRPC_BIN=$FRPC_BIN (no build) ==="
fi
RS_FRPS="${FRPS_BIN:-./target/release/frps}"
RS_FRPC="${FRPC_BIN:-./target/release/frpc}"
# Recorded in `meta` so a reader can tell whether the measured frp-rs binaries
# came from the recorded commit or were handed in by the caller.
if [ -n "${FRPS_BIN:-}" ] && [ -n "${FRPC_BIN:-}" ]; then
  RS_BIN_SOURCE="caller-supplied FRPS_BIN/FRPC_BIN"
else
  RS_BIN_SOURCE="built from the working tree"
fi

# ---------------------------------------------------------------- versions
rs_version=$(grep -m1 'pub const VERSION' frp-core/src/lib.rs | sed -E 's/.*"([^"]+)".*/\1/')
[ -n "$rs_version" ] || { echo "error: could not read VERSION from frp-core/src/lib.rs" >&2; exit 1; }

host_os=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$(uname -m)" in
  x86_64)        host_arch=amd64; file_marker='x86-64|x86_64' ;;
  arm64|aarch64) host_arch=arm64; file_marker='arm64|aarch64' ;;
  *) echo "error: unsupported host architecture: $(uname -m)" >&2; exit 1 ;;
esac
go_platform="${host_os}_${host_arch}"
GO_DIR="${GO_FRP_DIR:-/tmp/frp_${rs_version}_${go_platform}}"
GO_FRPS="$GO_DIR/frps"
GO_FRPC="$GO_DIR/frpc"

if [ ! -x "$GO_FRPS" ] || [ ! -x "$GO_FRPC" ]; then
  echo "error: Go frp binaries not found in $GO_DIR." >&2
  echo "       Fetch them with: bash scripts/download-go-frp.sh $rs_version $go_platform" >&2
  exit 1
fi

for bin in "$RS_FRPS" "$RS_FRPC" "$GO_FRPS" "$GO_FRPC" "$STRESS"; do
  [ -x "$bin" ] || { echo "error: not executable: $bin" >&2; exit 1; }
done

if command -v file >/dev/null 2>&1; then
  go_desc=$(file -b "$GO_FRPS")
  printf '%s' "$go_desc" | grep -Eqi "$file_marker" \
    || { echo "error: Go binary is not for this host ($go_platform): $go_desc" >&2; exit 1; }
fi

go_version=$("$GO_FRPS" --version 2>/dev/null | head -1 | tr -d 'v \r\n')
[ "$go_version" = "$rs_version" ] \
  || { echo "error: Go frp version '$go_version' != frp-rs target '$rs_version'" >&2; exit 1; }
rs_reported=$("$RS_FRPS" --version 2>/dev/null | head -1 | tr -d 'v \r\n')
case "$rs_reported" in
  *"$rs_version"*) ;;
  *) echo "error: $RS_FRPS reports '$rs_reported', expected $rs_version" >&2; exit 1 ;;
esac

# Binary digests so a later reader can tell exactly which builds produced the
# series (the version guard alone cannot distinguish two builds of 0.71.0).
sha256_of() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" 2>/dev/null | cut -d' ' -f1
  elif command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" 2>/dev/null | cut -d' ' -f1
  else
    echo "unavailable"
  fi
}
sha256_stream() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 | cut -d' ' -f1
  elif command -v sha256sum >/dev/null 2>&1; then
    sha256sum | cut -d' ' -f1
  else
    echo "unavailable"
  fi
}

rs_sha=$(git -C "$PROJECT_DIR" rev-parse HEAD 2>/dev/null || echo unknown)
rs_sha_short=$(git -C "$PROJECT_DIR" rev-parse --short HEAD 2>/dev/null || echo unknown)
cpu_cores=$(sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo 0)
# Self-description: `rs_dirty` is true when the working tree had uncommitted
# changes to the HARNESS corpus — this script, its helpers AND the traffic
# generator under scripts/frp-stress, which is what actually writes the traffic
# rows — so an artifact cannot silently pass for a clean commit's output. The
# digests pin the exact harness files that ran: a commit sha alone cannot,
# because a soak can be launched from a dirty tree, and the measured frp-rs
# binary is not always built from the recorded commit at all (see
# `rs_bin_source`).
HARNESS_PATHS=(scripts/rss-soak.sh scripts/lib scripts/frp-stress/src scripts/frp-stress/Cargo.toml)
if [ -n "$(git -C "$PROJECT_DIR" status --porcelain -- "${HARNESS_PATHS[@]}" 2>/dev/null)" ]; then
  rs_dirty=true
else
  rs_dirty=false
fi
# Digest of the generator sources AS THEY EXIST ON DISK (path + content hash per
# file), so a published artifact can be matched to the generator that produced
# it even when the tree was clean at a different commit.
stress_tree_sha=$(
  cd "$PROJECT_DIR" || exit 1
  find scripts/frp-stress/src scripts/frp-stress/Cargo.toml -type f -print 2>/dev/null \
    | LC_ALL=C sort \
    | while IFS= read -r f; do printf '%s ' "$f"; sha256_of "$f"; printf '\n'; done
)
stress_tree_sha=$(printf '%s\n' "$stress_tree_sha" | sha256_stream)
soak_sha=$(sha256_of "$SCRIPT_DIR/rss-soak.sh")
run_dir_lib_sha=$(sha256_of "$SCRIPT_DIR/lib/rss-soak-run-dir.sh")
summary_py_sha=$(sha256_of "$SCRIPT_DIR/lib/rss-soak-summary.py")
# The identity of the binaries that were ACTUALLY measured. Comparing the two
# sides here is what stops a run in which the caller pointed FRPS_BIN/FRPC_BIN at
# the Go binaries from being published as a head-to-head comparison.
rs_frps_sha=$(sha256_of "$RS_FRPS"); rs_frpc_sha=$(sha256_of "$RS_FRPC")
go_frps_sha=$(sha256_of "$GO_FRPS"); go_frpc_sha=$(sha256_of "$GO_FRPC")
if [ "$rs_frps_sha" = "$go_frps_sha" ] || [ "$rs_frpc_sha" = "$go_frpc_sha" ]; then
  echo "error: the frp-rs and Go binaries are identical (sha256 $rs_frps_sha / $rs_frpc_sha);" >&2
  echo "       this would publish one implementation against itself. Point FRPS_BIN/FRPC_BIN at a" >&2
  echo "       real frp-rs build, or unset them to build from this tree." >&2
  exit 1
fi
echo "frp-rs $rs_version ($rs_sha_short) vs Go frp $go_version on $go_platform, ${cpu_cores} cores"
# The frp-rs sha above is the TREE's, which is only the measured binary's when
# the binary was built from it; print what was actually measured, and where it
# came from, so a caller-supplied pair cannot be read as the tree's build.
echo "measured frp-rs binaries: frps $rs_frps_sha / frpc $rs_frpc_sha ($RS_BIN_SOURCE)"
echo "window ${DURATION}s, sample interval ${INTERVAL}s -> out $OUT"

# ---------------------------------------------------------------- configs
# camelCase TOML: Go's native spelling, and frp-rs's compat layer accepts it
# (the same trick scripts/compare-go-frp.sh uses so ONE config pair drives
# both implementations). Same proxy set on both sides; only ports differ.
write_configs() {
  cat > "$RUN_DIR/rs-frps.toml" <<EOF
bindAddr = "127.0.0.1"
bindPort = $RS_PORT
[auth]
method = "token"
token = "$TOKEN"
[log]
level = "error"
EOF
  cat > "$RUN_DIR/rs-frpc.toml" <<EOF
serverAddr = "127.0.0.1"
serverPort = $RS_PORT
loginFailExit = true
[auth]
method = "token"
token = "$TOKEN"
[log]
level = "error"
[[proxies]]
name = "soak-tcp"
type = "tcp"
localIP = "127.0.0.1"
localPort = $RS_ECHO
remotePort = $RS_REMOTE
EOF
  cat > "$RUN_DIR/go-frps.toml" <<EOF
bindAddr = "127.0.0.1"
bindPort = $GO_PORT
[auth]
method = "token"
token = "$TOKEN"
[log]
level = "error"
EOF
  cat > "$RUN_DIR/go-frpc.toml" <<EOF
serverAddr = "127.0.0.1"
serverPort = $GO_PORT
loginFailExit = true
[auth]
method = "token"
token = "$TOKEN"
[log]
level = "error"
[[proxies]]
name = "soak-tcp"
type = "tcp"
localIP = "127.0.0.1"
localPort = $GO_ECHO
remotePort = $GO_REMOTE
EOF
}
write_configs

alive() { kill -0 "$1" 2>/dev/null; }

# port_open <host:port> -> 0 when a TCP connect succeeds (proxy registered).
port_open() { (exec 3<>"/dev/tcp/${1%:*}/${1#*:}") 2>/dev/null; }

# RSS in KB, or the JSON literal `null` when the reading is not usable. The
# plausibility rules (positive integer within SOAK_RSS_CEILING_KB) live in
# scripts/lib/rss-soak-run-dir.sh so the fixture can drive them against a stubbed
# `ps` without starting a soak; see rss_soak_rss_kb there for why a non-empty
# check alone is not enough.
rss_kb() { rss_soak_rss_kb "$1" "$RSS_CEILING_KB"; }
load1() {
  local v
  v=$(uptime | sed -E 's/.*load average[s]?: ([0-9.]+).*/\1/')
  case "$v" in
    [0-9]*) printf '%s' "$v" ;;
    *) printf 'null' ;;
  esac
}
time_wait_count() {
  local n
  n=$(netstat -an -p tcp 2>/dev/null | grep -c TIME_WAIT || true)
  printf '%s' "${n:-0}"
}

# json_field <file> <key> -> value or 0. Used to read a generator's result row.
json_field() {
  python3 -c 'import json,sys
try:
    print(json.load(open(sys.argv[1]))[sys.argv[2]])
except Exception:
    print(0)' "$1" "$2" 2>/dev/null || echo 0
}

# ---------------------------------------------------------------- stand up
"$STRESS" --scenario echo --port "$RS_ECHO" >"$RUN_DIR/rs-echo.log" 2>&1 & add_echo "rs-echo" $!
"$STRESS" --scenario echo --port "$GO_ECHO" >"$RUN_DIR/go-echo.log" 2>&1 & add_echo "go-echo" $!
sleep 1

"$RS_FRPS" -c "$RUN_DIR/rs-frps.toml" >"$RUN_DIR/rs-frps.log" 2>&1 & add_frp "frp-rs-frps" $!
"$GO_FRPS" -c "$RUN_DIR/go-frps.toml" >"$RUN_DIR/go-frps.log" 2>&1 & add_frp "go-frps" $!
sleep 1
"$RS_FRPC" -c "$RUN_DIR/rs-frpc.toml" >"$RUN_DIR/rs-frpc.log" 2>&1 & add_frp "frp-rs-frpc" $!
"$GO_FRPC" -c "$RUN_DIR/go-frpc.toml" >"$RUN_DIR/go-frpc.log" 2>&1 & add_frp "go-frpc" $!

RS_FRPS_PID="${FRP_PIDS[0]}"; GO_FRPS_PID="${FRP_PIDS[1]}"
RS_FRPC_PID="${FRP_PIDS[2]}"; GO_FRPC_PID="${FRP_PIDS[3]}"

for p in "${FRP_PIDS[@]}"; do
  alive "$p" || { echo "error: a frps/frpc process exited during startup; see $RUN_DIR/*.log" >&2; exit 1; }
done

# Wait (bounded) for both proxies to register: frps binds the remote port only
# once frpc's login + NewProxy have succeeded.
register_deadline=$(( $(date +%s) + 30 ))
while :; do
  if port_open "127.0.0.1:$RS_REMOTE" && port_open "127.0.0.1:$GO_REMOTE"; then break; fi
  if [ "$(date +%s)" -ge "$register_deadline" ]; then
    echo "error: proxies did not register within 30s (rs=$RS_REMOTE go=$GO_REMOTE)" >&2
    tail -5 "$RUN_DIR/rs-frpc.log" "$RUN_DIR/go-frpc.log" 2>/dev/null >&2
    exit 1
  fi
  sleep 1
done
echo "both proxies registered"

# --------------------------------------------------- pre-flight data check
# Registration proves a listener exists, not that bytes cross the bridge. A
# half-open bridge would otherwise produce a beautiful flat RSS series.
preflight() {
  local stack="$1" remote="$2" ctrl="$3"
  local file="$RUN_DIR/$stack-preflight.json"
  rm -f "$file"
  "$STRESS" --scenario memory --mode churn --port "$remote" --frps-addr "127.0.0.1:$ctrl" \
    --concurrency 2 --rate 50 --duration 3 --msg-bytes "$MSG_BYTES" --label "preflight-$stack" \
    --json-out "$file" --json-truncate >"$RUN_DIR/$stack-preflight.log" 2>&1 || true
  local rt
  rt=$(json_field "$file" round_trips)
  echo "pre-flight $stack: $rt echo round trips"
  [ "${rt:-0}" -gt 0 ] 2>/dev/null
}
preflight rs "$RS_REMOTE" "$RS_PORT" \
  || { echo "error: frp-rs bridge moved no bytes during pre-flight (see $RUN_DIR/rs-preflight.log)" >&2; exit 1; }
preflight go "$GO_REMOTE" "$GO_PORT" \
  || { echo "error: Go bridge moved no bytes during pre-flight (see $RUN_DIR/go-preflight.log)" >&2; exit 1; }
echo "pre-flight OK: both bridges completed echo round trips"

# ---------------------------------------------------------------- traffic
# Identical recipe on both sides: paced short-lived connection churn plus a few
# long-lived, rate-capped byte streams. The churn rate is fixed per stack so both
# are OFFERED the same connections/second; the achieved round trips are recorded
# per side and reconciled in the summary, so a reader can check both accepted it.
# Both generators run for GEN_DURATION (the window plus GENERATOR_TAIL) so that
# none of them ends while samples are still being taken.
traffic() {
  local stack="$1" remote="$2" ctrl="$3"
  "$STRESS" --scenario memory --mode churn --port "$remote" --frps-addr "127.0.0.1:$ctrl" \
    --concurrency "$CHURN_CONNS" --rate "$CHURN_RATE" --duration "$GEN_DURATION" --msg-bytes "$MSG_BYTES" \
    --label "soak-churn-$stack" --json-out "$RUN_DIR/$stack-churn.json" --json-truncate \
    >"$RUN_DIR/$stack-churn.log" 2>&1 & add_traffic "$stack-churn" $!
  "$STRESS" --scenario throughput --port "$remote" --frps-addr "127.0.0.1:$ctrl" \
    --streams "$STREAMS" --mbps "$STREAM_MBPS" --duration "$GEN_DURATION" --label "soak-steady-$stack" --no-floor \
    --json-out "$RUN_DIR/$stack-steady.json" --json-truncate \
    >"$RUN_DIR/$stack-steady.log" 2>&1 & add_traffic "$stack-steady" $!
}
traffic rs "$RS_REMOTE" "$RS_PORT"
traffic go "$GO_REMOTE" "$GO_PORT"

# Hard-deadline orphan guard. `nohup … &` runs this script without job control,
# so SIGINT is ignored by bash for the async children, and a `kill -9` of this
# script runs no trap at all: the two echo backends and the four frp processes
# would then outlive it forever (none of them has a self-imposed end). One
# watchdog subshell polls this shell's pid and, once it is gone — however it
# died — kills the whole child list and drops the lock. Normal teardown kills
# the watchdog first, so it only ever acts on an abnormal exit.
( parent=$$
  while kill -0 "$parent" 2>/dev/null; do sleep 5; done
  for p in "${ALL_PIDS[@]:-}"; do [ -n "$p" ] && kill -9 "$p" 2>/dev/null; done
  if [ -f "$LOCK_FILE" ] && [ "$(cat "$LOCK_FILE" 2>/dev/null || true)" = "$parent" ]; then
    rm -f "$LOCK_FILE"
  fi ) >/dev/null 2>&1 &
WATCHDOG_PID=$!

sleep 2

# ---------------------------------------------------------------- sample
# Clear this run's evidence at the last safe moment: pre-flight passed (so the
# bridges work), and this run's generators are alive so they cannot have written
# anything yet. Without this, a generator that dies inside the window leaves the
# PREVIOUS run's row in $RUN_DIR, and the summary publishes borrowed traffic
# under "aborted": null. See scripts/lib/rss-soak-run-dir.sh.
rss_soak_clear_run_artifacts "$RUN_DIR" "$OUT" || { echo "error: cannot clear run artifacts in $RUN_DIR" >&2; exit 1; }
start_epoch=$(date +%s)
start_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)
started_load=$(load1)
# The meta record is written by the shared, fixture-covered writer
# (rss_soak_write_meta in scripts/lib/rss-soak-run-dir.sh): it JSON-escapes
# every string field — notably $RUN_DIR, the binary paths and the host name —
# and records $RSS_CEILING_KB so the artifact carries the bound it was produced
# under. The reader prefers that recorded ceiling over its own environment, so
# the same artifact gets the same verdict anywhere.
rss_soak_write_meta "$OUT" \
  "$start_utc" "$DURATION" "$INTERVAL" "$GEN_DURATION" "$(hostname -s)" "$go_platform" "$cpu_cores" \
  "$rs_version" "$rs_sha" "$rs_dirty" "$soak_sha" "$run_dir_lib_sha" "$summary_py_sha" "$stress_tree_sha" "$RS_BIN_SOURCE" "$RUN_DIR" \
  "$go_version" "$GO_DIR" "$RS_FRPS" "$RS_FRPC" \
  "$CHURN_CONNS" "$CHURN_RATE" "$MSG_BYTES" "$STREAMS" "$STREAM_MBPS" \
  "$RS_PORT" "$RS_REMOTE" "$RS_ECHO" "$GO_PORT" "$GO_REMOTE" "$GO_ECHO" \
  "$rs_frps_sha" "$rs_frpc_sha" "$go_frps_sha" "$go_frpc_sha" \
  "$started_load" "$RSS_CEILING_KB" || { echo "error: cannot write meta to $OUT" >&2; exit 1; }

echo "=== soak running: $(date -u +%H:%M:%SZ), load1=$started_load ==="
aborted=""
samples=0

# Report HOW each dead process died, not just that it is gone: `wait` still
# yields the remembered status of a child bash has reaped, and 127 means the
# status was already collected. The status is recorded verbatim — it does NOT
# identify a signal, because a process that handles SIGTERM exits 0 (frp-rs
# does), so "(exit 0)" beside a name means "exited by itself or was asked to
# stop", and only the elapsed time says which. Sets DEAD_SEEN in the CALLER's
# shell (a `$( )` wrapper would run `wait` in a subshell with no job table).
DEAD_SEEN=""
scan_dead() { # <check_generators: 1|0>
  local check_gen="$1" i p st
  DEAD_SEEN=""
  for i in "${!FRP_PIDS[@]}"; do
    p="${FRP_PIDS[$i]}"
    if ! alive "$p"; then
      wait "$p" 2>/dev/null
      st=$?
      if [ "$st" = 127 ]; then DEAD_SEEN="${DEAD_SEEN}${FRP_NAMES[$i]} "
      else DEAD_SEEN="${DEAD_SEEN}${FRP_NAMES[$i]}(exit $st) "; fi
    fi
  done
  # The echo backends have no self-imposed end either, so they are scanned at
  # EVERY iteration, including the last one.
  for i in "${!ECHO_PIDS[@]}"; do
    p="${ECHO_PIDS[$i]}"
    if ! alive "$p"; then
      wait "$p" 2>/dev/null
      st=$?
      if [ "$st" = 127 ]; then DEAD_SEEN="${DEAD_SEEN}${ECHO_NAMES[$i]} "
      else DEAD_SEEN="${DEAD_SEEN}${ECHO_NAMES[$i]}(exit $st) "; fi
    fi
  done
  # The traffic generators end by design (GENERATOR_TAIL past the window), so
  # they are only scanned while the window is open; see the loop below.
  [ "$check_gen" = 1 ] || return 0
  for i in "${!GEN_PIDS[@]}"; do
    p="${GEN_PIDS[$i]}"
    if ! alive "$p"; then
      wait "$p" 2>/dev/null
      st=$?
      if [ "$st" = 127 ]; then DEAD_SEEN="${DEAD_SEEN}${GEN_NAMES[$i]} "
      else DEAD_SEEN="${DEAD_SEEN}${GEN_NAMES[$i]}(exit $st) "; fi
    fi
  done
}

# The scan runs BEFORE the window-end test, so the last sampling interval is
# examined too: with the scan after the break, a process that died at
# DURATION-5 s was never seen and the series was published as "run completed".
# The four frp processes and the two echo backends have no self-imposed end, so
# any death is a fault at any elapsed time. The four traffic generators DO end
# (by design, GENERATOR_TAIL seconds past the window), so they are only checked
# while the window is still open: a generator dying inside the window is a fault
# with no grace period, and one that never wrote its result row is in any case
# caught after the window by the summary's traffic reconciliation.
while :; do
  if [ "$SIGNALLED" = 1 ]; then
    aborted="interrupted by signal (SIGINT/SIGTERM)"
    break
  fi
  elapsed=$(( $(date +%s) - start_epoch ))
  if [ "$elapsed" -lt "$DURATION" ]; then scan_dead 1; else scan_dead 0; fi
  if [ -n "$DEAD_SEEN" ]; then
    aborted="process died at ${elapsed}s: ${DEAD_SEEN}"
    echo "error: $aborted" >&2
    break
  fi
  if [ "$elapsed" -ge "$DURATION" ]; then break; fi

  printf '{"kind":"sample","elapsed_s":%s,"ts":"%s","load1":%s,"time_wait":%s,"frp_rs_frps_kb":%s,"frp_rs_frpc_kb":%s,"go_frps_kb":%s,"go_frpc_kb":%s}\n' \
    "$elapsed" "$(rss_soak_json_str "$(date -u +%Y-%m-%dT%H:%M:%SZ)")" "$(load1)" "$(time_wait_count)" \
    "$(rss_kb "$RS_FRPS_PID")" "$(rss_kb "$RS_FRPC_PID")" \
    "$(rss_kb "$GO_FRPS_PID")" "$(rss_kb "$GO_FRPC_PID")" >> "$OUT"
  samples=$((samples + 1))
  # `sleep` in the background + `wait`, not a bare `sleep`: a trapped SIGTERM
  # interrupts `wait` immediately, so the loop notices it at once instead of
  # only when the sleep returns (up to INTERVAL seconds later). Under the
  # documented `nohup … &` launch bash ignores SIGINT for async commands and
  # there is no job control, so SIGTERM is the signal that stops a detached soak.
  sleep "$INTERVAL" &
  sleep_pid=$!
  wait "$sleep_pid" 2>/dev/null
  :
done

# ------------------------------------------------------------ generator tail
# The traffic generators were launched with GENERATOR_TAIL extra seconds, so they
# should still be running here. Give them that tail to finish and write their
# result rows (the summary reads those files), bounded, and only when the run has
# not already faulted.
if [ -z "$aborted" ]; then
  gen_deadline=$(( $(date +%s) + GENERATOR_TAIL + 60 ))
  while :; do
    pending=""
    for p in "${TRAFFIC_PIDS[@]:-}"; do
      if [ -n "$p" ] && alive "$p"; then pending=yes; break; fi
    done
    [ -z "$pending" ] && break
    if [ "$(date +%s)" -ge "$gen_deadline" ]; then
      echo "warning: traffic generator(s) still running past the window; results may be incomplete" >&2
      break
    fi
    sleep 2
  done
fi

# A death AFTER the window closes does not invalidate the samples already taken,
# but it must still be recorded. Nothing else looks at the frp processes between
# the window-end break and the summary, so a `kill -9` during the generator tail
# used to leave no trace at all: the series is complete and the run said "run
# completed". The frp processes and echo backends have no self-imposed end, so
# they are re-scanned here (generators are excluded — they are expected to have
# exited by now, which is what the tail above waited for).
if [ -z "$aborted" ]; then
  scan_dead 0
  if [ -n "$DEAD_SEEN" ]; then
    aborted="process died after the window closed: ${DEAD_SEEN}"
    echo "error: $aborted" >&2
  fi
fi

# ---------------------------------------------------------------- teardown
cleanup
trap - EXIT INT TERM

# Summary + completeness reconciliation live in scripts/lib/rss-soak-summary.py
# so the fixture can drive the real reader (see scripts/tests/rss-soak-run-dir.sh).
summary_rc=0
python3 "$SCRIPT_DIR/lib/rss-soak-summary.py" "$OUT" "$aborted" \
  "$RUN_DIR/rs-churn.json" "$RUN_DIR/go-churn.json" \
  "$RUN_DIR/rs-steady.json" "$RUN_DIR/go-steady.json" || summary_rc=$?

echo "=== soak artifact written: $OUT ($samples samples) ==="
exit "$summary_rc"
