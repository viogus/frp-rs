#!/usr/bin/env bash
# =============================================================================
# frp-rs full-matrix A/B throughput gate.
#
# Measures the six bridge configurations (plain / encrypt / compress /
# encrypt_compress / mux / tls) for TWO code states and reports the per-config
# delta over GATE_PCT (default 5%).
#
# =============================================================================
# THE GATE IS INFORMATIONAL (TODO.md:11799) — this is a decision, not an
# accident, and this header carries the numbers it rests on.
#
# A >GATE_PCT delta prints the table and an annotation and exits 0, with the
# final line `A/B GATE REGRESSED (informational; gate demoted — see the
# header)`. It does not red a run. Set AB_GATE_ENFORCE=1 to restore the hard
# failure (exit 1); the CI job exposes the same switch as the `enforce`
# workflow_dispatch input. Nothing was deleted: the table, the confirm loop
# and the threshold all still run, and enforcement is one variable away.
#
# Why the hard failure was demoted. Threshold 5% sits an order of magnitude
# below the gate's own measured noise floor, so a red gate on a *code*
# change is not evidence of a regression either:
#
#   * Run 36996762744 measured a docs-comment-only delta — merged as #459,
#     `97a03884..ae7bf50d`, a diff whose 40 changed `.rs` lines (20 added, 20
#     removed) are entirely citation re-points inside doc comments (the
#     recorded item moved, so each reference to it was renumbered; no
#     executable line changed) — at +58.8% on `plain` and -15.6% on
#     `encrypt_compress` in the same run, in opposite directions.
#   * Before the PR mode was retired, *identical* binaries (the docs-only
#     #280) measured tls -35.1% / -27.9% / +24.5% across three attempts
#     (`.github/workflows/ab-matrix.yml:15-17`).
#
# The recorded pair is why the demotion is not redundant with the delta
# classifier below: its diff is NOT empty under `'*.rs' 'Cargo*.toml'` (10
# `.rs` files), so a path-based skip alone cannot refuse to measure it. And the
# classifier is not redundant with the demotion: a records-only daily delta has
# provably nothing to measure, so skipping it saves the VPS run that the
# demotion would still spend.
#
# Read the numbers as: "same-code spread up to ~±35%, published delta for a
# semantics-free delta up to ~±59%". A regression smaller than that is not
# separable from the host, which is why the gate publishes rather than blocks.
# =============================================================================
#
# Skips a delta with nothing measurable in it before spending anything: in REF
# mode (`BEFORE_REF`/`AFTER_REF`) the delta is classified by
# `scripts/ab-measurable-delta.sh` *before* any worktree/build; if it contains
# no path that can change the measured numbers, the run prints an explicit skip
# line naming both refs and exits 0. AB_FORCE_MEASURE=1 bypasses the skip (for
# noise studies that deliberately measure a same-code pair).
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
#   # Commit-vs-commit, classified first (skipped when nothing measurable):
#   BEFORE_REF=main~1 AFTER_REF=main bash scripts/ab-matrix.sh 3 10
#
# Output: a per-config table with A / B / delta%, plus a final informational or
# FAIL line. Exit 0 if every config is within threshold OR the gate is
# informational; 1 only when something regressed > GATE_PCT under
# AB_GATE_ENFORCE=1.
#
# Numbers are host-specific; always compare against a same-host before build.
# On shared CI runners the single before/after shot is dominated by
# CPU-contention variance, so a regressed config is re-measured up to
# CONFIRM_RETRIES times (default 2). The reported delta is the MEDIAN of every
# sample actually taken (first shot plus every confirm re-measurement) and the
# sample count is printed next to it; the minimum is never reported.
# =============================================================================
set -euo pipefail
export RUST_LOG=warn

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

REPS="${1:-3}"
RDUR="${2:-10}"
GATE_PCT="${GATE_PCT:-5}"
CONFIRM_RETRIES="${CONFIRM_RETRIES:-2}"
SKIP_BUILD="${SKIP_BUILD:-0}"   # set to 1 to assume *_ROOT already built
# AB_FORCE_MEASURE=1 measures even a delta with nothing measurable in it (a
# deliberate same-code/noise study); AB_GATE_ENFORCE=1 restores the hard
# failure for a beyond-gate delta (the gate is informational by default — see
# the header).
AB_FORCE_MEASURE="${AB_FORCE_MEASURE:-0}"
AB_GATE_ENFORCE="${AB_GATE_ENFORCE:-0}"
_WT_PATHS=()                     # REF worktrees to clean up on exit
FAIL=0                           # set to 1 by gate_report on any regression
GATE_FAIL_TEXT=''                # human-readable list of regressed configs
# =============================================================================
# Gate arithmetic and verdict (pure; also driven by
# scripts/tests/ab-measurable-delta.sh through the AB_MATRIX_LIB_ONLY seam).
# =============================================================================

# Median of the numbers passed as arguments (Bash 3.2: no nameref).
# Deliberately UNFILTERED: this same function takes the delta percentages, and
# a regressed config's delta is negative — dropping <= 0 here would erase every
# real regression. Throughput samples go through median_mbps below instead.
gate_median() {
  python3 -c '
import sys, statistics
v = [float(x) for x in sys.argv[1:]]
print(round(statistics.median(v), 1) if v else 0)
' "$@"
}

# Median mbps of the throughput samples `run_side` writes one per line to
# stdin. Samples <= 0 are dropped: run_side emits nothing when a server fails
# to start, and a missing measurement must not be counted as 0 mbps.
median_mbps() {
  python3 -c '
import sys, statistics
v = [float(x) for x in sys.stdin.read().split() if float(x) > 0]
print(round(statistics.median(v), 1) if v else 0)
'
}

# Does a delta percentage represent a regression beyond the gate?
above_gate() {  # $1 = delta %, exit 0 when it regresses by more than GATE_PCT
  python3 -c "import sys; sys.exit(0 if ($1 < -$GATE_PCT) else 1)"
}

# The verdict for one config. Prints "<median> <samples> <VERDICT>", where
# VERDICT is REGRESSED or pass. The value is the MEDIAN of every delta sample
# actually taken, never the minimum: the confirm loop below decides whether to
# take another shot, but it must not be able to select a sample to publish.
# (TODO.md:11799 — the old code replaced `delta` with any *more negative*
# re-measurement and published that, so a single noisy shot became "the"
# regression.)
gate_verdict() {  # gate_verdict <delta-sample>...
  local median samples result
  if [[ $# -eq 0 ]]; then
    printf '0 0 SKIP(no data)\n'
    return 0
  fi
  samples=$#
  median=$(gate_median "$@")
  result="pass"
  if above_gate "$median"; then result="REGRESSED"; fi
  printf '%s %s %s\n' "$median" "$samples" "$result"
}

# Publish one table row / annotation. The row is also appended to
# $GITHUB_STEP_SUMMARY when the runner set that variable, so a red-or-not
# verdict is visible on the job page; a local run (variable unset) just prints.
# Sets FAIL=1 when the verdict regressed, so that ONE run still reports every
# config. This function never ends the run: enforcement lives in gate_final
# below, which is the only site that decides the exit code.
gate_report() {  # gate_report <label> <v_a> <v_b> <median> <samples> <verdict>
  local label="$1" v_a="$2" v_b="$3" median="$4" samples="$5" verdict="$6"
  printf '%-18s %9s %9s %8s   %s\n' "$label" "$v_a" "$v_b" "${median}%" "$verdict (n=$samples)"
  if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    printf '| %s | %s | %s | %s%% | %s (n=%s) |\n' \
      "$label" "$v_a" "$v_b" "$median" "$verdict" "$samples" >> "$GITHUB_STEP_SUMMARY"
  fi
  if [[ "$verdict" == "REGRESSED" ]]; then
    FAIL=1
    GATE_FAIL_TEXT="${GATE_FAIL_TEXT}${label} ${v_a} -> ${v_b} (${median}%, median of ${samples} sample(s))"$'\n'
    echo "::warning::A/B throughput ${label} regressed ${median}% (> ${GATE_PCT}% gate; median of ${samples} same-pair sample(s)). The gate is informational by default (TODO.md:11799); set AB_GATE_ENFORCE=1 to make a regression fail the run."
  fi
}

# The single enforcement site, and therefore the only place the run's exit code
# is decided: 1 only when a config regressed AND AB_GATE_ENFORCE=1, else 0. It
# reads the FAIL/GATE_FAIL_TEXT globals gate_report accumulated and prints the
# final verdict block; the script ends with `if gate_final; then exit 0; else
# exit 1; fi`.
#
# A function rather than inline code so the fixture suite can drive the real
# decision through the AB_MATRIX_LIB_ONLY seam: a demoted gate whose re-arm
# could not be exercised would be a promise no test witnesses. (It also means
# there is exactly one reachable exit path; the base had the enforce exit
# inside gate_report, which made the caller's rc propagation and this block
# dead code.)
gate_final() {  # gate_final: prints the verdict, returns 0 (or 1 under enforce)
  if [[ "$FAIL" != "1" ]]; then
    echo "A/B GATE PASSED: all configs within ${GATE_PCT}% of the before baseline (median of the samples taken)."
    return 0
  fi
  if [[ "$AB_GATE_ENFORCE" == "1" ]]; then
    echo "A/B GATE FAILED: one or more configs regressed more than ${GATE_PCT}% (before -> after) with AB_GATE_ENFORCE=1."
    return 1
  fi
  echo "A/B GATE REGRESSED (informational; gate demoted — see the header)"
  echo "  regressed:"
  printf '%s' "$GATE_FAIL_TEXT"
  echo "  threshold ${GATE_PCT}% is below this gate's measured noise floor (identical binaries: -35.1% / -27.9% / +24.5%);"
  echo "  set AB_GATE_ENFORCE=1 to restore the hard failure (exit 1)."
  return 0
}

# A/B noise mitigation for shared runners: a single before/after shot is
# dominated by CPU-contention variance, so a run that looks regressed is
# re-measured up to CONFIRM_RETRIES times. The caller reports the MEDIAN of
# every delta actually taken, with its sample count — not one shot and not the
# worst shot.
#
# Sets three globals (rather than printing them) for `measure_pair_deltas
# <mux> <enc> <comp> <tls> <label>`:
#   PAIR_DELTAS   – space-separated per-attempt delta percentages ("" if either
#                   side produced no data at all)
#   PAIR_MEDIAN_A – median mbps over every BEFORE sample taken
#   PAIR_MEDIAN_B – median mbps over every AFTER sample taken
# Globals, not stdout, because a `$(...)` capture would run this in a subshell
# and the side medians would be discarded there — leaving the row's before/after
# columns describing runs the delta was NOT computed from. The per-attempt
# deltas go to stderr as progress.
measure_pair_deltas() {  # measure_pair_deltas <mux> <enc> <comp> <tls> <label>
  local mux="$1" enc="$2" comp="$3" tls="$4" label="$5"
  local v_a v_b ca cb ndelta attempt d
  local -a deltas=() as=() bs=()
  PAIR_DELTAS=""
  PAIR_MEDIAN_A="0"
  PAIR_MEDIAN_B="0"
  v_a=$(run_side "before-$label" "$FRPS_A" "$FRPC_A" "$STRESS_A" "$mux" "$enc" "$comp" "$tls" "$REPS" "$RDUR" | median_mbps)
  v_b=$(run_side "after-$label"  "$FRPS_B" "$FRPC_B" "$STRESS_B" "$mux" "$enc" "$comp" "$tls" "$REPS" "$RDUR" | median_mbps)
  if [[ "$v_a" == "0" || "$v_b" == "0" ]]; then
    return 0
  fi
  as+=("$v_a"); bs+=("$v_b")
  deltas+=("$(python3 -c "print(round((100.0*($v_b-$v_a)/$v_a),1))")")
  attempt=0
  # Retry decision only: the loop may take more samples while the median so far
  # still looks regressed. It never chooses a value to report.
  while [[ "$(gate_verdict "${deltas[@]}" | cut -d' ' -f3)" == "REGRESSED" ]] \
        && [[ "$attempt" -lt "${CONFIRM_RETRIES:-2}" ]]; do
    attempt=$((attempt + 1))
    ca=$(run_side "before-$label-c$attempt" "$FRPS_A" "$FRPC_A" "$STRESS_A" "$mux" "$enc" "$comp" "$tls" "$REPS" "$RDUR" | median_mbps)
    cb=$(run_side "after-$label-c$attempt"  "$FRPS_B" "$FRPC_B" "$STRESS_B" "$mux" "$enc" "$comp" "$tls" "$REPS" "$RDUR" | median_mbps)
    if [[ "$ca" == "0" || "$cb" == "0" ]]; then
      continue
    fi
    as+=("$ca"); bs+=("$cb")
    ndelta=$(python3 -c "print(round((100.0*($cb-$ca)/$ca),1))")
    deltas+=("$ndelta")
    # A re-measurement within the gate proves the flagged regression was noise;
    # stop rather than burn another pair. (The median of everything taken,
    # including this shot, is what gets reported.)
    above_gate "$ndelta" || break
  done
  PAIR_DELTAS="${deltas[*]}"
  PAIR_MEDIAN_A="$(gate_median "${as[@]}")"
  PAIR_MEDIAN_B="$(gate_median "${bs[@]}")"
  for d in "${deltas[@]}"; do
    printf 'A/B delta %s: %s%%\n' "$label" "$d" >&2
  done
}

# --- SOURCE-ONLY GUARD (test seam) ------------------------------------------
# Sourced by scripts/tests/ab-measurable-delta.sh with AB_MATRIX_LIB_ONLY=1 so
# the fixture suite drives the *real* median/verdict/report code instead of a
# copy of it. Everything above is assignment or a pure function definition;
# everything below provisions worktrees, builds and starts servers, which no
# test should trigger. The return is only reached under `source` (a plain
# `bash ab-matrix.sh` runs on with the variable unset).
if [[ "${AB_MATRIX_LIB_ONLY:-0}" == "1" ]]; then
  return 0 2>/dev/null || exit 0
fi

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
BEFORE_ROOT="${BEFORE_ROOT:-}"
BEFORE_REF="${BEFORE_REF:-}"

# --- classify the delta BEFORE any checkout/build ---------------------------
# Only a commit-vs-commit run can be classified: both refs must be git
# revisions. A *_ROOT run measures pre-built binary directories that are not
# necessarily revisions of this repo, so there is nothing to classify and the
# run proceeds (the CI job classifies in its own step, before it builds).
#
# rc 0 -> measurable paths (printed; measure as today)
# rc 1 -> nothing measurable  -> skip, exit 0, and do NOT call build_side
# rc 2 -> classifier could not decide -> warn and measure anyway. Fail OPEN
#         towards measuring: a skip must be a positive finding, never a
#         side effect of an unresolved input.
if [[ -n "$BEFORE_REF" && -n "$AFTER_REF" ]]; then
  if [[ "$AB_FORCE_MEASURE" == "1" ]]; then
    echo "A/B delta classification bypassed (AB_FORCE_MEASURE=1): measuring $BEFORE_REF..$AFTER_REF" >&2
  else
    classify_rc=0
    classify_out="$(bash "$SCRIPT_DIR/ab-measurable-delta.sh" "$BEFORE_REF" "$AFTER_REF")" || classify_rc=$?
    case "$classify_rc" in
      0)
        echo "A/B delta $BEFORE_REF..$AFTER_REF touches $(printf '%s\n' "$classify_out" | wc -l | tr -d ' ') measurable path(s); measuring" >&2
        printf '%s\n' "$classify_out" >&2
        ;;
      1)
        echo "A/B GATE SKIPPED (informational): nothing measurable in $BEFORE_REF..$AFTER_REF — no path in the delta can change the measured numbers (docs/records-only). No worktree, build or measurement was run. Set AB_FORCE_MEASURE=1 to measure this pair anyway."
        exit 0
        ;;
      *)
        echo "WARN: could not classify $BEFORE_REF..$AFTER_REF (scripts/ab-measurable-delta.sh rc $classify_rc) — measuring anyway rather than skipping on an unresolved input" >&2
        ;;
    esac
  fi
fi

# LOCAL PATCH (perf measurement only, not part of the code diff): fixed
# /tmp/ab-* paths collide across users on shared machines (sticky-bit /tmp,
# files owned by another user are undeletable and unwritable). Use a private
# mktemp dir instead. Created only after the classify step so a skip exits
# without leaving a scratch dir behind (the cleanup trap is not armed yet).
ABTMP="$(mktemp -d /tmp/abmatrix-XXXXXX)"

if [[ -n "$AFTER_ROOT" || -n "$AFTER_REF" ]]; then
  build_side AFTER "$AFTER_ROOT" "$AFTER_REF"   # sets AFTER_DIR via eval
else
  AFTER_DIR="$PROJECT_DIR"
fi

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
CA="$ABTMP/ca.crt"; CAKEY="$ABTMP/ca.key"
CERT="$ABTMP/srv.crt"; KEY="$ABTMP/srv.key"
if [[ ! -f "$CERT" ]]; then
  openssl req -x509 -newkey rsa:2048 -keyout "$CAKEY" -out "$CA" -days 1 -nodes -subj "/CN=abmatrix-ca" 2>/dev/null
  openssl req -newkey rsa:2048 -keyout "$KEY" -out "$ABTMP/srv.csr" -nodes -subj "/CN=localhost" 2>/dev/null
  openssl x509 -req -in "$ABTMP/srv.csr" -CA "$CA" -CAkey "$CAKEY" -CAcreateserial -out "$CERT" -days 1 \
    -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=CA:FALSE") 2>/dev/null
fi

PIDS=()
cleanup() {
  for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done
  rm -rf "$ABTMP"
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
  } > "$ABTMP/frps.toml"
  {
    echo "server_addr = \"127.0.0.1\""; echo "server_port = $PORT"; echo "token = \"$TOKEN\""
    echo "login_fail_exit = true"; echo "pool_count = 1"; echo "tcp_mux = $mux"
    if [[ "$tls" == "true" ]]; then echo "tls_enable = true"; echo "tls_ca_file = \"$CA\""; echo "tls_server_name = \"localhost\""; echo "disable_custom_tls_first_byte = true"; fi
    echo "[[proxies]]"; echo "name = \"ab-tcp\""; echo "type = \"tcp\""
    echo "local_ip = \"127.0.0.1\""; echo "local_port = $ECHO"; echo "remote_port = $RPORT"
    [[ "$enc"  == "true" ]] && echo "use_encryption = true"
    [[ "$comp" == "true" ]] && echo "use_compression = true"
  } > "$ABTMP/frpc.toml"
  PIDS=()
  "$stress" --scenario echo --port "$ECHO" >/dev/null 2>&1 & PIDS+=($!)
  sleep 1
  "$frps" -c "$ABTMP/frps.toml" >/dev/null 2>&1 & PIDS+=($!)
  sleep 1
  "$frpc" -c "$ABTMP/frpc.toml" >/dev/null 2>&1 & PIDS+=($!)
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


# FAIL / GATE_FAIL_TEXT are initialised next to the other gate variables above
# the source-only guard, so gate_report is self-contained under the test seam.
printf '%-18s %9s %9s %8s   %s\n' "config" "before" "after" "delta%" "result"
if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  printf '### A/B throughput gate (informational, TODO.md:11799)\n\n' >> "$GITHUB_STEP_SUMMARY"
  printf '| config | before | after | delta%% | result |\n|---|---|---|---|---|\n' >> "$GITHUB_STEP_SUMMARY"
fi
#            label            mux   enc   comp  tls
while IFS= read -r l; do
  set -- $l; mux="$1" enc="$2" comp="$3" tls="$4"; label="$5"
  # Called directly (never in a $(...)), so the PAIR_* globals it sets survive:
  # the row's before/after are the medians of the very samples the delta came
  # from. Two extra measurement runs per config used to be spent here just to
  # print a before/after that did not correspond to the printed delta.
  measure_pair_deltas "$mux" "$enc" "$comp" "$tls" "$label"
  v_a="$PAIR_MEDIAN_A"
  v_b="$PAIR_MEDIAN_B"
  read -r median samples verdict <<< "$(gate_verdict $PAIR_DELTAS)"
  if [[ "$verdict" == "SKIP(no data)" ]]; then
    printf '%-18s %9s %9s %8s   %s\n' "$label" "$v_a" "$v_b" "-" "SKIP(no data)"
    continue
  fi
  # gate_report never ends the run (gate_final does, once, below), so it is
  # called plainly: the base wrapped it in `set +e … rc=$?` for an exit that
  # could not happen here.
  gate_report "$label" "$v_a" "$v_b" "$median" "$samples" "$verdict"
done <<'EOF'
false  false false false  plain
false  true  false false  encrypt
false  false true  false  compress
false  true  true  false  encrypt_compress
true   false false false  mux
false  false false true   tls
EOF

echo ""
# The one place the run's exit code is decided (gate_final's comment). In an
# `if` condition so `set -e` does not abort on its deliberate rc 1: the else
# branch *is* the enforcement.
if gate_final; then
  exit 0
else
  exit 1
fi
