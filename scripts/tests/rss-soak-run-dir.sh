#!/usr/bin/env bash
# =============================================================================
# Fixture: RSS-soak run directory + summary reader
# =============================================================================
#
# Covers the review findings that a soak artifact could be published as
# "run completed" while its numbers were not this run's:
#
#   * a traffic row left behind by an EARLIER run in the same run directory
#     (the run directory defaults to /tmp/rss-soak, so this is the default
#     configuration), which the summary would publish as this run's load;
#   * a series with NO RSS readings at all (a stubbed or broken `ps`), which the
#     summary used to print as a table of zeros next to "run completed";
#   * traffic that was not actually symmetric, and a steady path that lost a
#     stream, neither of which used to abort the run.
#
# It exercises the real `rss_soak_prepare_run_dir` / `rss_soak_clear_run_artifacts`
# / `rss_soak_validate_window` / `rss_soak_rss_kb` from
# `scripts/lib/rss-soak-run-dir.sh` and the real reader
# `scripts/lib/rss-soak-summary.py` against synthetic directories. No network, no
# built binary and no real traffic, so it is safe and fast in the `health` job.
#
# The suite also covers the round-3 findings, where a well-formed but WRONG
# reading was published as evidence: a `ps` stub printing `0` or a constant, an
# artifact whose columns are all one value, implausible magnitudes, a `nan`
# tolerance that disabled the achieved-load check, one binary on both sides, and
# degenerate totals.

set -uo pipefail

self=$0
ROOT=$(cd -P -- "$(dirname -- "$self")/../.." && pwd)
LIB="$ROOT/scripts/lib/rss-soak-run-dir.sh"
SUMMARY="$ROOT/scripts/lib/rss-soak-summary.py"

# Floor on the number of checks that must run. Deleting a case (or returning
# early past one) leaves every remaining assertion green, so without this the
# suite cannot detect its own neutering. Enforced from the EXIT trap below, which
# is installed before the first assertion, and again explicitly before RESULT.
MIN_CHECKS=67

checks=0
fails=0
floor_armed=1
work=$(mktemp -d "${TMPDIR:-/tmp}/rss-soak-fixture.XXXXXX")
cleanup() { rm -rf -- "$work"; }

ok() { checks=$((checks + 1)); printf '  ok    %s\n' "$1"; }
bad() { checks=$((checks + 1)); fails=$((fails + 1)); printf '  FAIL  %s\n' "$1"; }
hdr() { printf '%s\n' "$1"; }

floor_check() {
    [ "$floor_armed" = 1 ] || return 0
    floor_armed=0
    if [ "$checks" -lt "$MIN_CHECKS" ]; then
        bad "the suite ran only $checks checks; MIN_CHECKS=$MIN_CHECKS (a case was deleted or skipped)"
    fi
}
trap 'floor_check; cleanup; exit "$fails"' EXIT

expect_rc() { # <want> <got> <msg>
    if [ "$1" = "$2" ]; then ok "$3 (rc=$2)"; else bad "$3 (want rc=$1, got rc=$2)"; fi
}
expect_grep() { # <pattern> <file> <msg>
    if grep -q -- "$1" "$2"; then ok "$3"; else bad "$3 (no /$1/ in $(basename -- "$2"))"; fi
}
expect_no_grep() { # <pattern> <file> <msg>
    if grep -q -- "$1" "$2"; then bad "$3 (unexpected /$1/ in $(basename -- "$2"))"; else ok "$3"; fi
}

if [ ! -f "$LIB" ] || [ ! -f "$SUMMARY" ]; then
    printf 'FAIL: missing %s or %s\n' "$LIB" "$SUMMARY"
    exit 1
fi
# shellcheck source=../lib/rss-soak-run-dir.sh
. "$LIB"

# --------------------------------------------------------------- run-dir guard
hdr 'run directory guard'

if out=$(rss_soak_prepare_run_dir "" "$work/out.jsonl" 2>/dev/null); then
    bad 'prepare refuses an empty run dir'
else
    ok 'prepare refuses an empty run dir'
fi
if [ -z "$out" ]; then ok 'a refused run dir prints no path'; else bad "a refused run dir printed '$out'"; fi

if rss_soak_prepare_run_dir "/" "$work/out.jsonl" >/dev/null 2>&1; then
    bad 'prepare refuses /'
else
    ok 'prepare refuses /'
fi
if rss_soak_clear_run_artifacts "" "$work/out.jsonl" >/dev/null 2>&1; then
    bad 'clear refuses an empty run dir'
else
    ok 'clear refuses an empty run dir'
fi
if rss_soak_clear_run_artifacts "/" "$work/out.jsonl" >/dev/null 2>&1; then
    bad 'clear refuses /'
else
    ok 'clear refuses /'
fi

abs=$(cd -- "$work" && rss_soak_prepare_run_dir rel ./rel-out.jsonl)
want=$(cd -- "$work/rel" && pwd -P)
if [ "$abs" = "$want" ]; then ok "prepare resolves a relative dir ($abs)"; else bad "prepare resolved '$abs', want '$want'"; fi
if [ -d "$work/rel" ]; then ok 'prepare creates the run dir'; else bad 'prepare did not create the run dir'; fi

deep=$(rss_soak_prepare_run_dir "$work/deep/run" "$work/deep/art/out.jsonl")
if [ -d "$work/deep/art" ]; then ok "prepare creates the artifact's parent dir"; else bad "prepare did not create the artifact's parent dir"; fi
if [ "$deep" = "$(cd -- "$work/deep/run" && pwd -P)" ]; then ok 'prepare echoes the resolved run dir'; else bad "prepare echoed '$deep'"; fi

run="$work/run"
rss_soak_prepare_run_dir "$run" "$run/out.jsonl" >/dev/null
for f in rs-churn.json go-churn.json rs-steady.json go-steady.json; do
    printf '{"round_trips":2376}\n' > "$run/$f"
done
printf 'stale\n' > "$run/out.jsonl"
printf 'keep\n' > "$run/unrelated.txt"
rss_soak_clear_run_artifacts "$run" "$run/out.jsonl"
rc=$?
expect_rc 0 "$rc" 'clear succeeds on an ordinary run dir'
stale_left=""
for f in rs-churn.json go-churn.json rs-steady.json go-steady.json; do
    [ -e "$run/$f" ] && stale_left="$stale_left $f"
done
if [ -z "$stale_left" ]; then ok 'clear removes all four traffic rows'; else bad "clear left:$stale_left"; fi
if [ ! -e "$run/out.jsonl" ]; then ok 'clear removes the artifact'; else bad 'clear left the artifact'; fi
if [ -e "$run/unrelated.txt" ]; then ok 'clear leaves unrelated files alone'; else bad 'clear removed an unrelated file'; fi

# ------------------------------------------------------ window / tolerance
hdr 'window and tolerance validators'

if rss_soak_validate_window abc 30 >/dev/null 2>&1; then bad 'window refuses a non-numeric duration'; else ok 'window refuses a non-numeric duration'; fi
if rss_soak_validate_window 59 30 >/dev/null 2>&1; then bad 'window refuses a duration below 60'; else ok 'window refuses a duration below 60'; fi
if rss_soak_validate_window 60 0 >/dev/null 2>&1; then bad 'window refuses a zero interval'; else ok 'window refuses a zero interval'; fi
if rss_soak_validate_window 60 30 >/dev/null 2>&1; then ok 'window accepts the documented minimum'; else bad 'window refused 60/30'; fi
if rss_soak_validate_tolerance nan >/dev/null 2>&1; then bad 'tolerance refuses nan'; else ok 'tolerance refuses nan'; fi
if rss_soak_validate_tolerance 0 >/dev/null 2>&1; then bad 'tolerance refuses 0'; else ok 'tolerance refuses 0'; fi
if rss_soak_validate_tolerance 1.5 >/dev/null 2>&1; then bad 'tolerance refuses a value above 1'; else ok 'tolerance refuses a value above 1'; fi
if rss_soak_validate_tolerance 0.10 >/dev/null 2>&1; then ok 'tolerance accepts the default 0.10'; else bad 'tolerance refused 0.10'; fi

# -------------------------------------------------------------- lock policy
# The lock is taken before the builds, so these run in well under a second and
# never touch cargo. An EMPTY lock must be treated as held: the winner creates
# the file and writes its pid in two steps, and stealing the lock in between
# starts a second soak on the same ports.
hdr 'lock policy'

empty_lock="$work/empty.lock"
: > "$empty_lock"
lock_out=$(SOAK_LOCK="$empty_lock" SOAK_RUN_DIR="$work/lock-run" SOAK_OUT="$work/lock-run/out.jsonl" \
    bash "$ROOT/scripts/rss-soak.sh" 60 30 2>&1 >/dev/null)
lock_rc=$?
expect_rc 1 "$lock_rc" 'an empty lock is held, not stolen'
if printf '%s' "$lock_out" | grep -q 'exists but is empty'; then ok 'the empty lock is named'; else bad 'the empty lock was not named'; fi
if [ -f "$empty_lock" ]; then ok 'the empty lock file is left in place'; else bad 'the empty lock file was removed'; fi

live_lock="$work/live.lock"
printf '%s\n' "$$" > "$live_lock"
lock_out=$(SOAK_LOCK="$live_lock" SOAK_RUN_DIR="$work/lock-run2" SOAK_OUT="$work/lock-run2/out.jsonl" \
    bash "$ROOT/scripts/rss-soak.sh" 60 30 2>&1 >/dev/null)
lock_rc=$?
expect_rc 1 "$lock_rc" 'a lock held by a live pid refuses a second soak'
if printf '%s' "$lock_out" | grep -q 'already running'; then ok 'the live holder is named'; else bad 'the live holder was not named'; fi

# ------------------------------------------------------- summary reader (real)
hdr 'summary reader'

summary() { # <artifact> <aborted> <rs-churn> <go-churn> <rs-steady> <go-steady>
    python3 "$SUMMARY" "$@" > "$1.stdout" 2>&1
    return $?
}

artifact() { # <path> <run_dir> <mode: rising|nulls|const|huge|falling> [extra-meta-json]
    local path="$1" dir="$2" mode="$3" extra="${4:-}" i kb
    printf '{"kind":"meta","duration_s":300,"interval_s":45,"run_dir":"%s","frp_rs_sha":"deadbeef"%s}\n' \
        "$dir" "$extra" > "$path"
    for i in 0 45 90 135 180; do
        case "$mode" in
            rising)  kb=$((12000 + i * 10)) ;;
            falling) kb=$((12000 - i * 10)) ;;
            const)   kb=1234 ;;
            huge)    kb=999999999 ;;
            nulls)   kb="" ;;
            *) bad "unknown artifact mode '$mode'"; return 1 ;;
        esac
        if [ -z "$kb" ]; then
            printf '{"kind":"sample","elapsed_s":%d,"load1":3.1,"time_wait":400,"frp_rs_frps_kb":null,"frp_rs_frpc_kb":null,"go_frps_kb":null,"go_frpc_kb":null}\n' \
                "$i" >> "$path"
        else
            printf '{"kind":"sample","elapsed_s":%d,"load1":3.1,"time_wait":400,"frp_rs_frps_kb":%d,"frp_rs_frpc_kb":%d,"go_frps_kb":%d,"go_frpc_kb":%d}\n' \
                "$i" "$kb" "$kb" "$((kb + 20000))" "$((kb + 12000))" >> "$path"
        fi
    done
}

traffic_rows() { # <dir> <round_trips> <total_bytes>
    local dir="$1" trips="$2" total="$3"
    mkdir -p -- "$dir"
    printf '{"connections":40,"round_trips":%s,"bytes":%s,"total_bytes":%s,"mbps":1.0,"failed_streams":0}\n' \
        "$trips" "$total" "$total" > "$dir/rs-churn.json"
    cp -- "$dir/rs-churn.json" "$dir/go-churn.json"
    printf '{"connections":3,"bytes":%s,"total_bytes":%s,"mbps":1.0,"failed_streams":0}\n' \
        "$total" "$total" > "$dir/rs-steady.json"
    cp -- "$dir/rs-steady.json" "$dir/go-steady.json"
}

run_summary() { # <dir> <mode> [extra-meta] [aborted]
    local dir="$1" mode="$2" extra="${3:-}" aborted="${4:-}"
    mkdir -p -- "$dir"
    local abs
    abs=$(rss_soak_prepare_run_dir "$dir" "$dir/out.jsonl")
    artifact "$dir/out.jsonl" "$abs" "$mode" "$extra"
    summary "$dir/out.jsonl" "$aborted" "$dir/rs-churn.json" "$dir/go-churn.json" \
        "$dir/rs-steady.json" "$dir/go-steady.json"
}

# 1. A run whose generators died early: the rows on disk predate the run, and
#    the soak clears them before the window opens. The summary must then abort
#    and must not publish the earlier run's numbers.
stale="$work/stale"
stale_abs=$(rss_soak_prepare_run_dir "$stale" "$stale/out.jsonl")
traffic_rows "$stale" 2376 999999
# The soak's order: clear (after pre-flight, before the window), then write meta
# and samples.
rss_soak_clear_run_artifacts "$stale" "$stale/out.jsonl"
artifact "$stale/out.jsonl" "$stale_abs" rising
summary "$stale/out.jsonl" "" "$stale/rs-churn.json" "$stale/go-churn.json" \
    "$stale/rs-steady.json" "$stale/go-steady.json"
expect_rc 3 "$?" 'no traffic row this run -> abort'
expect_no_grep 2376 "$stale/out.jsonl" 'the earlier round_trips are not published'
expect_no_grep 999999 "$stale/out.jsonl" 'the earlier byte totals are not published'
expect_grep 'completed no echo round trips' "$stale/out.jsonl" 'the missing row is named'
expect_no_grep 'run completed' "$stale/out.jsonl.stdout" 'not printed as completed'

# 2. No RSS readings at all (a stubbed `ps`): abort, and never print a reading
#    that was not measured.
norss="$work/norss"
norss_abs=$(rss_soak_prepare_run_dir "$norss" "$norss/out.jsonl")
artifact "$norss/out.jsonl" "$norss_abs" nulls
traffic_rows "$norss" 600 2000000
summary "$norss/out.jsonl" "" "$norss/rs-churn.json" "$norss/go-churn.json" \
    "$norss/rs-steady.json" "$norss/go-steady.json"
expect_rc 3 "$?" 'an empty RSS column -> abort'
expect_grep 'no RSS measurements for frp-rs frps' "$norss/out.jsonl" 'the empty column is named'
expect_grep 'NO READINGS' "$norss/out.jsonl.stdout" 'the table says NO READINGS'
expect_no_grep 'frp-rs frps *0' "$norss/out.jsonl.stdout" 'no fabricated 0 KB reading'
expect_no_grep 'run completed' "$norss/out.jsonl.stdout" 'not printed as completed'

# 3. A run with readings and symmetric traffic completes, and its summary carries
#    the computed trend rather than relying on an eyeball.
good="$work/good"
good_abs=$(rss_soak_prepare_run_dir "$good" "$good/out.jsonl")
artifact "$good/out.jsonl" "$good_abs" rising
traffic_rows "$good" 600 2000000
summary "$good/out.jsonl" "" "$good/rs-churn.json" "$good/go-churn.json" \
    "$good/rs-steady.json" "$good/go-steady.json"
expect_rc 0 "$?" 'a healthy run completes'
expect_grep 'run completed' "$good/out.jsonl.stdout" 'the table says run completed'
expect_grep '"trend"' "$good/out.jsonl" 'the summary carries a per-column trend'
expect_grep '"achieved_equality"' "$good/out.jsonl" 'the summary carries the traffic comparison'
if python3 -c 'import json,sys
rows=[json.loads(l) for l in open(sys.argv[1]) if l.strip()]
s=[r for r in rows if r.get("kind")=="summary"][-1]
sys.exit(0 if s.get("run_dir")==sys.argv[2] else 1)' "$good/out.jsonl" "$good_abs"; then
    ok 'the summary records the resolved run dir'
else
    bad 'the summary did not record the resolved run dir'
fi

# 4. One side was handed half the work: not head-to-head, so abort.
gap="$work/gap"
gap_abs=$(rss_soak_prepare_run_dir "$gap" "$gap/out.jsonl")
artifact "$gap/out.jsonl" "$gap_abs" rising
printf '{"round_trips":600,"total_bytes":2000000,"failed_streams":0}\n' > "$gap/rs-churn.json"
printf '{"round_trips":600,"total_bytes":2000000,"failed_streams":0}\n' > "$gap/rs-steady.json"
printf '{"round_trips":300,"total_bytes":1000000,"failed_streams":0}\n' > "$gap/go-churn.json"
printf '{"total_bytes":1000000,"failed_streams":0}\n' > "$gap/go-steady.json"
summary "$gap/out.jsonl" "" "$gap/rs-churn.json" "$gap/go-churn.json" \
    "$gap/rs-steady.json" "$gap/go-steady.json"
expect_rc 3 "$?" 'a one-sided traffic gap -> abort'
expect_grep 'differs by' "$gap/out.jsonl" 'the gap is named as the abort reason'

# 5. A steady path that lost a stream: the run is torn, so abort.
torn="$work/torn"
torn_abs=$(rss_soak_prepare_run_dir "$torn" "$torn/out.jsonl")
artifact "$torn/out.jsonl" "$torn_abs" rising
printf '{"round_trips":600,"total_bytes":2000000,"failed_streams":0}\n' > "$torn/rs-churn.json"
printf '{"round_trips":600,"total_bytes":2000000,"failed_streams":0}\n' > "$torn/go-churn.json"
printf '{"total_bytes":2000000,"failed_streams":0}\n' > "$torn/rs-steady.json"
printf '{"total_bytes":2000000,"failed_streams":2}\n' > "$torn/go-steady.json"
summary "$torn/out.jsonl" "" "$torn/rs-churn.json" "$torn/go-churn.json" \
    "$torn/rs-steady.json" "$torn/go-steady.json"
expect_rc 3 "$?" 'a lost steady stream -> abort'
expect_grep 'lost 2 stream' "$torn/out.jsonl" 'the torn path is named'

# 6. `ps` printing a constant: every reading is well-formed, but a whole column
#    that never moves is the shape of an UNMEASURED line, not of a stable
#    process. This is the "perfectly flat" artifact a stubbed `ps` produced.
const="$work/const"
const_abs=$(rss_soak_prepare_run_dir "$const" "$const/out.jsonl")
artifact "$const/out.jsonl" "$const_abs" const
traffic_rows "$const" 600 2000000
summary "$const/out.jsonl" "" "$const/rs-churn.json" "$const/go-churn.json" \
    "$const/rs-steady.json" "$const/go-steady.json"
expect_rc 3 "$?" 'a column that never moves -> abort'
expect_grep 'identical RSS' "$const/out.jsonl" 'the constant column is named'
expect_no_grep 'run completed' "$const/out.jsonl.stdout" 'a constant column is not completed'

# 7. Well-formed but implausible magnitudes (a hand-made artifact, or `ps`
#    returning nonsense): refused by the reader even though the generator would
#    never have written them.
huge="$work/huge"
huge_abs=$(rss_soak_prepare_run_dir "$huge" "$huge/out.jsonl")
artifact "$huge/out.jsonl" "$huge_abs" huge
traffic_rows "$huge" 600 2000000
summary "$huge/out.jsonl" "" "$huge/rs-churn.json" "$huge/go-churn.json" \
    "$huge/rs-steady.json" "$huge/go-steady.json"
expect_rc 3 "$?" 'an implausible RSS magnitude -> abort'
expect_grep 'implausible RSS reading' "$huge/out.jsonl" 'the implausible readings are named'

# 8. A `nan` tolerance used to slip past float() and disable the achieved-load
#    reconciliation while the run still reported "run completed".
nan="$work/nan"
nan_abs=$(rss_soak_prepare_run_dir "$nan" "$nan/out.jsonl")
artifact "$nan/out.jsonl" "$nan_abs" rising
traffic_rows "$nan" 600 2000000
export SOAK_TRAFFIC_TOLERANCE=nan
summary "$nan/out.jsonl" "" "$nan/rs-churn.json" "$nan/go-churn.json" \
    "$nan/rs-steady.json" "$nan/go-steady.json"
nan_rc=$?
unset SOAK_TRAFFIC_TOLERANCE
expect_rc 3 "$nan_rc" 'a nan tolerance -> abort'
expect_grep 'not a finite positive number' "$nan/out.jsonl" 'the nan tolerance is named'
expect_no_grep 'NaN' "$nan/out.jsonl" 'NaN is never recorded as a tolerance'

# 9. The same binary on both sides is not a comparison. The soak refuses this
#    before the window opens; a hand-edited artifact must not present it either.
same="$work/same"
same_abs=$(rss_soak_prepare_run_dir "$same" "$same/out.jsonl")
artifact "$same/out.jsonl" "$same_abs" rising \
    ',"bin_sha256":{"rs_frps":"aaa","go_frps":"aaa","rs_frpc":"bbb","go_frpc":"ccc"}'
traffic_rows "$same" 600 2000000
summary "$same/out.jsonl" "" "$same/rs-churn.json" "$same/go-churn.json" \
    "$same/rs-steady.json" "$same/go-steady.json"
expect_rc 3 "$?" 'identical frp-rs and Go binaries -> abort'
expect_grep 'same binary' "$same/out.jsonl" 'the shared binary is named'

# 10. A run that moved almost nothing did measure something, but not enough to
#     support any comparison: refused by an absolute floor.
tiny="$work/tiny"
tiny_abs=$(rss_soak_prepare_run_dir "$tiny" "$tiny/out.jsonl")
artifact "$tiny/out.jsonl" "$tiny_abs" rising
traffic_rows "$tiny" 1 1
summary "$tiny/out.jsonl" "" "$tiny/rs-churn.json" "$tiny/go-churn.json" \
    "$tiny/rs-steady.json" "$tiny/go-steady.json"
expect_rc 3 "$?" 'degenerate achieved totals -> abort'
expect_grep 'only 1 round trips' "$tiny/out.jsonl" 'the churn floor is named'
expect_grep 'moved only 1 bytes' "$tiny/out.jsonl" 'the steady floor is named'

# 11. A DECREASING series must produce a negative slope. A sign error in the
#     trend computation otherwise leaves every "no growth" statement intact.
fall="$work/fall"
fall_abs=$(rss_soak_prepare_run_dir "$fall" "$fall/out.jsonl")
artifact "$fall/out.jsonl" "$fall_abs" falling
traffic_rows "$fall" 600 2000000
summary "$fall/out.jsonl" "" "$fall/rs-churn.json" "$fall/go-churn.json" \
    "$fall/rs-steady.json" "$fall/go-steady.json"
expect_rc 0 "$?" 'a falling series still completes'
if python3 -c 'import json,sys
rows=[json.loads(l) for l in open(sys.argv[1]) if l.strip()]
t=[r for r in rows if r.get("kind")=="summary"][-1]["trend"]["frp_rs_frps_kb"]
sys.exit(0 if t["slope_kb_per_hour"] < 0 and t["monotonic_nondecreasing"] is False else 1)' \
        "$fall/out.jsonl"; then
    ok 'a falling series reports a negative slope and not-non-decreasing'
else
    bad 'the trend did not report the falling series as falling'
fi

# ------------------------------------------------- rss reading guard (real fn)
hdr 'rss reading guard'

stub="$work/stub"
mkdir -p -- "$stub"
stub_ps() { # <shell body>
    printf '#!/bin/sh\n%s\n' "$1" > "$stub/ps"
    chmod +x "$stub/ps"
}
stub_ps 'printf "0\n"'
out=$(PATH="$stub:$PATH" rss_soak_rss_kb $$ 104857600)
if [ "$out" = "null" ]; then ok 'a ps stub printing 0 yields no reading'; else bad "0 yielded '$out'"; fi

stub_ps 'printf "1234\n"'
out=$(PATH="$stub:$PATH" rss_soak_rss_kb $$ 104857600)
if [ "$out" = "1234" ]; then ok 'one plausible reading passes (whole-column constancy is the reader s job)'; else bad "1234 yielded '$out'"; fi

stub_ps 'printf "999999999\n"'
out=$(PATH="$stub:$PATH" rss_soak_rss_kb $$ 104857600)
if [ "$out" = "null" ]; then ok 'a reading above the ceiling yields no reading'; else bad "999999999 yielded '$out'"; fi

stub_ps 'printf -- "-5\n"'
out=$(PATH="$stub:$PATH" rss_soak_rss_kb $$ 104857600)
if [ "$out" = "null" ]; then ok 'a negative reading yields no reading'; else bad "-5 yielded '$out'"; fi

stub_ps 'printf "12.5\n"'
out=$(PATH="$stub:$PATH" rss_soak_rss_kb $$ 104857600)
if [ "$out" = "null" ]; then ok 'a non-integer reading yields no reading'; else bad "12.5 yielded '$out'"; fi

stub_ps 'exit 0'
out=$(PATH="$stub:$PATH" rss_soak_rss_kb $$ 104857600)
if [ "$out" = "null" ]; then ok 'an empty ps output yields no reading'; else bad "empty output yielded '$out'"; fi

out=$(rss_soak_rss_kb $$ 104857600)
if [ -n "$out" ] && [ "$out" != "null" ] && [ "$out" -gt 0 ] 2>/dev/null; then
    ok "the real ps is still believed for this process ($out KB)"
else
    bad "the real ps was not believed for this process (got '$out')"
fi

floor_check
printf '\nRESULT: %d fixture check(s) hold\n' "$((checks - fails))"
exit "$fails"
