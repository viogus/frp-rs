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
# from `scripts/lib/rss-soak-run-dir.sh` and the real reader
# `scripts/lib/rss-soak-summary.py` against synthetic directories. No network, no
# built binary and no `ps` sample, so it is safe and fast in the `health` job.

set -uo pipefail

self=$0
ROOT=$(cd -P -- "$(dirname -- "$self")/../.." && pwd)
LIB="$ROOT/scripts/lib/rss-soak-run-dir.sh"
SUMMARY="$ROOT/scripts/lib/rss-soak-summary.py"

checks=0
fails=0
work=$(mktemp -d "${TMPDIR:-/tmp}/rss-soak-fixture.XXXXXX")
cleanup() { rm -rf -- "$work"; }
trap cleanup EXIT

ok() { checks=$((checks + 1)); printf '  ok    %s\n' "$1"; }
bad() { checks=$((checks + 1)); fails=$((fails + 1)); printf '  FAIL  %s\n' "$1"; }
hdr() { printf '%s\n' "$1"; }

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

# ------------------------------------------------------- summary reader (real)
hdr 'summary reader'

summary() { # <artifact> <aborted> <rs-churn> <go-churn> <rs-steady> <go-steady>
    python3 "$SUMMARY" "$@" > "$1.stdout" 2>&1
    return $?
}

artifact() { # <path> <run_dir> <1|0 = RSS readings or nulls>
    local path="$1" dir="$2" rss="$3" i kb
    printf '{"kind":"meta","duration_s":300,"interval_s":45,"run_dir":"%s","frp_rs_sha":"deadbeef"}\n' \
        "$dir" > "$path"
    for i in 0 45 90; do
        if [ "$rss" = 1 ]; then
            kb=$((12000 + i * 10))
            printf '{"kind":"sample","elapsed_s":%d,"load1":3.1,"time_wait":400,"frp_rs_frps_kb":%d,"frp_rs_frpc_kb":%d,"go_frps_kb":%d,"go_frpc_kb":%d}\n' \
                "$i" "$kb" "$kb" "$((kb + 20000))" "$((kb + 12000))" >> "$path"
        else
            printf '{"kind":"sample","elapsed_s":%d,"load1":3.1,"time_wait":400,"frp_rs_frps_kb":null,"frp_rs_frpc_kb":null,"go_frps_kb":null,"go_frpc_kb":null}\n' \
                "$i" >> "$path"
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

# 1. A run whose generators died early: the rows on disk predate the run, and
#    the soak clears them before the window opens. The summary must then abort
#    and must not publish the earlier run's numbers.
stale="$work/stale"
stale_abs=$(rss_soak_prepare_run_dir "$stale" "$stale/out.jsonl")
traffic_rows "$stale" 2376 999999
# The soak's order: clear (after pre-flight, before the window), then write meta
# and samples.
rss_soak_clear_run_artifacts "$stale" "$stale/out.jsonl"
artifact "$stale/out.jsonl" "$stale_abs" 1
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
artifact "$norss/out.jsonl" "$norss_abs" 0
traffic_rows "$norss" 600 1200
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
artifact "$good/out.jsonl" "$good_abs" 1
traffic_rows "$good" 600 1200
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
artifact "$gap/out.jsonl" "$gap_abs" 1
printf '{"round_trips":600,"total_bytes":1000,"failed_streams":0}\n' > "$gap/rs-churn.json"
printf '{"round_trips":600,"total_bytes":1000,"failed_streams":0}\n' > "$gap/rs-steady.json"
printf '{"round_trips":300,"total_bytes":500,"failed_streams":0}\n' > "$gap/go-churn.json"
printf '{"total_bytes":500,"failed_streams":0}\n' > "$gap/go-steady.json"
summary "$gap/out.jsonl" "" "$gap/rs-churn.json" "$gap/go-churn.json" \
    "$gap/rs-steady.json" "$gap/go-steady.json"
expect_rc 3 "$?" 'a one-sided traffic gap -> abort'
expect_grep 'differs by' "$gap/out.jsonl" 'the gap is named as the abort reason'

# 5. A steady path that lost a stream: the run is torn, so abort.
torn="$work/torn"
torn_abs=$(rss_soak_prepare_run_dir "$torn" "$torn/out.jsonl")
artifact "$torn/out.jsonl" "$torn_abs" 1
printf '{"round_trips":600,"total_bytes":1000,"failed_streams":0}\n' > "$torn/rs-churn.json"
printf '{"round_trips":600,"total_bytes":1000,"failed_streams":0}\n' > "$torn/go-churn.json"
printf '{"total_bytes":1000,"failed_streams":0}\n' > "$torn/rs-steady.json"
printf '{"total_bytes":1000,"failed_streams":2}\n' > "$torn/go-steady.json"
summary "$torn/out.jsonl" "" "$torn/rs-churn.json" "$torn/go-churn.json" \
    "$torn/rs-steady.json" "$torn/go-steady.json"
expect_rc 3 "$?" 'a lost steady stream -> abort'
expect_grep 'lost 2 stream' "$torn/out.jsonl" 'the torn path is named'

printf '\nRESULT: %d fixture check(s) hold\n' "$((checks - fails))"
exit "$fails"
