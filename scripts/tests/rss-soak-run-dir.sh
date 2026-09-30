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
# / `rss_soak_validate_window` / `rss_soak_rss_kb` / `rss_soak_write_meta` from
# `scripts/lib/rss-soak-run-dir.sh` and the real reader
# `scripts/lib/rss-soak-summary.py` against synthetic directories. No network, no
# built binary and no real traffic, so it is safe and fast in the `health` job.
#
# The suite also covers the round-3 findings, where a well-formed but WRONG
# reading was published as evidence: a `ps` stub printing `0` or a constant, an
# artifact whose columns are all one value, implausible magnitudes, a `nan`
# tolerance that disabled the achieved-load check, one binary on both sides, and
# degenerate totals.
#
# Round 4 adds: the JSON escaping of the meta writer (a `"`/`\` in the run dir
# used to make the line unparseable and silently drop run_dir, the digests, the
# ports and the same-binary guard), the artifact's own recorded RSS ceiling
# taking precedence over the reader's environment, the one-reading abort path,
# a monotonic (sticky) abort verdict, the 1 GiB default ceiling, and a marker per
# scenario so a deleted case cannot be hidden by padding the check count.

set -uo pipefail

self=$0
ROOT=$(cd -P -- "$(dirname -- "$self")/../.." && pwd)
LIB="$ROOT/scripts/lib/rss-soak-run-dir.sh"
SUMMARY="$ROOT/scripts/lib/rss-soak-summary.py"

# A UTF-8 locale for the round-5 locale-independence checks: the escaper bug is
# only reachable with one active, and `C` alone cannot see it. `C` itself is
# always available. (No pipe here: the suite sets `pipefail`, and `grep -q` exits
# early, so `locale -a | grep -q ...` reports 141 via SIGPIPE even on a match.)
utf8_locale=""
available_locales=$(locale -a 2>/dev/null || true)
for cand in en_US.UTF-8 C.UTF-8 en_US.utf8 C.utf8; do
    if grep -qxF -- "$cand" <<<"$available_locales"; then utf8_locale="$cand"; break; fi
done

# Floor on the number of checks that must run. Deleting a case (or returning
# early past one) leaves every remaining assertion green, so without this the
# suite cannot detect its own neutering. Enforced from the EXIT trap below, which
# is installed before the first assertion, and again explicitly before RESULT.
MIN_CHECKS=158
# MIN_CHECKS is a COUNT and a count is not an identity: deleting case 6 and
# padding with three dummy `ok` calls restored the floor while the constant
# column — one of the two shapes this suite exists to refuse — went untested.
# Each section/case therefore also leaves a marker, and the suite asserts that
# every expected marker is present at the end. A deleted or skipped case loses
# its marker even when the total count still clears the floor.

checks=0
fails=0
floor_armed=1
work=$(mktemp -d "${TMPDIR:-/tmp}/rss-soak-fixture.XXXXXX")
MARKERS="$work/markers.log"
: > "$MARKERS"
cleanup() { rm -rf -- "$work"; }

ok() { checks=$((checks + 1)); printf '  ok    %s\n' "$1"; }
bad() { checks=$((checks + 1)); fails=$((fails + 1)); printf '  FAIL  %s\n' "$1"; }
hdr() { printf '%s\n' "$1"; }
mark() { printf '%s\n' "$1" >> "$MARKERS"; }
require_marker() { # <name>
    if grep -qxF -- "$1" "$MARKERS" 2>/dev/null; then
        ok "scenario ran: $1"
    else
        bad "scenario missing: $1 (its checks were deleted or skipped)"
    fi
}

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
mark run-dir-guard

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
mark window-tolerance

if rss_soak_validate_window abc 30 >/dev/null 2>&1; then bad 'window refuses a non-numeric duration'; else ok 'window refuses a non-numeric duration'; fi
if rss_soak_validate_window 59 30 >/dev/null 2>&1; then bad 'window refuses a duration below 60'; else ok 'window refuses a duration below 60'; fi
if rss_soak_validate_window 60 0 >/dev/null 2>&1; then bad 'window refuses a zero interval'; else ok 'window refuses a zero interval'; fi
if rss_soak_validate_window 60 30 >/dev/null 2>&1; then ok 'window accepts the documented minimum'; else bad 'window refused 60/30'; fi
if rss_soak_validate_tolerance nan >/dev/null 2>&1; then bad 'tolerance refuses nan'; else ok 'tolerance refuses nan'; fi
if rss_soak_validate_tolerance 0 >/dev/null 2>&1; then bad 'tolerance refuses 0'; else ok 'tolerance refuses 0'; fi
if rss_soak_validate_tolerance 1.5 >/dev/null 2>&1; then bad 'tolerance refuses a value above 1'; else ok 'tolerance refuses a value above 1'; fi
if rss_soak_validate_tolerance 0.10 >/dev/null 2>&1; then ok 'tolerance accepts the default 0.10'; else bad 'tolerance refused 0.10'; fi
# The tolerance is recorded verbatim in `meta`; awk accepts these but JSON does
# not, and an unparseable meta line is silently skipped by the reader.
if rss_soak_validate_tolerance .5 >/dev/null 2>&1; then bad 'tolerance accepts .5 (invalid JSON number)'; else ok 'tolerance refuses .5 (invalid JSON number)'; fi
if rss_soak_validate_tolerance +0.5 >/dev/null 2>&1; then bad 'tolerance accepts +0.5 (invalid JSON number)'; else ok 'tolerance refuses +0.5 (invalid JSON number)'; fi
if rss_soak_validate_tolerance 01 >/dev/null 2>&1; then bad 'tolerance accepts 01 (invalid JSON number)'; else ok 'tolerance refuses 01 (invalid JSON number)'; fi
if rss_soak_validate_tolerance 1e-1 >/dev/null 2>&1; then ok 'tolerance accepts the JSON number 1e-1'; else bad 'tolerance refused 1e-1'; fi

# -------------------------------------------------------------- lock policy
# The lock is taken before the builds, so these run in well under a second and
# never touch cargo. An EMPTY lock must be treated as held: the winner creates
# the file and writes its pid in two steps, and stealing the lock in between
# starts a second soak on the same ports.
hdr 'lock policy'
mark lock-policy

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

# ---------------------------------------------- meta writer (JSON escaping)
# The `meta` record is JSON Lines and interpolates operator-supplied strings.
# A `"` or `\` in the run dir (or a binary path, or the host name) used to make
# the line unparseable, and the reader SILENTLY SKIPS an unparseable line: the
# artifact lost run_dir, harness_sha256, bin_sha256, the ports and the recipe,
# the identical-binaries guard never ran, and the run still printed
# "run completed". These checks push such a string through the REAL writer
# (rss_soak_write_meta) and parse the line back.
hdr 'meta writer (JSON escaping)'
mark meta-writer

nasty_dir="$work/nasty\"dir\\x"
nasty_bin="$work/bin\"q\\b/frps"
nasty_host=$(printf 'host"name\ttab')
nasty_meta="$work/nasty-meta.jsonl"
if rss_soak_write_meta "$nasty_meta" \
    '2026-01-01T00:00:00Z' 300 45 320 "$nasty_host" darwin 8 "0.71.0" deadbeef false \
    h1 h2 h3 h4 'built-here' "$nasty_dir" "0.71.0" "$work/go\"dir" "$nasty_bin" "$work/frpc" \
    8 40 64 3 5 18100 18101 18102 18200 18201 18202 \
    aa bb cc dd 1.5 1048576 0.10; then
    ok 'the writer accepts quotes and backslashes in its string fields'
else
    bad 'the writer refused a well-formed call'
fi
if python3 -c 'import json,sys
m=json.loads(open(sys.argv[1]).read().splitlines()[0])
sys.exit(0 if (m["run_dir"]==sys.argv[2] and m["rs_bin"]==sys.argv[3]
               and m["host"]==sys.argv[4] and m["go_frp_dir"]==sys.argv[5]
               and m["rss_ceiling_kb"]==1048576
               and m["traffic_tolerance"]==0.10) else 1)' \
        "$nasty_meta" "$nasty_dir" "$nasty_bin" "$nasty_host" "$work/go\"dir"; then
    ok 'the meta line parses back to the same quoted paths, ceiling and tolerance'
else
    bad 'the meta line from a quoted run dir is not valid JSON or lost its values'
fi
if python3 -c 'import json,sys
json.loads(open(sys.argv[1]).read().splitlines()[0])' "$nasty_meta" >/dev/null 2>&1; then
    ok 'the reader (json) can parse the meta line it was handed'
else
    bad 'the meta line is invalid JSON (JSONDecodeError)'
fi
if rss_soak_write_meta "$work/bad-meta.jsonl" one two >/dev/null 2>&1; then
    bad 'the writer accepted a truncated argument list'
else
    ok 'the writer refuses a truncated argument list'
fi
if [ -e "$work/bad-meta.jsonl" ]; then
    bad 'a refused meta write still created the artifact'
else
    ok 'a refused meta write appends nothing'
fi

# -------------------------------------------- meta writer (locale independence)
# round 5: the escaper was LOCALE-DEPENDENT. `[[:cntrl:]]` and `${s:0:1}` are
# byte-oriented only in the C locale; under any UTF-8 locale bash 3.2 matched the
# Unicode Cc/Cf categories too, so U+200B took the `\u` branch and
# `printf "'$ch"` sign-extended its first byte into `\uffffffffffffffe2` — valid
# JSON, silently wrong value. These teeth sweep the code points through the REAL
# function and round-trip a REAL artifact whose run dir contains U+200B, U+00AD
# and a combining mark, under a UTF-8 locale and under C.
hdr 'meta writer (locale independence)'
mark meta-escaper-locale

escaper_cases="$work/escaper-cases.sh"
python3 - "$escaper_cases" <<'PY'
import sys
# U+0001..U+00FF (U+0000 is unreachable: a bash string cannot hold a NUL byte),
# plus the Unicode Cc/Cf points bash 3.2's [[:cntrl:]] also matched in a UTF-8
# locale, plus the named-escape targets the escaper must keep in short form.
extra = [
    0x0600, 0x0601, 0x0602, 0x0603, 0x0604, 0x0605, 0x061C, 0x06DD, 0x070F,
    0x0890, 0x0891, 0x08E2, 0x180E,
    0x200B, 0x200C, 0x200D, 0x200E, 0x200F,
    0x202A, 0x202B, 0x202C, 0x202D, 0x202E,
    0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0x2066, 0x2069,
    0xFFF9, 0xFFFA, 0xFFFB, 0xE0001, 0xE0020,
    0x0008, 0x0009, 0x000A, 0x000C, 0x000D,
]
points = list(range(1, 0x100)) + extra
out = ["CASES=()"]
for cp in points:
    # bash 3.2's printf has no \u escape, and $'...' carries the raw bytes just
    # as well: emit the UTF-8 encoding as \xNN byte escapes.
    out.append("CASES+=( $'%s' )" % "".join("\\x%02x" % b for b in chr(cp).encode("utf-8")))
open(sys.argv[1], "w").write("\n".join(out) + "\n")
PY
sweep_n=$(grep -c 'CASES+=' "$escaper_cases")

escaper_sweep() { # <env arg>... -> NUL-delimited (input, escaped) records on stdout
    env "$@" bash -c '
        set -uo pipefail
        . "$1"
        . "$2"
        for ch in "${CASES[@]}"; do
            printf "%s\0%s\0" "$ch" "$(rss_soak_json_str "$ch")"
        done
    ' _ "$LIB" "$escaper_cases"
}

sweep_roundtrips() { # <file> <locale> -> 0 if every record decodes back
    python3 - "$1" "$2" "$sweep_n" <<'PY'
import json, sys
raw = open(sys.argv[1], "rb").read()
fields = raw.split(b"\0")
if fields and fields[-1] == b"":
    fields.pop()
if len(fields) != 2 * int(sys.argv[3]):
    print(f"swept {len(fields) // 2} case(s), expected {sys.argv[3]}", file=sys.stderr)
    sys.exit(1)
bad = 0
for i in range(0, len(fields), 2):
    src, esc = fields[i], fields[i + 1]
    try:
        got = json.loads(b'"' + esc + b'"').encode("utf-8")
    except Exception:
        got = None
    if got != src:
        bad += 1
        if bad <= 3:
            print(f"{src.hex()} -> {esc!r} -> {None if got is None else got.hex()}", file=sys.stderr)
sys.exit(1 if bad else 0)
PY
}

sweep_one() { # <label> <env arg>...
    local label="$1"
    shift
    if escaper_sweep "$@" > "$work/sweep.bin" 2> "$work/sweep.err" \
       && sweep_roundtrips "$work/sweep.bin" "$label"; then
        ok "$sweep_n code points round-trip through rss_soak_json_str under $label"
    else
        bad "rss_soak_json_str does not round-trip every code point under $label"
        sed 's/^/      /' "$work/sweep.err"
    fi
}

if [ -z "$utf8_locale" ]; then
    bad 'no UTF-8 locale is installed, so the escaper cannot be tested as documented'
else
    # The environments round 5 named, plus C. The defect was that the escape
    # branch consulted the ambient locale at all, so each of them has to hold.
    sweep_one "LC_ALL=$utf8_locale" "LC_ALL=$utf8_locale" "LC_CTYPE=$utf8_locale"
    sweep_one "LANG=$utf8_locale (LC_ALL and LC_CTYPE unset)" -u LC_ALL -u LC_CTYPE "LANG=$utf8_locale"
    sweep_one 'LC_ALL=C.UTF-8' 'LC_ALL=C.UTF-8' 'LC_CTYPE=C.UTF-8'
    sweep_one 'LC_CTYPE=C' -u LC_ALL -u LANG 'LC_CTYPE=C'
fi

esc_01=$(rss_soak_json_str $'\x01')
esc_7f=$(rss_soak_json_str $'\x7f')
esc_nl=$(rss_soak_json_str $'\n')
esc_bs=$(rss_soak_json_str '\')
esc_q=$(rss_soak_json_str '"')
if [ "$esc_01" = '\u0001' ] && [ "$esc_7f" = '\u007f' ] && [ "$esc_nl" = '\n' ] \
   && [ "$esc_bs" = '\\' ] && [ "$esc_q" = '\"' ]; then
    ok 'the ASCII control/quote/backslash escapes keep their exact short forms'
else
    bad "ASCII escapes changed: 0x01=$esc_01 0x7F=$esc_7f NL=$esc_nl BS=$esc_bs Q=$esc_q"
fi

# ------------------------------------------------------- summary reader (real)
hdr 'summary reader'
mark summary-reader

summary() { # <artifact> <aborted> <rs-churn> <go-churn> <rs-steady> <go-steady>
    python3 "$SUMMARY" "$@" > "$1.stdout" 2>&1
    return $?
}

artifact() { # <path> <run_dir> <mode: rising|nulls|const|huge|falling|single|big2g> [extra-meta-json]
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
            # ~1.9 GiB: above the 1 GiB default the reader falls back to, below
            # the old 100 GiB default.
            big2g)   kb=2000000 ;;
            # Exactly ONE sample: one reading per column cannot show stability.
            single)  [ "$i" = 0 ] || break; kb=12000 ;;
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

# meta writer (locale independence), part 2: writer -> reader through a REAL
# artifact whose run dir carries U+200B, U+00AD, a combining mark (U+0301) and
# the two line-ish separators (U+0085, U+2028) that a `str.splitlines()`-based
# reader would shred. The writer runs under the locale under test; the reader
# must hand the same bytes back in the summary record. (Part 1, the direct sweep,
# is above; this half needs the reader helpers defined.)
zwsp=$'\xe2\x80\x8b'
shy=$'\xc2\xad'
comb=$'e\xcc\x81'
nel=$'\xc2\x85'
lsep=$'\xe2\x80\xa8'
for loc in "$utf8_locale" C; do
    [ -n "$loc" ] || continue
    rt="$work/roundtrip-$loc"
    mkdir -p -- "$rt"
    rt_abs=$(rss_soak_prepare_run_dir "$rt/run-$zwsp$shy-$comb$nel$lsep" "$rt/out.jsonl")
    if LC_ALL="$loc" LC_CTYPE="$loc" rss_soak_write_meta "$rt/out.jsonl" \
        '2026-01-01T00:00:00Z' 300 45 320 'host' darwin 8 "0.71.0" deadbeef false \
        h1 h2 h3 h4 'built-here' "$rt_abs" "0.71.0" "$rt/go" "$rt/frps" "$rt/frpc" \
        8 40 64 3 5 18100 18101 18102 18200 18201 18202 \
        aa bb cc dd 1.5 1048576 0.10; then
        ok "the writer accepts a run dir with U+200B/U+00AD/U+0301 under LC_ALL=$loc"
    else
        bad "the writer refused a UTF-8 run dir under LC_ALL=$loc"
    fi
    for i in 0 45 90 135 180; do
        printf '{"kind":"sample","elapsed_s":%d,"load1":3.1,"time_wait":400,"frp_rs_frps_kb":%d,"frp_rs_frpc_kb":%d,"go_frps_kb":%d,"go_frpc_kb":%d}\n' \
            "$i" $((12000 + i * 10)) $((12010 + i * 10)) $((32000 + i * 10)) $((24000 + i * 10)) \
            >> "$rt/out.jsonl"
    done
    traffic_rows "$rt" 600 2000000
    summary "$rt/out.jsonl" "" "$rt/rs-churn.json" "$rt/go-churn.json" "$rt/rs-steady.json" "$rt/go-steady.json"
    expect_rc 0 $? "a real artifact with a UTF-8 run dir reads clean under LC_ALL=$loc"
    if python3 -c 'import json,sys
rows=[json.loads(l) for l in open(sys.argv[1], encoding="utf-8") if l.strip()]
s=[r for r in rows if r.get("kind")=="summary"][-1]
sys.exit(0 if s.get("run_dir")==sys.argv[2] else 1)' "$rt/out.jsonl" "$rt_abs"; then
        ok "the reader returns the UTF-8 run dir byte-identically under LC_ALL=$loc"
    else
        bad "the reader returned a different run dir under LC_ALL=$loc"
    fi
done

# 1. A run whose generators died early: the rows on disk predate the run, and
#    the soak clears them before the window opens. The summary must then abort
#    and must not publish the earlier run's numbers.
mark summary-case-01
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
mark summary-case-02
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
mark summary-case-03
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
mark summary-case-04
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
mark summary-case-05
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
mark summary-case-06
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
mark summary-case-07
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
mark summary-case-08
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
mark summary-case-09
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
mark summary-case-10
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
mark summary-case-11
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

# 12. Exactly one reading per column is not a series: a single point cannot show
#     that anything is stable. Columns with fewer than two readings used to be
#     skipped, so this artifact printed "run completed".
mark summary-case-12
one="$work/one"
one_abs=$(rss_soak_prepare_run_dir "$one" "$one/out.jsonl")
artifact "$one/out.jsonl" "$one_abs" single
traffic_rows "$one" 600 2000000
summary "$one/out.jsonl" "" "$one/rs-churn.json" "$one/go-churn.json" \
    "$one/rs-steady.json" "$one/go-steady.json"
expect_rc 3 "$?" 'a single RSS reading per column -> abort'
expect_grep 'has only 1 RSS reading' "$one/out.jsonl" 'the lone reading is named'
expect_grep '"samples": 1' "$one/out.jsonl" 'the summary counted exactly one sample'
expect_no_grep 'run completed' "$one/out.jsonl.stdout" 'one reading is not completed'

# 13. The artifact's OWN recorded ceiling wins over the reader's environment.
#     This series was produced under a 40000 KB ceiling and its readings sit
#     under it, so a reader whose SOAK_RSS_CEILING_KB is a hostile 1 KB must
#     still accept it. Before the fix the ceiling came from the env alone, so the
#     SAME artifact read "run completed" here and rc 3 "implausible" there.
mark summary-case-13
ceil="$work/ceil"
ceil_abs=$(rss_soak_prepare_run_dir "$ceil" "$ceil/out.jsonl")
artifact "$ceil/out.jsonl" "$ceil_abs" rising ',"rss_ceiling_kb":40000'
traffic_rows "$ceil" 600 2000000
export SOAK_RSS_CEILING_KB=1
summary "$ceil/out.jsonl" "" "$ceil/rs-churn.json" "$ceil/go-churn.json" \
    "$ceil/rs-steady.json" "$ceil/go-steady.json"
ceil_rc=$?
unset SOAK_RSS_CEILING_KB
expect_rc 0 "$ceil_rc" 'the artifact ceiling beats a hostile-low ambient env'
expect_grep 'from artifact meta' "$ceil/out.jsonl.stdout" 'the ceiling source is the artifact'
expect_grep '"rss_ceiling_kb": 40000' "$ceil/out.jsonl" 'the summary records the artifact ceiling'

# 14. ... and the ambient env cannot RAISE it either: this artifact records a
#     10000 KB ceiling while its readings are ~12-32 MB, so it must abort even
#     though the reader's default ceiling (1 GiB) would have accepted them.
mark summary-case-14
lowceil="$work/lowceil"
lowceil_abs=$(rss_soak_prepare_run_dir "$lowceil" "$lowceil/out.jsonl")
artifact "$lowceil/out.jsonl" "$lowceil_abs" rising ',"rss_ceiling_kb":10000'
traffic_rows "$lowceil" 600 2000000
unset SOAK_RSS_CEILING_KB
summary "$lowceil/out.jsonl" "" "$lowceil/rs-churn.json" "$lowceil/go-churn.json" \
    "$lowceil/rs-steady.json" "$lowceil/go-steady.json"
expect_rc 3 "$?" 'an artifact ceiling below its own readings -> abort'
expect_grep 'outside 1..10000 KB' "$lowceil/out.jsonl" 'the artifact ceiling is the one applied'

# 15. The verdict is monotonic. The reader APPENDS a summary, so re-running it
#     over an artifact that already aborted used to append "run completed"
#     behind the death verdict once the traffic rows were healthy (or trimmed):
#     a consumer that takes the last summary was misled.
mark summary-case-15
sticky="$work/sticky"
sticky_abs=$(rss_soak_prepare_run_dir "$sticky" "$sticky/out.jsonl")
artifact "$sticky/out.jsonl" "$sticky_abs" rising
printf '{"round_trips":600,"total_bytes":2000000,"failed_streams":0}\n' > "$sticky/rs-churn.json"
printf '{"round_trips":600,"total_bytes":2000000,"failed_streams":0}\n' > "$sticky/go-churn.json"
printf '{"total_bytes":2000000,"failed_streams":0}\n' > "$sticky/rs-steady.json"
printf '{"total_bytes":2000000,"failed_streams":2}\n' > "$sticky/go-steady.json"
summary "$sticky/out.jsonl" "" "$sticky/rs-churn.json" "$sticky/go-churn.json" \
    "$sticky/rs-steady.json" "$sticky/go-steady.json"
expect_rc 3 "$?" 'the torn run aborts and records the death verdict'
printf '{"total_bytes":2000000,"failed_streams":0}\n' > "$sticky/go-steady.json"
summary "$sticky/out.jsonl" "" "$sticky/rs-churn.json" "$sticky/go-churn.json" \
    "$sticky/rs-steady.json" "$sticky/go-steady.json"
expect_rc 3 "$?" 'a re-read cannot clear an existing abort verdict'
expect_grep 'a previous summary already aborted' "$sticky/out.jsonl" 'the prior verdict is named'
expect_grep 'ABORTED' "$sticky/out.jsonl.stdout" 'the re-read still prints ABORTED'
expect_no_grep 'run completed' "$sticky/out.jsonl.stdout" 'the re-read does not print run completed'
if python3 -c 'import json,sys
rows=[json.loads(l) for l in open(sys.argv[1]) if l.strip()]
s=[r for r in rows if r.get("kind")=="summary"]
sys.exit(0 if len(s)==2 and all(r.get("aborted") for r in s) else 1)' "$sticky/out.jsonl"; then
    ok 'both appended summaries carry an abort'
else
    bad 'an appended summary cleared the abort verdict'
fi

# 16. The reader's FALLBACK default (for an artifact that records no ceiling of
#     its own — an older or hand-written series) is 1 GiB, not the old 100 GiB.
#     These ~1.9 GiB readings must be refused; under the old default they were
#     accepted and published as a completed run.
mark summary-case-16
nob="$work/nob"
nob_abs=$(rss_soak_prepare_run_dir "$nob" "$nob/out.jsonl")
artifact "$nob/out.jsonl" "$nob_abs" big2g
traffic_rows "$nob" 600 2000000
unset SOAK_RSS_CEILING_KB
summary "$nob/out.jsonl" "" "$nob/rs-churn.json" "$nob/go-churn.json" \
    "$nob/rs-steady.json" "$nob/go-steady.json"
expect_rc 3 "$?" 'an artifact with no recorded ceiling gets the 1 GiB default'
expect_grep 'outside 1..1048576 KB' "$nob/out.jsonl" 'the 1 GiB fallback default is applied'
expect_grep 'from default' "$nob/out.jsonl.stdout" 'the ceiling source is the default'

# 17. round 5: the traffic tolerance, like the ceiling, is recorded in the
#     artifact and preferred over the reader's environment. Before this, two
#     BYTE-IDENTICAL artifacts got opposite verdicts from SOAK_TRAFFIC_TOLERANCE
#     alone: the default env read rc 3 ("differs by 50.0%"), an ambient 0.6 read
#     rc 0 ("run completed"). An artifact that records nothing must still behave
#     exactly as before (env, then 0.10).
mark summary-case-17

tolerance_case() { # <dir> <recorded|-|> <ambient|-|> <want-rc> <msg>
    local dir="$1" recorded="$2" ambient="$3" want="$4" msg="$5"
    local abs extra="" rc
    mkdir -p -- "$dir"
    abs=$(rss_soak_prepare_run_dir "$dir" "$dir/out.jsonl")
    [ "$recorded" = "-" ] || extra=",\"traffic_tolerance\":$recorded"
    artifact "$dir/out.jsonl" "$abs" rising "$extra"
    # A 50% churn gap: 600 frp-rs round trips vs 300 Go ones.
    printf '{"connections":40,"round_trips":600,"bytes":2000000,"total_bytes":2000000,"mbps":1.0,"failed_streams":0}\n' > "$dir/rs-churn.json"
    printf '{"connections":40,"round_trips":300,"bytes":2000000,"total_bytes":2000000,"mbps":1.0,"failed_streams":0}\n' > "$dir/go-churn.json"
    printf '{"connections":3,"bytes":2000000,"total_bytes":2000000,"mbps":1.0,"failed_streams":0}\n' > "$dir/rs-steady.json"
    cp -- "$dir/rs-steady.json" "$dir/go-steady.json"
    if [ "$ambient" = "-" ]; then unset SOAK_TRAFFIC_TOLERANCE; else export SOAK_TRAFFIC_TOLERANCE="$ambient"; fi
    summary "$dir/out.jsonl" "" "$dir/rs-churn.json" "$dir/go-churn.json" \
        "$dir/rs-steady.json" "$dir/go-steady.json"
    rc=$?
    unset SOAK_TRAFFIC_TOLERANCE
    if [ "$rc" = "$want" ]; then ok "$msg (rc=$rc)"; else bad "$msg (want rc=$want, got rc=$rc)"; fi
}

tolerance_case "$work/tol-rec06-a" 0.6  -    0 'an artifact recording 0.6 completes with the env unset'
tolerance_case "$work/tol-rec06-b" 0.6  0.10 0 'an artifact recording 0.6 beats an ambient 0.10'
tolerance_case "$work/tol-rec06-c" 0.6  0.6  0 'an artifact recording 0.6 agrees with an ambient 0.6'
tolerance_case "$work/tol-rec01-a" 0.10 -    3 'an artifact recording 0.10 aborts with the env unset'
tolerance_case "$work/tol-rec01-b" 0.10 0.10 3 'an artifact recording 0.10 aborts against an ambient 0.10'
tolerance_case "$work/tol-rec01-c" 0.10 0.6  3 'an artifact recording 0.10 beats an ambient 0.6'
tolerance_case "$work/tol-none-a"  -    -    3 'an artifact recording nothing keeps the 0.10 default'
tolerance_case "$work/tol-none-b"  -    0.10 3 'an artifact recording nothing reads an ambient 0.10'
tolerance_case "$work/tol-none-c"  -    0.6  0 'an artifact recording nothing still reads an ambient 0.6'
# A value that is PRESENT but unusable must abort rather than fall through to the
# environment: otherwise a hand-edited artifact is environment-flippable again.
tolerance_case "$work/tol-bogus-a" '"bogus"' -   3 'an artifact recording a string tolerance aborts'
tolerance_case "$work/tol-bogus-b" '"bogus"' 0.6 3 'a recorded string tolerance is not environment-flipped'
# A 400-digit JSON integer overflows float(); it must be "unusable", not a
# traceback rc 1.
huge=$(python3 -c 'print(10 ** 400)')
tolerance_case "$work/tol-huge"    "$huge"   -   3 'a recorded integer too large for a float aborts'
# JSON `null` means "recorded nothing", so env-then-default still applies.
tolerance_case "$work/tol-null-a"  null      -   3 'an artifact recording null keeps the default'
tolerance_case "$work/tol-null-b"  null      0.6 0 'an artifact recording null still reads an ambient 0.6'

expect_grep '"traffic_tolerance": 0.6' "$work/tol-rec06-a/out.jsonl" 'the summary records the artifact tolerance'
expect_grep '"traffic_tolerance_source": "artifact meta"' "$work/tol-rec06-a/out.jsonl" 'the summary names the artifact as the tolerance source'
expect_grep 'traffic tolerance: 0.6 (from artifact meta)' "$work/tol-rec06-a/out.jsonl.stdout" 'the printed table names the artifact as the tolerance source'
expect_grep 'traffic tolerance: 0.1 (from default)' "$work/tol-none-a/out.jsonl.stdout" 'the printed table names the default when the artifact records none'
expect_grep 'traffic tolerance: 0.6 (from environment)' "$work/tol-none-c/out.jsonl.stdout" 'the printed table names the environment when the artifact records none'
expect_grep 'records an unusable traffic tolerance' "$work/tol-bogus-a/out.jsonl" 'an unusable recorded tolerance is named'
expect_no_grep 'Traceback' "$work/tol-huge/out.stdout" 'a giant recorded tolerance is refused, not a traceback'

# 18. round 5: a non-UTF-8 artifact is an UNUSABLE artifact — refused loudly with
#     the artifact name and the byte offset, not a bare traceback and not a
#     silent U+FFFD substitution (the writer stays byte-preserving by design).
mark summary-case-18
badenc="$work/badenc"
mkdir -p -- "$badenc"
printf '{"kind":"meta","run_dir":"/tmp/\377\376"}\n' > "$badenc/out.jsonl"
python3 "$SUMMARY" "$badenc/out.jsonl" "" "$badenc/x" "$badenc/y" "$badenc/z" "$badenc/w" \
    > "$badenc/out.stdout" 2>&1
expect_rc 2 "$?" 'a non-UTF-8 artifact is an unusable artifact (rc 2)'
expect_grep 'not valid UTF-8' "$badenc/out.stdout" 'the decoding failure is named'
expect_grep 'byte offset' "$badenc/out.stdout" 'the failing byte offset is named'
expect_grep 'out\.jsonl' "$badenc/out.stdout" 'the artifact path is named'
expect_no_grep 'Traceback' "$badenc/out.stdout" 'the failure is not a bare traceback'

# ------------------------------------------------- rss reading guard (real fn)
hdr 'rss reading guard'
mark rss-reading-guard

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

# The DEFAULT ceiling is 1 GiB (1048576 KB), justified by the committed memory
# baselines (real RSS 15-30 MB). These pin it: under the old 100 GiB default a
# 2000000 KB (~1.9 GiB) reading was accepted, and this fixture used to pass an
# explicit ceiling everywhere, so the default itself was never exercised.
stub_ps 'printf "2000000\n"'
out=$(PATH="$stub:$PATH" rss_soak_rss_kb $$)
if [ "$out" = "null" ]; then ok 'the default 1 GiB ceiling refuses a ~1.9 GiB reading'; else bad "2000000 yielded '$out' under the default ceiling"; fi

stub_ps 'printf "20000\n"'
out=$(PATH="$stub:$PATH" rss_soak_rss_kb $$)
if [ "$out" = "20000" ]; then ok 'the default 1 GiB ceiling accepts a realistic 20 MB reading'; else bad "20000 yielded '$out' under the default ceiling"; fi

# ---------------------------------------------------------------- coverage floor
# MIN_CHECKS pins a count; these pin the IDENTITY of what ran. A case that is
# deleted (or skipped by an early return) loses its marker even if the count is
# padded back over the floor.
require_marker run-dir-guard
require_marker window-tolerance
require_marker lock-policy
require_marker meta-writer
require_marker meta-escaper-locale
require_marker summary-reader
require_marker summary-case-01
require_marker summary-case-02
require_marker summary-case-03
require_marker summary-case-04
require_marker summary-case-05
require_marker summary-case-06
require_marker summary-case-07
require_marker summary-case-08
require_marker summary-case-09
require_marker summary-case-10
require_marker summary-case-11
require_marker summary-case-12
require_marker summary-case-13
require_marker summary-case-14
require_marker summary-case-15
require_marker summary-case-16
require_marker summary-case-17
require_marker summary-case-18
require_marker rss-reading-guard

floor_check
printf '\nRESULT: %d fixture check(s) hold\n' "$((checks - fails))"
exit "$fails"
