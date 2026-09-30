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
MIN_CHECKS=269
# MIN_CHECKS is a COUNT and a count is not an identity: deleting a case and
# padding the same number of dummy `ok` calls elsewhere restored the floor while
# the behaviour that case existed to pin — e.g. the constant column — went
# untested. Two more things therefore pin each scenario, both in `end_case`:
# its marker is written AFTER its assertions, so a case that returns early or
# crashes before them is missing from the marker list; and its check count is
# compared with the number it performed, so deleting three assertions and
# padding three `ok` calls anywhere else in the suite reds that case. The total
# still has to clear the floor, which is what catches a case deleted outright.

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
# A scenario's marker is written by `end_case`, i.e. AFTER its last assertion.
# Emitting it at the top (what this suite used to do) meant a case that lost its
# assertions, or returned early before them, still announced itself as run: the
# marker is the identity of the scenario, so it has to be reached by walking the
# assertions, not by arriving at the comment above them.
#
# `end_case <count>` additionally pins how many checks that scenario performed.
# MIN_CHECKS only bounds the total, so deleting three assertions and padding
# three dummy `ok` calls kept the floor green; the per-case delta does not.
case_start() { # <name>
    case_name="$1"
    case_checks=$checks
}
end_case() { # <expected-count>
    local expected="${1:-}" got=$((checks - case_checks))
    if [ -z "$case_name" ]; then
        bad 'end_case without case_start (fixture bug)'
    elif [ -n "$expected" ] && [ "$got" -ne "$expected" ]; then
        bad "scenario $case_name ran $got check(s), expected $expected (a case lost or padded its assertions)"
    fi
    mark "$case_name"
    case_name=""
}
case_name=""
case_checks=0
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
case_start run-dir-guard

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

end_case 13
# ------------------------------------------------------ window / tolerance
hdr 'window and tolerance validators'
case_start window-tolerance

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

end_case 12
# -------------------------------------------------------------- lock policy
# The lock is taken before the builds, so these run in well under a second and
# never touch cargo. An EMPTY lock must be treated as held: the winner creates
# the file and writes its pid in two steps, and stealing the lock in between
# starts a second soak on the same ports.
hdr 'lock policy'
case_start lock-policy

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

end_case 5
# ---------------------------------------------- meta writer (JSON escaping)
# The `meta` record is JSON Lines and interpolates operator-supplied strings.
# A `"` or `\` in the run dir (or a binary path, or the host name) used to make
# the line unparseable, and the reader SILENTLY SKIPS an unparseable line: the
# artifact lost run_dir, harness_sha256, bin_sha256, the ports and the recipe,
# the identical-binaries guard never ran, and the run still printed
# "run completed". These checks push such a string through the REAL writer
# (rss_soak_write_meta) and parse the line back.
hdr 'meta writer (JSON escaping)'
case_start meta-writer

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

end_case 5
# -------------------------------------------- meta writer (locale independence)
# round 5: the escaper was LOCALE-DEPENDENT. `[[:cntrl:]]` and `${s:0:1}` are
# byte-oriented only in the C locale; under any UTF-8 locale bash 3.2 matched the
# Unicode Cc/Cf categories too, so U+200B took the `\u` branch and
# `printf "'$ch"` sign-extended its first byte into `\uffffffffffffffe2` — valid
# JSON, silently wrong value. These teeth sweep the code points through the REAL
# function and round-trip a REAL artifact whose run dir contains U+200B, U+00AD
# and a combining mark, under a UTF-8 locale and under C.
hdr 'meta writer (locale independence)'
case_start meta-escaper-locale

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

end_case 5
# ------------------------------------------------------- summary reader (real)
hdr 'summary reader'
case_start summary-reader

# Does the reader under test take the optional <summary-out> (round 7) or does it
# still append its own closing record (round 6)? This suite is also run against
# the round-6 head to show each round-7 tooth red, so it must not depend on the
# round-7 call convention to reach an assertion.
reader_producer_mode=0
if grep -q 'in (7, 8)' "$SUMMARY"; then reader_producer_mode=1; fi

summary() { # <artifact> <aborted> <rs-churn> <go-churn> <rs-steady> <go-steady>
    # Producer/close-out mode: the reader is READ-ONLY, so it writes its closing
    # record to a file this caller owns and this helper appends it with the real
    # library helper (the one scripts/rss-soak.sh uses), separator included.
    #
    # The round-7 reader grew that optional <summary-out> argument; the round-6
    # reader took exactly six and appended its own record. Both shapes are
    # supported here on purpose: it is what lets every round-7 tooth be run
    # against the round-6 head (this fixture file copied in alone) and shown red,
    # rather than failing trivially on a usage error.
    local artifact="$1" tmp rc
    tmp="$artifact.summary.$$"
    if [ "$reader_producer_mode" = 1 ]; then
        python3 "$SUMMARY" "$@" "$tmp" > "$artifact.stdout" 2>&1
        rc=$?
        rss_soak_append_summary "$artifact" "$tmp" || :
    else
        python3 "$SUMMARY" "$@" > "$artifact.stdout" 2>&1
        rc=$?
    fi
    rm -f -- "$tmp"
    return "$rc"
}

reverify() { # <artifact> <rs-churn> <go-churn> <rs-steady> <go-steady>
    # Verify mode: no <summary-out>, so the reader must not write a byte. Against
    # the round-6 reader (which always appends) this is the same six-argument
    # call, and the byte-identity check is exactly what catches it.
    local artifact="$1"
    shift
    python3 "$SUMMARY" "$artifact" "" "$@" > "$artifact.verify.stdout" 2>&1
}

artifact() { # <path> <run_dir> <mode: rising|nulls|const|huge|falling|single|big2g> [extra-meta-json]
    local path="$1" dir="$2" mode="$3" extra="${4:-}" i kb
    printf '{"kind":"meta","duration_s":180,"interval_s":45,"run_dir":"%s","frp_rs_sha":"deadbeef"%s}\n' \
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
        '2026-01-01T00:00:00Z' 180 45 180 'host' darwin 8 "0.71.0" deadbeef false \
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

end_case 6
# 1. A run whose generators died early: the rows on disk predate the run, and
#    the soak clears them before the window opens. The summary must then abort
#    and must not publish the earlier run's numbers.
case_start summary-case-01
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

end_case 5
# 2. No RSS readings at all (a stubbed `ps`): abort, and never print a reading
#    that was not measured.
case_start summary-case-02
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

end_case 5
# 3. A run with readings and symmetric traffic completes, and its summary carries
#    the computed trend rather than relying on an eyeball.
case_start summary-case-03
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

end_case 5
# 4. One side was handed half the work: not head-to-head, so abort.
case_start summary-case-04
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

end_case 2
# 5. A steady path that lost a stream: the run is torn, so abort.
case_start summary-case-05
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

end_case 2
# 6. `ps` printing a constant: every reading is well-formed, but a whole column
#    that never moves is the shape of an UNMEASURED line, not of a stable
#    process. This is the "perfectly flat" artifact a stubbed `ps` produced.
case_start summary-case-06
const="$work/const"
const_abs=$(rss_soak_prepare_run_dir "$const" "$const/out.jsonl")
artifact "$const/out.jsonl" "$const_abs" const
traffic_rows "$const" 600 2000000
summary "$const/out.jsonl" "" "$const/rs-churn.json" "$const/go-churn.json" \
    "$const/rs-steady.json" "$const/go-steady.json"
expect_rc 3 "$?" 'a column that never moves -> abort'
expect_grep 'identical RSS' "$const/out.jsonl" 'the constant column is named'
expect_no_grep 'run completed' "$const/out.jsonl.stdout" 'a constant column is not completed'

end_case 3
# 7. Well-formed but implausible magnitudes (a hand-made artifact, or `ps`
#    returning nonsense): refused by the reader even though the generator would
#    never have written them.
case_start summary-case-07
huge="$work/huge"
huge_abs=$(rss_soak_prepare_run_dir "$huge" "$huge/out.jsonl")
artifact "$huge/out.jsonl" "$huge_abs" huge
traffic_rows "$huge" 600 2000000
summary "$huge/out.jsonl" "" "$huge/rs-churn.json" "$huge/go-churn.json" \
    "$huge/rs-steady.json" "$huge/go-steady.json"
expect_rc 3 "$?" 'an implausible RSS magnitude -> abort'
expect_grep 'implausible RSS reading' "$huge/out.jsonl" 'the implausible readings are named'

end_case 2
# 8. A `nan` tolerance used to slip past float() and disable the achieved-load
#    reconciliation while the run still reported "run completed".
case_start summary-case-08
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
expect_grep 'not a finite number in (0, 1)' "$nan/out.jsonl" 'the nan tolerance is named'
expect_no_grep 'NaN' "$nan/out.jsonl" 'NaN is never recorded as a tolerance'

end_case 3
# 9. The same binary on both sides is not a comparison. The soak refuses this
#    before the window opens; a hand-edited artifact must not present it either.
case_start summary-case-09
same="$work/same"
same_abs=$(rss_soak_prepare_run_dir "$same" "$same/out.jsonl")
artifact "$same/out.jsonl" "$same_abs" rising \
    ',"bin_sha256":{"rs_frps":"aaa","go_frps":"aaa","rs_frpc":"bbb","go_frpc":"ccc"}'
traffic_rows "$same" 600 2000000
summary "$same/out.jsonl" "" "$same/rs-churn.json" "$same/go-churn.json" \
    "$same/rs-steady.json" "$same/go-steady.json"
expect_rc 3 "$?" 'identical frp-rs and Go binaries -> abort'
expect_grep 'same binary' "$same/out.jsonl" 'the shared binary is named'

end_case 2
# 10. A run that moved almost nothing did measure something, but not enough to
#     support any comparison: refused by an absolute floor.
case_start summary-case-10
tiny="$work/tiny"
tiny_abs=$(rss_soak_prepare_run_dir "$tiny" "$tiny/out.jsonl")
artifact "$tiny/out.jsonl" "$tiny_abs" rising
traffic_rows "$tiny" 1 1
summary "$tiny/out.jsonl" "" "$tiny/rs-churn.json" "$tiny/go-churn.json" \
    "$tiny/rs-steady.json" "$tiny/go-steady.json"
expect_rc 3 "$?" 'degenerate achieved totals -> abort'
expect_grep 'only 1 round trips' "$tiny/out.jsonl" 'the churn floor is named'
expect_grep 'moved only 1 bytes' "$tiny/out.jsonl" 'the steady floor is named'

end_case 3
# 11. A DECREASING series must produce a negative slope. A sign error in the
#     trend computation otherwise leaves every "no growth" statement intact.
case_start summary-case-11
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

end_case 2
# 12. Exactly one reading per column is not a series: a single point cannot show
#     that anything is stable. Columns with fewer than two readings used to be
#     skipped, so this artifact printed "run completed".
case_start summary-case-12
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

end_case 4
# 13. The artifact's OWN recorded ceiling wins over the reader's environment.
#     This series was produced under a 40000 KB ceiling and its readings sit
#     under it, so a reader whose SOAK_RSS_CEILING_KB is a hostile 1 KB must
#     still accept it. Before the fix the ceiling came from the env alone, so the
#     SAME artifact read "run completed" here and rc 3 "implausible" there.
case_start summary-case-13
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

end_case 3
# 14. ... and the ambient env cannot RAISE it either: this artifact records a
#     10000 KB ceiling while its readings are ~12-32 MB, so it must abort even
#     though the reader's default ceiling (1 GiB) would have accepted them.
case_start summary-case-14
lowceil="$work/lowceil"
lowceil_abs=$(rss_soak_prepare_run_dir "$lowceil" "$lowceil/out.jsonl")
artifact "$lowceil/out.jsonl" "$lowceil_abs" rising ',"rss_ceiling_kb":10000'
traffic_rows "$lowceil" 600 2000000
unset SOAK_RSS_CEILING_KB
summary "$lowceil/out.jsonl" "" "$lowceil/rs-churn.json" "$lowceil/go-churn.json" \
    "$lowceil/rs-steady.json" "$lowceil/go-steady.json"
expect_rc 3 "$?" 'an artifact ceiling below its own readings -> abort'
expect_grep 'outside 1..10000 KB' "$lowceil/out.jsonl" 'the artifact ceiling is the one applied'

end_case 2
# 15. The verdict is monotonic. The reader APPENDS a summary, so re-running it
#     over an artifact that already aborted used to append "run completed"
#     behind the death verdict once the traffic rows were healthy (or trimmed):
#     a consumer that takes the last summary was misled.
case_start summary-case-15
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

end_case 6
# 16. The reader's FALLBACK default (for an artifact that records no ceiling of
#     its own — an older or hand-written series) is 1 GiB, not the old 100 GiB.
#     These ~1.9 GiB readings must be refused; under the old default they were
#     accepted and published as a completed run.
case_start summary-case-16
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

end_case 3
# 17. round 5: the traffic tolerance, like the ceiling, is recorded in the
#     artifact and preferred over the reader's environment. Before this, two
#     BYTE-IDENTICAL artifacts got opposite verdicts from SOAK_TRAFFIC_TOLERANCE
#     alone: the default env read rc 3 ("differs by 50.0%"), an ambient 0.6 read
#     rc 0 ("run completed"). An artifact that records nothing must still behave
#     exactly as before (env, then 0.10).
case_start summary-case-17

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
# JSON `null` is a RECORDED value: the key is present, so it must be usable and
# the run must abort. Treating null as "recorded nothing" let the ambient
# environment flip two byte-identical artifacts (a 5% spread read rc 0 with the
# env unset and rc 3 with SOAK_TRAFFIC_TOLERANCE=0.01).
tolerance_case "$work/tol-null-a"  null      -   3 'a recorded null tolerance is present-but-unusable'
tolerance_case "$work/tol-null-b"  null      0.6 3 'a recorded null tolerance is not environment-flipped'
tolerance_case "$work/tol-true-a"  true      -   3 'a recorded boolean tolerance is present-but-unusable'
tolerance_case "$work/tol-true-b"  true      0.6 3 'a recorded boolean tolerance is not environment-flipped'
# Above the writer's open (0, 1) contract. Any finite value > 0 used to be
# accepted, so a recorded 100 let a 90% spread read "run completed".
tolerance_case "$work/tol-100-a"   100       -   3 'a recorded tolerance above 1 aborts'
tolerance_case "$work/tol-100-b"   100       0.6 3 'a recorded tolerance above 1 is not environment-flipped'
tolerance_case "$work/tol-1e9"     1e9       -   3 'a recorded tolerance of 1e9 aborts'
tolerance_case "$work/tol-zero"    0         -   3 'a recorded tolerance of 0 aborts'

expect_grep '"traffic_tolerance": 0.6' "$work/tol-rec06-a/out.jsonl" 'the summary records the artifact tolerance'
expect_grep '"traffic_tolerance_source": "artifact meta"' "$work/tol-rec06-a/out.jsonl" 'the summary names the artifact as the tolerance source'
expect_grep 'traffic tolerance: 0.6 (from artifact meta)' "$work/tol-rec06-a/out.jsonl.stdout" 'the printed table names the artifact as the tolerance source'
expect_grep 'traffic tolerance: 0.1 (from default)' "$work/tol-none-a/out.jsonl.stdout" 'the printed table names the default when the artifact records none'
expect_grep 'traffic tolerance: 0.6 (from environment)' "$work/tol-none-c/out.jsonl.stdout" 'the printed table names the environment when the artifact records none'
expect_grep 'records an unusable traffic tolerance' "$work/tol-bogus-a/out.jsonl" 'an unusable recorded tolerance is named'
expect_grep 'records an unusable traffic tolerance' "$work/tol-null-a/out.jsonl" 'a recorded null is named as the unusable tolerance, not merely aborted for the spread'
expect_grep 'a finite number in (0, 1)' "$work/tol-100-a/out.jsonl" 'the usable range is named for a too-large tolerance'
expect_grep 'traffic tolerance: 0.1 (from artifact meta, unusable)' "$work/tol-null-b/out.jsonl.stdout" \
    'the printed table reports the unusable recorded tolerance, not the environment'
expect_no_grep 'from environment' "$work/tol-null-b/out.jsonl.stdout" 'a recorded null does not fall back to the environment'
expect_no_grep 'Traceback' "$work/tol-huge/out.stdout" 'a giant recorded tolerance is refused, not a traceback'
expect_no_grep 'Traceback' "$work/tol-100-a/out.jsonl.stdout" 'a too-large recorded tolerance is refused, not a traceback'

end_case 32
# 18. round 5: a non-UTF-8 artifact is an UNUSABLE artifact — refused loudly with
#     the artifact name and the byte offset, not a bare traceback and not a
#     silent U+FFFD substitution (the writer stays byte-preserving by design).
case_start summary-case-18
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

end_case 5
# 19. round 6: a summary appended to an artifact whose last line has no trailing
#     newline must not be glued to it. A soak killed mid-`printf` leaves such a
#     line; gluing makes BOTH lines unparseable, so the aborted summary the
#     monotonic rule depends on becomes invisible and the re-read prints
#     "run completed" over a real abort.
case_start summary-case-19
unterm="$work/unterminated"
mkdir -p -- "$unterm"
unterm_abs=$(rss_soak_prepare_run_dir "$unterm" "$unterm/out.jsonl")
artifact "$unterm/out.jsonl" "$unterm_abs" rising ""
traffic_rows "$unterm" 600 2000000
printf '%s' '{"kind":"summary","aborted":"previous run died without a newline","samples":1}' >> "$unterm/out.jsonl"
if [ "$(tail -c 1 -- "$unterm/out.jsonl" | od -An -tx1 | tr -d ' \n')" = "7d" ]; then
    ok 'the fixture artifact really ends without a newline'
else
    bad 'the fixture artifact already ends with a newline (fixture bug)'
fi
summary "$unterm/out.jsonl" "" "$unterm/rs-churn.json" "$unterm/go-churn.json" \
    "$unterm/rs-steady.json" "$unterm/go-steady.json"
expect_rc 3 "$?" 'an unterminated prior summary still aborts the re-read'
expect_grep 'a previous summary already aborted this artifact' "$unterm/out.jsonl.stdout" \
    'the re-read sees the abort verdict the separator keeps visible'
if python3 -c '
import json, sys
lines = [l for l in open(sys.argv[1], "rb").read().decode("utf-8").split("\n") if l.strip()]
assert len(lines) >= 8, [len(lines), lines[-1][:60]]
rows = [json.loads(l) for l in lines]
assert rows[-1]["kind"] == "summary" and rows[-1]["aborted"], rows[-1]
' "$unterm/out.jsonl"; then
    ok 'the appended summary is its own parseable line (one JSON object per line)'
else
    bad 'the appended summary is not a parseable line of its own'
fi

end_case 4
# 20. round 6: a line that is VALID JSON but not an object used to kill the
#     reader with an AttributeError traceback (rc 1). It is a corrupt artifact and
#     must take the documented rc 2 path, naming the artifact, the line and the
#     JSON type.
case_start summary-case-20
for spec in 'null:null' '123:number' '"x":string' '[1,2]:array'; do
    line="${spec%%:*}"; word="${spec##*:}"
    nd="$work/nondict-${word}"
    mkdir -p -- "$nd"
    printf '{"kind":"meta","run_dir":"/tmp/x"}\n%s\n' "$line" > "$nd/out.jsonl"
    python3 "$SUMMARY" "$nd/out.jsonl" "" "$nd/a" "$nd/b" "$nd/c" "$nd/d" > "$nd/out.stdout" 2>&1
    expect_rc 2 "$?" "a JSON $word line is an unusable artifact (rc 2)"
    expect_grep "line 2 is a JSON $word, not an object" "$nd/out.stdout" "the $word line and its number are named"
    expect_no_grep 'Traceback' "$nd/out.stdout" "a JSON $word line is not a traceback"
done

end_case 12
# 21. round 7 (B1/G1): a tolerance of exactly 1 can never fail — the spread is
#     |a - b| / max(a, b) in [0, 1) for positive counts — so accepting it
#     silently switched the achieved-load reconciliation OFF: a 50% churn gap
#     read "run completed" with `traffic tolerance: 1`. The usable interval is
#     now the OPEN (0, 1), in the writer validator and in every reader path.
case_start summary-case-21
rss_soak_validate_tolerance 1     && bad 'the writer accepts a tolerance of 1' \
                                  || ok 'the writer refuses a tolerance of 1'
rss_soak_validate_tolerance 1.0   && bad 'the writer accepts a tolerance of 1.0' \
                                  || ok 'the writer refuses a tolerance of 1.0'
rss_soak_validate_tolerance 1e0   && bad 'the writer accepts a tolerance of 1e0' \
                                  || ok 'the writer refuses a tolerance of 1e0'
rss_soak_validate_tolerance 0.999 && ok 'the writer accepts a tolerance just under 1' \
                                  || bad 'the writer refuses 0.999'
rss_soak_validate_tolerance 0.10  && ok 'the writer still accepts the 0.10 default' \
                                  || bad 'the writer refuses 0.10'
tolerance_case "$work/tol-one-a" 1.0  -   3 'an artifact recording 1.0 aborts instead of disabling the check'
tolerance_case "$work/tol-one-b" 1.0  0.6 3 'a recorded 1.0 is not rescued by an ambient 0.6'
tolerance_case "$work/tol-one-c" 1e0  -   3 'an artifact recording 1e0 aborts'
expect_grep 'records an unusable traffic tolerance' "$work/tol-one-a/out.jsonl" 'a recorded 1.0 is named as the unusable tolerance'
expect_grep 'a finite number in (0, 1)' "$work/tol-one-a/out.jsonl" 'the open interval is named for a recorded 1.0'
expect_no_grep 'run completed' "$work/tol-one-a/out.jsonl.stdout" 'a recorded 1.0 does not read as completed'
# The env/fallback path has the same open interval: with no recorded key the
# reader used to accept an ambient SOAK_TRAFFIC_TOLERANCE=1 and switch the
# reconciliation off, which is the whole finding moved into the environment.
tolerance_case "$work/tol-env-one-a" - 1   3 'an ambient tolerance of 1 is refused when the artifact records none'
tolerance_case "$work/tol-env-one-b" - 1.0 3 'an ambient tolerance of 1.0 is refused when the artifact records none'
tolerance_case "$work/tol-env-one-c" - 1e0 3 'an ambient tolerance of 1e0 is refused when the artifact records none'

end_case 14
# 22. round 7 (B2/G5/G6): the reader must be READ-ONLY and fail closed. It used
#     to append its own summary, so re-reading the artifact of a run killed
#     before it closed out (samples, no closing record) wrote `"aborted": null`
#     and printed "run completed" over a series that never closed out.
case_start summary-case-22
tear="$work/tear"
mkdir -p -- "$tear"
tear_abs=$(rss_soak_prepare_run_dir "$tear" "$tear/out.jsonl")
artifact "$tear/out.jsonl" "$tear_abs" rising
traffic_rows "$tear" 600 2000000
tear_before=$(shasum -a 256 -- "$tear/out.jsonl")
reverify "$tear/out.jsonl" "$tear/rs-churn.json" "$tear/go-churn.json" "$tear/rs-steady.json" "$tear/go-steady.json"
expect_rc 3 "$?" 'a re-read of an artifact with no closing summary aborts'
expect_grep 'no closing summary record' "$tear/out.jsonl.verify.stdout" 'the missing close-out is named'
expect_no_grep 'run completed' "$tear/out.jsonl.verify.stdout" 'an unclosed series is never completed'
if [ "$tear_before" = "$(shasum -a 256 -- "$tear/out.jsonl")" ]; then
    ok 'verify mode left the artifact byte-identical'
else
    bad 'the reader wrote into the artifact'
fi
if grep -Eq '"kind":[[:space:]]*"summary"' "$tear/out.jsonl"; then
    bad 'the reader appended a summary record of its own'
else
    ok 'the reader appended nothing'
fi
# A closing record cut off mid-write means the same thing — the run did not close
# out — and the reader must not repair it. The truncation uses the REAL writer's
# own bytes ($good closed out above, through the real append helper):
# json.dumps(sort_keys=True) starts the line with "aborted", so a test that only
# looks for a leading {"kind":"summary" misses every record this harness writes.
truncate_real() { # <dir> <before|after>
    local dir="$1" spec="$2" abs
    mkdir -p -- "$dir"
    abs=$(rss_soak_prepare_run_dir "$dir" "$dir/out.jsonl")
    artifact "$dir/out.jsonl" "$abs" rising
    traffic_rows "$dir" 600 2000000
    python3 - "$good/out.jsonl" "$dir/out.jsonl" "$spec" <<'PYEOF'
import sys
src, dst, spec = sys.argv[1], sys.argv[2], sys.argv[3]
rec = [l for l in open(src, encoding="utf-8").read().split("\n") if l.strip()][-1]
marker = '"kind": "summary"'
i = rec.find(marker)
if i < 0:
    i = len(rec) // 2
tail = rec[:i - 4] if spec == "before" else rec[:i + len(marker) + 5]
lines = [l for l in open(dst, encoding="utf-8").read().split("\n") if l.strip()]
lines.append(tail)
open(dst, "w", encoding="utf-8").write("\n".join(lines) + "\n")
PYEOF
    reverify "$dir/out.jsonl" "$dir/rs-churn.json" "$dir/go-churn.json" \
        "$dir/rs-steady.json" "$dir/go-steady.json"
    expect_rc 3 "$?" "the $spec truncation of the closing record aborts the re-read"
    expect_grep 'did not close out' "$dir/out.jsonl.verify.stdout" "the $spec truncation is named as an unclosed series"
    expect_no_grep 'run completed' "$dir/out.jsonl.verify.stdout" "a $spec truncation is not completed"
}
truncate_real "$work/trunc-before" before
truncate_real "$work/trunc-after" after
# The legacy hand-written fragment shape, still recognised.
trunc="$work/trunc-hand"
mkdir -p -- "$trunc"
trunc_abs=$(rss_soak_prepare_run_dir "$trunc" "$trunc/out.jsonl")
artifact "$trunc/out.jsonl" "$trunc_abs" rising
traffic_rows "$trunc" 600 2000000
printf '%s' '{"kind":"summary","aborted":null,"samp' >> "$trunc/out.jsonl"
reverify "$trunc/out.jsonl" "$trunc/rs-churn.json" "$trunc/go-churn.json" \
    "$trunc/rs-steady.json" "$trunc/go-steady.json"
expect_rc 3 "$?" 'a hand-written truncated closing record aborts the re-read'
expect_grep 'did not close out' "$trunc/out.jsonl.verify.stdout" 'the hand-written truncation is named as an unclosed series'
expect_no_grep 'run completed' "$trunc/out.jsonl.verify.stdout" 'a hand-written truncation is not completed'
# ... and a healthy artifact that DOES close out still verifies clean.
good="$work/good"
reverify "$good/out.jsonl" "$good/rs-churn.json" "$good/go-churn.json" "$good/rs-steady.json" "$good/go-steady.json"
expect_rc 0 "$?" 'a closed-out healthy artifact verifies read-only'
expect_no_grep 'no closing summary record' "$good/out.jsonl.verify.stdout" 'the close-out satisfies verify mode'

end_case 16
# 23. round 7 (B3/G7): `duration_s` was never read, so a hand-written
#     `"duration_s": 10800` beside two samples at 0 s and 45 s read "run
#     completed": every per-column check passed because each column had two
#     distinct readings. The recorded window and interval are now checked
#     against the samples on disk, and a missing/unusable pair is itself fatal.
case_start summary-case-23
cov="$work/cov"
mkdir -p -- "$cov"
cov_abs=$(rss_soak_prepare_run_dir "$cov" "$cov/out.jsonl")
printf '{"kind":"meta","duration_s":10800,"interval_s":45,"run_dir":"%s"}\n' "$cov_abs" > "$cov/out.jsonl"
for i in 0 45; do
    printf '{"kind":"sample","elapsed_s":%d,"load1":3.1,"time_wait":400,"frp_rs_frps_kb":%d,"frp_rs_frpc_kb":%d,"go_frps_kb":%d,"go_frpc_kb":%d}\n' \
        "$i" $((12000 + i * 10)) $((12010 + i * 10)) $((32000 + i * 10)) $((24000 + i * 10)) >> "$cov/out.jsonl"
done
traffic_rows "$cov" 600 2000000
summary "$cov/out.jsonl" "" "$cov/rs-churn.json" "$cov/go-churn.json" "$cov/rs-steady.json" "$cov/go-steady.json"
expect_rc 3 "$?" 'a recorded 10800 s window with 45 s of samples aborts'
expect_grep 'cover 45s of a recorded 10800s window' "$cov/out.jsonl" 'both the coverage and the window are named'
hol="$work/hole"
mkdir -p -- "$hol"
hol_abs=$(rss_soak_prepare_run_dir "$hol" "$hol/out.jsonl")
printf '{"kind":"meta","duration_s":180,"interval_s":45,"run_dir":"%s"}\n' "$hol_abs" > "$hol/out.jsonl"
for i in 0 45 180; do
    printf '{"kind":"sample","elapsed_s":%d,"load1":3.1,"time_wait":400,"frp_rs_frps_kb":%d,"frp_rs_frpc_kb":%d,"go_frps_kb":%d,"go_frpc_kb":%d}\n' \
        "$i" $((12000 + i * 10)) $((12010 + i * 10)) $((32000 + i * 10)) $((24000 + i * 10)) >> "$hol/out.jsonl"
done
traffic_rows "$hol" 600 2000000
summary "$hol/out.jsonl" "" "$hol/rs-churn.json" "$hol/go-churn.json" "$hol/rs-steady.json" "$hol/go-steady.json"
expect_rc 3 "$?" 'a hole in the sample spacing aborts'
expect_grep 'spaced at the recorded interval_s' "$hol/out.jsonl" 'the spacing rule is named'
nod="$work/nodur"
mkdir -p -- "$nod"
nod_abs=$(rss_soak_prepare_run_dir "$nod" "$nod/out.jsonl")
printf '{"kind":"meta","interval_s":45,"run_dir":"%s"}\n' "$nod_abs" > "$nod/out.jsonl"
for i in 0 45 90 135 180; do
    printf '{"kind":"sample","elapsed_s":%d,"load1":3.1,"time_wait":400,"frp_rs_frps_kb":%d,"frp_rs_frpc_kb":%d,"go_frps_kb":%d,"go_frpc_kb":%d}\n' \
        "$i" $((12000 + i * 10)) $((12010 + i * 10)) $((32000 + i * 10)) $((24000 + i * 10)) >> "$nod/out.jsonl"
done
traffic_rows "$nod" 600 2000000
summary "$nod/out.jsonl" "" "$nod/rs-churn.json" "$nod/go-churn.json" "$nod/rs-steady.json" "$nod/go-steady.json"
expect_rc 3 "$?" 'a missing duration_s aborts (the coverage bound cannot be verified)'
expect_grep 'does not record a usable duration_s' "$nod/out.jsonl" 'the missing bound is named'

end_case 6
# 24. round 7 (B4/G4): a wrong-typed field used to kill the reader with a
#     traceback (rc 1) where the documented contract is rc 2 "the artifact
#     itself is unusable". Each field is named together with its line.
case_start summary-case-24
type_case() { # <name> <patch-python> <field>
    local name="$1" patch="$2" field="$3"
    local dir="$work/type-$name" abs
    mkdir -p -- "$dir"
    abs=$(rss_soak_prepare_run_dir "$dir" "$dir/out.jsonl")
    artifact "$dir/out.jsonl" "$abs" rising
    python3 -c "$patch" "$dir/out.jsonl"
    traffic_rows "$dir" 600 2000000
    reverify "$dir/out.jsonl" "$dir/rs-churn.json" "$dir/go-churn.json" "$dir/rs-steady.json" "$dir/go-steady.json"
    expect_rc 2 "$?" "$name: a wrong-typed $field is an unusable artifact (rc 2)"
    expect_grep "field '$field'" "$dir/out.jsonl.verify.stdout" "$name: the $field field is named"
    expect_no_grep 'Traceback' "$dir/out.jsonl.verify.stdout" "$name: no bare traceback for $field"
}
type_case load1 'import json,sys
p=sys.argv[1]; rows=[l for l in open(p).read().split("\n") if l.strip()]
r=json.loads(rows[1]); r["load1"]="3.1"; rows[1]=json.dumps(r)
open(p,"w").write("\n".join(rows)+"\n")' load1
type_case timewait 'import json,sys
p=sys.argv[1]; rows=[l for l in open(p).read().split("\n") if l.strip()]
r=json.loads(rows[1]); r["time_wait"]={"a":1}; rows[1]=json.dumps(r)
open(p,"w").write("\n".join(rows)+"\n")' time_wait
type_case interval 'import json,sys
p=sys.argv[1]; rows=[l for l in open(p).read().split("\n") if l.strip()]
r=json.loads(rows[0]); r["interval_s"]="abc"; rows[0]=json.dumps(r)
open(p,"w").write("\n".join(rows)+"\n")' interval_s
type_case binsha 'import json,sys
p=sys.argv[1]; rows=[l for l in open(p).read().split("\n") if l.strip()]
r=json.loads(rows[0]); r["bin_sha256"]="x"; rows[0]=json.dumps(r)
open(p,"w").write("\n".join(rows)+"\n")' bin_sha256
traffic_type_case() { # <name> <json-row> <field>
    local name="$1" row="$2" field="$3"
    local dir="$work/type-$name" abs
    mkdir -p -- "$dir"
    abs=$(rss_soak_prepare_run_dir "$dir" "$dir/out.jsonl")
    artifact "$dir/out.jsonl" "$abs" rising
    traffic_rows "$dir" 600 2000000
    printf '%s\n' "$row" > "$dir/rs-churn.json"
    reverify "$dir/out.jsonl" "$dir/rs-churn.json" "$dir/go-churn.json" "$dir/rs-steady.json" "$dir/go-steady.json"
    expect_rc 2 "$?" "$name: a wrong-typed traffic $field is an unusable artifact (rc 2)"
    expect_grep "field '$field'" "$dir/out.jsonl.verify.stdout" "$name: the traffic $field field is named"
    expect_no_grep 'Traceback' "$dir/out.jsonl.verify.stdout" "$name: no bare traceback for traffic $field"
}
traffic_type_case churn-trips '{"connections":40,"round_trips":"600","bytes":2000000,"total_bytes":2000000,"mbps":1.0,"failed_streams":0}' round_trips
traffic_type_case steady-bytes '{"connections":3,"bytes":2000000,"total_bytes":[1],"mbps":1.0,"failed_streams":0}' total_bytes

end_case 18
# 25. round 7 (G2): the ceiling's precedence is by KEY PRESENCE, not truthiness.
#     A recorded-but-unusable ceiling (`null`, `true`, `"0.6"`, `[]`, `{}`, 0, -1)
#     used to fall through to the ambient SOAK_RSS_CEILING_KB, so one byte-identical
#     artifact read rc 3 under the default and "run completed" under
#     SOAK_RSS_CEILING_KB=3000000. Only an artifact that records NO ceiling falls back.
case_start summary-case-25
n=0
for spec in null true '"0.6"' '[]' '{}' 0 -1; do
    n=$((n + 1))
    d="$work/ceil-bogus-$n"
    mkdir -p -- "$d"
    abs=$(rss_soak_prepare_run_dir "$d" "$d/out.jsonl")
    artifact "$d/out.jsonl" "$abs" rising ",\"rss_ceiling_kb\":$spec"
    traffic_rows "$d" 600 2000000
    export SOAK_RSS_CEILING_KB=3000000
    summary "$d/out.jsonl" "" "$d/rs-churn.json" "$d/go-churn.json" "$d/rs-steady.json" "$d/go-steady.json"
    rc=$?
    unset SOAK_RSS_CEILING_KB
    expect_rc 3 "$rc" "a recorded ceiling of $spec aborts instead of falling through to the env"
done
expect_grep 'records an unusable RSS ceiling' "$work/ceil-bogus-1/out.jsonl" 'the unusable recorded ceiling is named'
expect_grep 'from artifact meta, unusable' "$work/ceil-bogus-1/out.jsonl.stdout" 'the printed ceiling source is the recorded-but-unusable one'
expect_no_grep 'from environment' "$work/ceil-bogus-1/out.jsonl.stdout" 'an unusable recorded ceiling never reports the environment as its source'
expect_no_grep 'run completed' "$work/ceil-bogus-1/out.jsonl.stdout" 'a present-but-unusable ceiling is never completed'

end_case 11
# 26. round 7 (G3): one unparseable line used to be skipped with everything on
#     it, so a BOM (or any corrupt meta line) dropped the digests, the ports and
#     the identical-binaries guard and turned a same-binary artifact from rc 3
#     into rc 0 "run completed". An unparseable non-summary line now refuses the
#     whole artifact with rc 2, naming the line and the JSON error.
case_start summary-case-26
bom="$work/bom"
mkdir -p -- "$bom"
bom_abs=$(rss_soak_prepare_run_dir "$bom" "$bom/out.jsonl")
printf '\xef\xbb\xbf{"kind":"meta","duration_s":180,"interval_s":45,"run_dir":"%s","bin_sha256":{"rs_frps":"aaa","go_frps":"aaa","rs_frpc":"bbb","go_frpc":"ccc"}}\n' \
    "$bom_abs" > "$bom/out.jsonl"
for i in 0 45 90 135 180; do
    printf '{"kind":"sample","elapsed_s":%d,"load1":3.1,"time_wait":400,"frp_rs_frps_kb":%d,"frp_rs_frpc_kb":%d,"go_frps_kb":%d,"go_frpc_kb":%d}\n' \
        "$i" $((12000 + i * 10)) $((12010 + i * 10)) $((32000 + i * 10)) $((24000 + i * 10)) >> "$bom/out.jsonl"
done
traffic_rows "$bom" 600 2000000
reverify "$bom/out.jsonl" "$bom/rs-churn.json" "$bom/go-churn.json" "$bom/rs-steady.json" "$bom/go-steady.json"
expect_rc 2 "$?" 'a BOM on the meta line is an unusable artifact (rc 2)'
expect_grep 'line 1 is not valid JSON' "$bom/out.jsonl.verify.stdout" 'the corrupt line number is named'
expect_no_grep 'run completed' "$bom/out.jsonl.verify.stdout" 'a skipped meta line can no longer read as completed'
torn="$work/torn-line"
mkdir -p -- "$torn"
torn_abs=$(rss_soak_prepare_run_dir "$torn" "$torn/out.jsonl")
artifact "$torn/out.jsonl" "$torn_abs" rising
python3 -c 'import sys
p=sys.argv[1]; rows=open(p).read().split("\n")
rows[2]="{\"kind\":\"sample\",\"elapsed_s\":90,"
open(p,"w").write("\n".join(rows))' "$torn/out.jsonl"
traffic_rows "$torn" 600 2000000
reverify "$torn/out.jsonl" "$torn/rs-churn.json" "$torn/go-churn.json" "$torn/rs-steady.json" "$torn/go-steady.json"
expect_rc 2 "$?" 'a torn sample line is an unusable artifact (rc 2)'
expect_grep 'line 3 is not valid JSON' "$torn/out.jsonl.verify.stdout" 'the torn sample line is named'

end_case 5
# 27. round 7 (G8): `json.loads` accepts bare `NaN`/`Infinity`, every comparison
#     against them is False, so a NaN round-trip count defeated the reconciliation
#     and the reader re-emitted bare `NaN` — which is not strict JSON. Both
#     readers now reject the token through `parse_constant`.
case_start summary-case-27
nan="$work/nan-json"
mkdir -p -- "$nan"
nan_abs=$(rss_soak_prepare_run_dir "$nan" "$nan/out.jsonl")
artifact "$nan/out.jsonl" "$nan_abs" rising
printf '{"connections":40,"round_trips":NaN,"bytes":NaN,"total_bytes":NaN,"mbps":NaN,"failed_streams":NaN}\n' > "$nan/rs-churn.json"
printf '{"connections":40,"round_trips":600,"bytes":2000000,"total_bytes":2000000,"mbps":1.0,"failed_streams":0}\n' > "$nan/go-churn.json"
printf '{"connections":3,"bytes":2000000,"total_bytes":2000000,"mbps":1.0,"failed_streams":0}\n' > "$nan/rs-steady.json"
cp -- "$nan/rs-steady.json" "$nan/go-steady.json"
reverify "$nan/out.jsonl" "$nan/rs-churn.json" "$nan/go-churn.json" "$nan/rs-steady.json" "$nan/go-steady.json"
expect_rc 2 "$?" 'a NaN traffic field is an unusable artifact (rc 2)'
expect_grep 'NaN is not a JSON number' "$nan/out.jsonl.verify.stdout" 'NaN is named as a non-JSON number'
expect_no_grep 'Traceback' "$nan/out.jsonl.verify.stdout" 'NaN is refused, not a traceback'
inf="$work/inf-json"
mkdir -p -- "$inf"
inf_abs=$(rss_soak_prepare_run_dir "$inf" "$inf/out.jsonl")
artifact "$inf/out.jsonl" "$inf_abs" rising
traffic_rows "$inf" 600 2000000
printf '{"connections":40,"round_trips":600,"bytes":2000000,"total_bytes":2000000,"mbps":Infinity,"failed_streams":0}\n' > "$inf/rs-churn.json"
reverify "$inf/out.jsonl" "$inf/rs-churn.json" "$inf/go-churn.json" "$inf/rs-steady.json" "$inf/go-steady.json"
expect_rc 2 "$?" 'an Infinity traffic field is an unusable artifact (rc 2)'
expect_grep 'Infinity is not a JSON number' "$inf/out.jsonl.verify.stdout" 'Infinity is named as a non-JSON number'

end_case 5
# ------------------------------------------------- rss reading guard (real fn)
hdr 'rss reading guard'
case_start rss-reading-guard

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

end_case 9
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
require_marker summary-case-19
require_marker summary-case-20
require_marker summary-case-21
require_marker summary-case-22
require_marker summary-case-23
require_marker summary-case-24
require_marker summary-case-25
require_marker summary-case-26
require_marker summary-case-27
require_marker rss-reading-guard

floor_check
printf '\nRESULT: %d fixture check(s) hold\n' "$((checks - fails))"
exit "$fails"
