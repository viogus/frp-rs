#!/usr/bin/env bash
# =============================================================================
# Run-directory guard for the RSS soak
# =============================================================================
#
# Sourced by `scripts/rss-soak.sh`, and — on its own — by the fixture test
# `scripts/tests/rss-soak-run-dir.sh`, which drives these functions against
# synthetic run directories.
#
# Why this file exists as a unit
# ------------------------------
# The soak reads its traffic evidence from four fixed paths under the run
# directory, and a generator only touches its own file when it FINISHES
# (`--json-truncate` truncates at write time, not at start). A generator that
# dies early therefore leaves the PREVIOUS run's row in place, and the summary
# would publish that borrowed row as this run's achieved load: a run can end
# `"aborted": null` / "run completed" while its byte totals came from an earlier
# run in the same run directory — which is the default configuration, since the
# run directory defaults to `/tmp/rss-soak` for every run. Nothing downstream can
# tell the two apart, so the run directory has to be cleared at the one moment it
# is safe: after pre-flight (so a broken bridge is still a pre-flight failure)
# and before the window's first sample, while this run's generators are alive
# and cannot have written anything yet.
#
# The contract
# ------------
#   rss_soak_prepare_run_dir <dir> <out>
#       Refuses a degenerate `<dir>`, `mkdir -p`s the run directory and `out`'s
#       directory, and echoes the resolved ABSOLUTE run directory — the value
#       the soak records in its `meta` record and reuses for every later path.
#   rss_soak_clear_run_artifacts <dir> <out>
#       Removes this run's traffic rows and the artifact — exactly the files a
#       previous run could leave behind for the summary to borrow. Callers MUST
#       call it before the window opens (see above).
#   rss_soak_validate_window <duration_s> <interval_s>
#       Refuses a window the soak loop cannot run (see below); 0 on success.
#   rss_soak_validate_tolerance <value>
#       Refuses a tolerance that would silently disable the achieved-load
#       reconciliation; 0 on success.
#   rss_soak_rss_kb <pid> <ceiling_kb>
#       Prints a process's RSS in KB, or the literal `null` when the `ps` output
#       cannot be a real reading (see below).
#
# Why the argument validators live here as well
# ---------------------------------------------
# They are pure refusals with no side effects, so the fixture can prove them
# without starting a run: a fixture that invoked `scripts/rss-soak.sh` with a
# valid-looking window would start a real soak (a 60 s window at minimum).
# Both refuse a value that would otherwise wedge or silently weaken a run:
#   * `DURATION=abc` makes the loop's `[ "$elapsed" -lt "$DURATION" ]` test error
#     — and a failing test is false — on every iteration, so the window never
#     ends; `INTERVAL=0` spins without sleeping.
#   * `SOAK_TRAFFIC_TOLERANCE=nan` slips past `float()` and makes every
#     `spread > tolerance` comparison false, i.e. it turns the reconciliation
#     off while the summary still records `"aborted": null`.
#
# A degenerate run directory is a hard refusal, never a silent no-op:
#   * `""` puts every artifact beside the repository root as a bare basename;
#   * `/` turns the clear step into a no-op against the filesystem root, and any
#     glob-based clear would then be catastrophic.
# A path that merely RESOLVES to `/` is refused for the same reason.
#
# The caller runs with `set -uo pipefail` and no `set -e`, so every failure here
# is an explicit non-zero return; the caller decides whether to exit.

# rss_soak_prepare_run_dir <dir> <out> -> absolute run dir on stdout.
rss_soak_prepare_run_dir() {
    local dir="${1:-}" out="${2:-}" abs

    case "$dir" in
        ""|/)
            printf 'ERROR: refusing run dir %q: an empty run dir scatters artifacts as bare basenames, and / makes the clear step a no-op against the filesystem root\n' "$dir" >&2
            printf 'ERROR: set SOAK_RUN_DIR to a dedicated scratch directory (default /tmp/rss-soak)\n' >&2
            return 1
            ;;
    esac

    if ! mkdir -p -- "$dir"; then
        printf 'ERROR: cannot create run dir %q\n' "$dir" >&2
        return 1
    fi
    # `pwd -P` so a symlinked scratch directory is recorded as the real one, and
    # so the degenerate check below sees the resolved path.
    abs=$(cd -- "$dir" && pwd -P) || {
        printf 'ERROR: cannot resolve run dir %q\n' "$dir" >&2
        return 1
    }
    if [ "$abs" = "/" ]; then
        printf 'ERROR: refusing run dir %q: it resolves to the filesystem root\n' "$dir" >&2
        return 1
    fi

    if [ -n "$out" ]; then
        local out_dir
        out_dir=$(dirname -- "$out")
        if ! mkdir -p -- "$out_dir"; then
            printf 'ERROR: cannot create artifact directory %q\n' "$out_dir" >&2
            return 1
        fi
    fi

    printf '%s\n' "$abs"
}

# rss_soak_clear_run_artifacts <dir> <out>
# The four traffic rows are named here, not globbed: the point is to remove
# exactly the files the summary reads, and a glob would silently widen if the
# run directory ever held something else.
rss_soak_clear_run_artifacts() {
    local dir="${1:-}" out="${2:-}" f

    case "$dir" in
        ""|/)
            printf 'ERROR: refusing to clear artifacts in run dir %q\n' "$dir" >&2
            return 1
            ;;
    esac

    for f in rs-churn.json go-churn.json rs-steady.json go-steady.json; do
        rm -f -- "$dir/$f" || return 1
    done
    if [ -n "$out" ]; then
        rm -f -- "$out" || return 1
    fi
    return 0
}

# rss_soak_validate_window <duration_s> <interval_s>
# Minimum window is 60 s: below that the series is shorter than a couple of
# sampling intervals and cannot support any statement about growth.
rss_soak_validate_window() {
    local duration="${1:-}" interval="${2:-}"

    if ! [[ "$duration" =~ ^[0-9]+$ ]] || [ "$duration" -lt 60 ]; then
        printf "error: duration_s must be an integer >= 60 (got '%s')\n" "$duration" >&2
        return 1
    fi
    if ! [[ "$interval" =~ ^[0-9]+$ ]] || [ "$interval" -lt 1 ]; then
        printf "error: interval_s must be an integer >= 1 (got '%s')\n" "$interval" >&2
        return 1
    fi
    return 0
}

# rss_soak_validate_tolerance <value>
# The summary uses `spread > tolerance`; `nan` compares false against
# everything, so an unvalidated `nan` disables the check while the run still
# reports `"aborted": null`, and `inf`/a huge value does the same by making every
# spread pass. `awk` is used rather than a bash pattern so the value is parsed as
# the same float Python will parse.
rss_soak_validate_tolerance() {
    local val="${1:-}"

    if ! awk -v v="$val" 'BEGIN { x = v + 0; exit !(x == x && x > 0 && x <= 1) }' </dev/null; then
        printf "error: SOAK_TRAFFIC_TOLERANCE must be a finite number in (0, 1] (got '%s')\n" "$val" >&2
        return 1
    fi
    return 0
}

# rss_soak_json_str <text> -> <text> escaped for use inside a JSON string.
#
# The artifact is JSON Lines and its `meta` record interpolates strings the
# caller supplies: the resolved run directory, the frp-rs/Go binary paths, the
# host name. A `"` or `\` in any of them makes the line unparseable, and an
# unparseable line is silently skipped by the reader
# (scripts/lib/rss-soak-summary.py:90-101) — the artifact then loses run_dir,
# harness_sha256, bin_sha256, the ports and the recipe, and the
# identical-binaries guard never runs, while the soak still prints
# "run completed". Escaping therefore lives here, and every string field of the
# record goes through it (see rss_soak_write_meta), not the call site.
#
# Escapes the two characters that terminate/corrupt a JSON string (`"` and `\`)
# plus every C0 control character (the named short forms, `\u00XX` otherwise):
# a raw byte below 0x20 is not legal inside a JSON string. Bytes >= 0x20,
# including non-ASCII UTF-8, are passed through unchanged, which JSON allows.
rss_soak_json_str() {
    local s="${1-}" out="" ch esc
    while [ -n "$s" ]; do
        ch="${s:0:1}"
        s="${s:1}"
        case "$ch" in
            '"')   out="${out}\\\"" ;;
            '\')   out="${out}\\\\" ;;
            $'\b') out="${out}\\b" ;;
            $'\f') out="${out}\\f" ;;
            $'\n') out="${out}\\n" ;;
            $'\r') out="${out}\\r" ;;
            $'\t') out="${out}\\t" ;;
            *)
                if [[ "$ch" = [[:cntrl:]] ]]; then
                    printf -v esc '\\u%04x' "'$ch"
                    out="${out}${esc}"
                else
                    out="${out}${ch}"
                fi
                ;;
        esac
    done
    printf '%s' "$out"
}

# rss_soak_write_meta <out> <37 values> -> appends the `meta` JSON line to <out>.#
# The one and only meta writer. It used to be a printf inlined in
# scripts/rss-soak.sh, which made the quoting bug (and any test of it)
# unreachable from the fixture; it lives here now so
# scripts/tests/rss-soak-run-dir.sh can push a run dir containing `"` and `\`
# through the REAL writer and parse the line back.
#
# Values, in order (the call site mirrors this list; the arity check below is
# what keeps the two from drifting silently):
#   1 started_utc            2 duration_s             3 interval_s
#   4 generator_duration_s   5 host                   6 platform
#   7 cpu_cores              8 frp_rs_version         9 frp_rs_sha
#  10 frp_rs_dirty          11 harness rss_soak_sh   12 harness run_dir_sh
#  13 harness summary_py    14 harness frp_stress_tree
#  15 rs_bin_source         16 run_dir               17 go_frp_version
#  18 go_frp_dir            19 rs_bin                20 rs_frpc_bin
#  21 churn_connections     22 churn_rate_per_stack  23 churn_msg_bytes
#  24 steady_streams        25 steady_mbps_per_stream
#  26-31 six ports          32-35 the four binary sha256 values
#  36 load1_start           37 rss_ceiling_kb
# Positions 1, 5, 6, 8, 9, 11-20 and 32-35 are STRING fields and are escaped
# with rss_soak_json_str; the rest are numbers/booleans already validated by the
# caller and are emitted raw.
rss_soak_write_meta() {
    if [ "$#" -ne 38 ]; then
        printf 'ERROR: rss_soak_write_meta wants 38 arguments (out path + 37 values), got %s\n' "$#" >&2
        return 1
    fi
    local out="$1"
    shift  # drop the out path so $1..$37 are the values
    printf '{"kind":"meta","started_utc":"%s","duration_s":%s,"interval_s":%s,"generator_duration_s":%s,"host":"%s","platform":"%s","cpu_cores":%s,"frp_rs_version":"%s","frp_rs_sha":"%s","frp_rs_dirty":%s,"harness_sha256":{"rss_soak_sh":"%s","run_dir_sh":"%s","summary_py":"%s","frp_stress_tree":"%s"},"rs_bin_source":"%s","run_dir":"%s","go_frp_version":"%s","go_frp_dir":"%s","rs_bin":"%s","rs_frpc_bin":"%s","traffic":{"churn_connections":%s,"churn_rate_per_stack":%s,"churn_msg_bytes":%s,"steady_streams":%s,"steady_mbps_per_stream":%s,"generator":"frp-stress","proxy_type":"tcp"},"ports":{"rs_control":%s,"rs_remote":%s,"rs_echo":%s,"go_control":%s,"go_remote":%s,"go_echo":%s},"bin_sha256":{"rs_frps":"%s","rs_frpc":"%s","go_frps":"%s","go_frpc":"%s"},"load1_start":%s,"rss_ceiling_kb":%s,"caveats":["RSS is not live heap; it includes allocator retention and page-cache effects","both stacks share this host, so a machine-level effect moves both series","the per-sample time_wait count is host-wide, not per-side","identical offered recipe, not guaranteed identical achieved volume; per-side achieved volume is recorded and compared, and a spread beyond SOAK_TRAFFIC_TOLERANCE aborts the run","one TCP proxy per stack; other proxy types and encryption/compression/mux paths are not exercised"]}\n' \
        "$(rss_soak_json_str "$1")" "$2" "$3" "$4" "$(rss_soak_json_str "$5")" "$(rss_soak_json_str "$6")" "$7" \
        "$(rss_soak_json_str "$8")" "$(rss_soak_json_str "$9")" "${10}" \
        "$(rss_soak_json_str "${11}")" "$(rss_soak_json_str "${12}")" "$(rss_soak_json_str "${13}")" "$(rss_soak_json_str "${14}")" \
        "$(rss_soak_json_str "${15}")" "$(rss_soak_json_str "${16}")" "$(rss_soak_json_str "${17}")" "$(rss_soak_json_str "${18}")" \
        "$(rss_soak_json_str "${19}")" "$(rss_soak_json_str "${20}")" \
        "${21}" "${22}" "${23}" "${24}" "${25}" "${26}" "${27}" "${28}" "${29}" "${30}" "${31}" \
        "$(rss_soak_json_str "${32}")" "$(rss_soak_json_str "${33}")" "$(rss_soak_json_str "${34}")" "$(rss_soak_json_str "${35}")" \
        "${36}" "${37}" >> "$out"
}

# rss_soak_rss_kb <pid> <ceiling_kb> -> KB on stdout, or the literal `null`.
# A reading is published only when it is a positive integer within the ceiling.
# The non-empty check alone was the round-2 fix, and it was not enough: a stubbed
# or misparsing `ps` that prints `0` produced a full table of zeros, and one that
# prints a constant produced exactly the "perfectly flat, unmeasured" series this
# artifact is supposed to test for. Anything that is not a plausible process RSS
# is reported as a MISSING reading, which the summary then aborts on if it leaves
# a column empty.
#   * empty output, a sign, a decimal point or any non-digit -> `null`;
#   * more than 12 digits -> `null` (bounds the arithmetic below);
#   * 0 or a negative value -> `null` (a process has resident memory);
#   * above <ceiling_kb> -> `null` (default 1 GiB; no plausible bridge here).
# A genuinely implausible constant reading still passes HERE — only a whole
# column of identical readings is implausible, and that is checked by the
# summary reader, which sees the series. The ceiling is a plausibility BOUND,
# not a heuristic oracle: see the default-ceiling rationale in
# scripts/frp-stress/baselines/README.md.
rss_soak_rss_kb() {
    local pid="${1:-}" ceiling="${2:-1048576}" v val

    [ -n "$pid" ] || { printf 'null'; return 0; }
    v=$(ps -o rss= -p "$pid" 2>/dev/null | tr -d ' \t')
    case "$v" in
        ''|*[!0-9]*) printf 'null'; return 0 ;;
    esac
    if [ "${#v}" -gt 12 ]; then printf 'null'; return 0; fi
    val=$(( 10#$v ))
    if [ "$val" -le 0 ] || [ "$val" -gt "$ceiling" ]; then
        printf 'null'
        return 0
    fi
    printf '%s' "$val"
}
