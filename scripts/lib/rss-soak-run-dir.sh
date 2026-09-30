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
