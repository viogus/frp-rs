#!/usr/bin/env bash
# =============================================================================
# A/B throughput gate — does this delta contain anything a measurement can see?
#
#   bash scripts/ab-measurable-delta.sh <before-rev> <after-rev>
#
# Exit codes:
#   0  the delta changes at least one input of the measured numbers → measure.
#      Every such path is printed, one per line, on stdout.
#   1  the delta contains no input the measurement can see (docs/records only)
#      → skip. Nothing is printed.
#   2  usage error, or a revision that cannot be resolved to a commit → the
#      caller must NOT treat this as a skip. Fail closed towards measuring.
#
# The whole point (TODO.md:10913): a red gate on `main` is not evidence of a
# regression when the delta re-measured the same binaries. Run 36996762744
# measured a docs-comment-only delta at +58.8% (`plain`) and -15.6%
# (`encrypt_compress`) in the same run, and the retired PR mode measured
# *identical* binaries at -35.1% / -27.9% / +24.5% across three attempts
# (`.github/workflows/ab-matrix.yml:15-17`). A classifier cannot fix that noise
# floor, but it stops the gate from spending VPS time (and publishing a delta)
# on a delta that provably cannot move the numbers at all.
#
# ---------------------------------------------------------------------------
# Why each class is in the measured set — the set must be a *superset* of the
# gate's inputs, because a missing entry silently skips a real delta:
#
#   *.rs                  every Rust source in the workspace, at any depth
#                         (git's pathspec `*` crosses `/`). The binaries under
#                         measurement are built from these.
#   :(glob)**/Cargo.toml  every crate manifest, at any depth including the
#   :(glob)**/Cargo.lock   workspace root and lockfile. Feature/dependency
#                         changes move codegen without touching a `.rs` file.
#   crates/**             the path scheme named in the Done-when. frp-rs puts
#                         its crates at the workspace root today (`frp-core/`,
#                         `frp-server/`, …), so this matches nothing yet; it is
#                         here so a future `crates/` layout is not a blind spot.
#   rust-toolchain*       `rust-toolchain.toml` pins the exact compiler; a bump
#                         recompiles every binary with a different codegen.
#   .cargo/**             `.cargo/config.toml` carries the release profile the
#                         CI A/B job writes (`lto=false opt-level=2`); a change
#                         there changes the measured codegen directly.
#   scripts/frp-stress/** the load generator. It is built and shipped *once per
#                         side* (ab-matrix.sh's `build_side`), so a change here
#                         changes a measured binary. It is also the only repo
#                         Rust that is not under a crate root — hence its own
#                         entry alongside `*.rs`.
#   scripts/ab-matrix.sh  the harness: it defines the six configs, the metrics
#                         and the median. A change here changes what "the
#                         measurement" even is.
#   scripts/ab-remote.sh  the shipper that runs the harness on the VPS. A
#                         change here changes how the run is executed.
#   .github/workflows/ab-matrix.yml
#                         the gate definition: step gating, env (GATE_PCT),
#                         refs. A change here can make the guard itself change.
#
# The path list is deliberately a superset of the Done-when's example
# (`'*.rs' 'Cargo*.toml' 'crates/**'`). The Done-when recipe as written cannot
# skip the recorded pair: `git diff --name-only 97a03884 ae7bf50d -- '*.rs'
# 'Cargo*.toml'` is NOT empty (10 `.rs` files, 20/20 changed lines are doc-comment
# citation re-points) — so this classifier, which quotes that same set as a
# subset, must *measure* that pair. It does. The recorded spread is a
# same-semantics spread, and it is closed by the gate's demotion, not here.
#
# Deliberately NOT in the set: `TODO.md`, `CHANGELOG.md`, `docs/**`, other
# workflows, and every other script. None of them is compiled, shipped to the
# VPS, or read by the harness, so none can move a measured number.
#
# `AB_REPO_DIR` selects the repository to classify (default: the repository
# this script lives in). The fixture suite drives the script against scratch
# repositories through it.
#
# Semantics are exactly the recorded command's shape — a tree diff between the
# two revisions (`git diff <before> <after> -- <pathspec>`), not a reflog walk.
# Deletions and renames count: a renamed `foo.rs` is a changed build input, and
# `--no-renames` is passed so a rename always surfaces as the delete+add pair
# instead of collapsing into a single rename record whose old/new paths could
# be missed by a pathspec.
# =============================================================================
set -euo pipefail

usage() {
  printf 'usage: %s <before-rev> <after-rev>\n' "${0##*/}" >&2
  printf '  exits 0 (measure, paths on stdout), 1 (no measurable delta), 2 (usage/unresolvable rev)\n' >&2
}

# The repository to classify. Default is the repo the script lives in, resolved
# from the script's own path (not $PWD) so it works from any cwd.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AB_REPO_DIR="${AB_REPO_DIR:-$(dirname "$SCRIPT_DIR")}"

if [[ $# -ne 2 ]]; then
  usage
  exit 2
fi
BEFORE_REV="$1"
AFTER_REV="$2"

# Every path class that can change the measured numbers. Order is the order of
# the comments in the header; `git diff --name-only` re-sorts by path anyway.
PATHSPECS=(
  '*.rs'
  ':(glob)**/Cargo.toml'
  ':(glob)**/Cargo.lock'
  'crates/**'
  'rust-toolchain*'
  '.cargo/**'
  'scripts/frp-stress/**'
  'scripts/ab-matrix.sh'
  'scripts/ab-remote.sh'
  '.github/workflows/ab-matrix.yml'
)

# Resolve a revision to a commit sha, without letting `set -e` abort on a bad
# rev (we want rc 2, not a raw git error). `^{commit}` peels annotated tags and
# refuses a tree/blob, so a non-commit revision is an unresolvable input.
resolve_commit() {  # resolve_commit <rev> -> sha on stdout, rc 1 if unresolved
  local rev="$1" sha
  sha="$(git -C "$AB_REPO_DIR" rev-parse --verify --quiet "${rev}^{commit}" 2>/dev/null)" || return 1
  [[ -n "$sha" ]] || return 1
  printf '%s\n' "$sha"
}

if [[ ! -d "$AB_REPO_DIR" ]]; then
  printf '%s: AB_REPO_DIR is not a directory: %s\n' "${0##*/}" "$AB_REPO_DIR" >&2
  exit 2
fi

before_sha="$(resolve_commit "$BEFORE_REV")" || {
  printf '%s: cannot resolve before revision %q in %s\n' "${0##*/}" "$BEFORE_REV" "$AB_REPO_DIR" >&2
  exit 2
}
after_sha="$(resolve_commit "$AFTER_REV")" || {
  printf '%s: cannot resolve after revision %q in %s\n' "${0##*/}" "$AFTER_REV" "$AB_REPO_DIR" >&2
  exit 2
}

# One path per line, tree diff at the two revisions. `--no-renames` (see the
# header). With two shas in hand this cannot fail on a bad argument, so a
# failure here is a real error and must not be read as "no measurable delta".
if ! changed="$(git -C "$AB_REPO_DIR" diff --name-only --no-renames "$before_sha" "$after_sha" -- "${PATHSPECS[@]}")"; then
  printf '%s: git diff failed for %s..%s in %s\n' "${0##*/}" "$before_sha" "$after_sha" "$AB_REPO_DIR" >&2
  exit 2
fi

if [[ -z "$changed" ]]; then
  exit 1
fi

printf '%s\n' "$changed"
exit 0
