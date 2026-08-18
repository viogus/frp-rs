#!/usr/bin/env bash
# =============================================================================
# Run the frp-rs A/B throughput gate on a remote VPS.
#
# The local GitHub-hosted runner shares its CPU and produces noisy, unrealiable
# throughput numbers (identical code measured -54% then +128% between runs).
# This script moves the *measurement* onto a stable, dedicated host: it bundles
# the already-built after/before release binaries + scripts/ab-matrix.sh into a
# tarball, ships it to a VPS over SSH (reusing the XTCP VPS + frp-test user),
# runs scripts/ab-matrix.sh there (loopback, exclusive CPU), and returns the
# gate's pass/fail exit code. A server-side flock (~/.ab-matrix.lock) prevents
# concurrent runs (e.g. two PRs, or a PR colliding with the daily XTCP slot)
# from overlapping on the same CPU and corrupting the numbers.
#
# Usage (env-driven, BASH 3.2 compatible):
#   AFTER_ROOT=/path/to/after-root \
#   BEFORE_ROOT=/path/to/base-root \
#   AB_VPS_HOST=<host> \
#   AB_VPS_SSH_KEY=/path/to/id_rsa \
#   bash scripts/ab-remote.sh [reps] [dur_s] [remote_dir]
#
#   AFTER_ROOT   dir containing target/release/{frps,frpc} and
#                scripts/frp-stress/target/release/frp-stress (the "after"/PR
#                state). Default: repo root (matches ab-matrix.sh AFTER_DIR).
#   BEFORE_ROOT  dir with the matching "before"/base layout (REQUIRED).
#   AB_VPS_HOST  VPS hostname/IP; falls back to XTCP_VPS_HOST.
#   AB_VPS_SSH_KEY  local path to the SSH private key; falls back to
#                XTCP_VPS_SSH_KEY (content) written to a temp file.
#   AB_VPS_USER  SSH user on the VPS (default: frp-test).
#
# Exit code mirrors the gate: 0 = PASS (all configs within GATE_PCT),
# 1 = REGRESSED, 2+ = setup/ssh error.
# =============================================================================
set -euo pipefail

REPS="${1:-3}"
DUR="${2:-8}"
RDIR="${3:-}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

AFTER_ROOT="${AFTER_ROOT:-$ROOT}"
if [[ -z "${BEFORE_ROOT:-}" ]]; then
  echo "ERROR: BEFORE_ROOT is required (points at the 'before'/base binary root)" >&2
  exit 2
fi

# Resolve VPS connection (reuse XTCP secrets by default)
USER="${AB_VPS_USER:-frp-test}"
HOST="${AB_VPS_HOST:-${XTCP_VPS_HOST:-}}"
if [[ -z "$HOST" ]]; then
  echo "ERROR: AB_VPS_HOST (or XTCP_VPS_HOST) not set" >&2
  exit 2
fi

SSH_KEY_FILE="${AB_VPS_SSH_KEY_FILE:-}"
if [[ -z "$SSH_KEY_FILE" ]]; then
  if [[ -n "${AB_VPS_SSH_KEY:-}" ]]; then
    SSH_KEY_FILE="${AB_VPS_SSH_KEY}"
  elif [[ -n "${XTCP_VPS_SSH_KEY:-}" ]]; then
    # XTCP_VPS_SSH_KEY is the *contents* of the private key; materialize it.
    SSH_KEY_FILE="$(mktemp)"
    printf '%s\n' "${XTCP_VPS_SSH_KEY}" > "$SSH_KEY_FILE"
  else
    echo "ERROR: AB_VPS_SSH_KEY or XTCP_VPS_SSH_KEY not set" >&2
    exit 2
  fi
fi
chmod 600 "$SSH_KEY_FILE"

SSH_COMMON=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
            -o BatchMode=yes -i "$SSH_KEY_FILE")

# Sanity-check the local binary roots before shipping.
check_root() {  # check_root <label> <root>
  local label="$1" root="$2"
  for b in "$root"/target/release/frps "$root"/target/release/frpc \
           "$root"/scripts/frp-stress/target/release/frp-stress; do
    if [[ ! -x "$b" ]]; then
      echo "ERROR: missing $label binary $b (did you build it?)" >&2
      exit 2
    fi
  done
}
check_root "after" "$AFTER_ROOT"
check_root "before" "$BEFORE_ROOT"

# --- build the tarball in a stable layout -------------------------------
#   $RDIR/
#     scripts/ab-matrix.sh
#     after/{target/release/{frps,frpc}, scripts/frp-stress/target/release/frp-stress}
#     base/  (same layout, from BEFORE_ROOT)
# The remote step passes AFTER_ROOT/BEFORE_ROOT explicitly so ab-matrix.sh does
# not depend on PROJECT_DIR resolution.
if [[ -z "$RDIR" ]]; then
  RDIR="$(mktemp -d "${TMPDIR:-/tmp}/ab-remote.XXXXXX")"
fi
mkdir -p "$RDIR/scripts" "$RDIR/after" "$RDIR/base"
cp "$SCRIPT_DIR/ab-matrix.sh" "$RDIR/scripts/ab-matrix.sh"

# Copy each side's binary tree, preserving the manifest layout.
stage_binaries() {  # stage_binaries <src_root> <dst_parent>
  local src="$1" dst="$2"
  ( cd "$src" && tar cf - target/release scripts/frp-stress/target/release ) \
    | ( cd "$dst" && tar xf - )
}
stage_binaries "$AFTER_ROOT"  "$RDIR/after"
stage_binaries "$BEFORE_ROOT" "$RDIR/base"

# --- ship & run on the VPS ----------------------------------------------
# A stable remote bundle root; use the same value local and remote.
REMOTE_BASE="ab-remote-run-$$"

echo "Shipping A/B bundle to ${USER}@${HOST}:~/${REMOTE_BASE}" >&2
ssh "${SSH_COMMON[@]}" "$USER@$HOST" "rm -rf ~/$REMOTE_BASE && mkdir -p ~/$REMOTE_BASE" || { echo "ERROR: ssh mkdir failed" >&2; exit 2; }
tar cf - -C "$RDIR" . | ssh "${SSH_COMMON[@]}" "$USER@$HOST" "tar xf - -C ~/$REMOTE_BASE"

echo "Running A/B matrix gate on ${USER}@${HOST}" >&2
set +e
OUT=$(ssh "${SSH_COMMON[@]}" "$USER@$HOST" \
  "cd ~/$REMOTE_BASE && AFTER_ROOT=\$PWD/after BEFORE_ROOT=\$PWD/base \
   flock -w 1800 ~/.ab-matrix.lock \
   bash scripts/ab-matrix.sh '$REPS' '$DUR' 2>&1")
RC=$?
set -e

# print the gate output so it lands in CI logs / artifacts
echo "$OUT"

# clean up the remote bundle regardless of the result
ssh "${SSH_COMMON[@]}" "$USER@$HOST" "rm -rf ~/$REMOTE_BASE" 2>/dev/null || true

if [[ "$RC" -ne 0 ]]; then
  echo "AB-REMOTE: A/B gate exited ${RC} on the VPS" >&2
fi
exit "$RC"
