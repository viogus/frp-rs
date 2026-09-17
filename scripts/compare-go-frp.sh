#!/usr/bin/env bash
# =============================================================================
# compare-go-frp.sh — measure frp-rs against the official Go frp release, on
# this machine, and emit a table you can paste into the README.
#
# Why this exists: the README's "Why frp-rs?" table was hand-written, and by the
# time anyone checked it, nothing in the tree could reproduce it. `scripts/go-frp/`
# was tracked in git holding **v0.69.1 macOS x86_64** binaries while the project
# targeted v0.71.0, so a size comparison drawn from them was meaningless. A table
# whose entire purpose is "why switch" has to be generated, and the generator has
# to refuse apples-to-oranges comparisons.
#
# Usage:
#   bash scripts/compare-go-frp.sh              # sizes (uses existing binaries)
#   bash scripts/compare-go-frp.sh --build      # build all four tiers first
#   bash scripts/compare-go-frp.sh --memory     # also measure idle RSS
#   bash scripts/compare-go-frp.sh --build --memory
#
# Guarantees, and it aborts rather than warns when they do not hold:
#   * the Go binaries are for THIS os/arch (checked with `file`)
#   * the Go binaries self-report the SAME version frp-rs targets (checked with
#     `--version`), so a stale download cannot silently produce a fake result
#   * the frp-rs binaries self-report that same version
#
# Exit codes: 0 measured, 1 a guard failed or a binary is missing.
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

DO_BUILD=0
DO_MEMORY=0
for arg in "$@"; do
  case "$arg" in
    --build)  DO_BUILD=1 ;;
    --memory) DO_MEMORY=1 ;;
    -h|--help)
      sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) echo "unknown argument: $arg" >&2; exit 1 ;;
  esac
done

die() { echo "error: $*" >&2; exit 1; }

# ---------------------------------------------------------------- platform
host_os=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$(uname -m)" in
  x86_64)         host_arch=amd64; file_marker='x86-64|x86_64' ;;
  arm64|aarch64)  host_arch=arm64; file_marker='arm64|aarch64' ;;
  *) die "unsupported host architecture: $(uname -m)" ;;
esac
go_platform="${host_os}_${host_arch}"

# ---------------------------------------------------------------- versions
# frp-rs's canonical version is the VERSION constant (CLAUDE.md: versioning is
# mandatory and aligned with Go frp's release number).
rs_version=$(grep -m1 'pub const VERSION' frp-core/src/lib.rs | sed -E 's/.*"([^"]+)".*/\1/')
[ -n "$rs_version" ] || die "could not read VERSION from frp-core/src/lib.rs"
echo "frp-rs target version: $rs_version"
echo "host platform:         $go_platform"
echo

# ---------------------------------------------------------------- go binaries
GO_DIR="${GO_FRP_DIR:-/tmp/frp_${rs_version}_${go_platform}}"
GO_FRPS="$GO_DIR/frps"
GO_FRPC="$GO_DIR/frpc"

if [ ! -x "$GO_FRPS" ] || [ ! -x "$GO_FRPC" ]; then
  echo "Go frp not found in $GO_DIR — fetching it (scripts/download-go-frp.sh)"
  bash scripts/download-go-frp.sh "$rs_version" "$go_platform" "$GO_DIR" \
    || die "download failed; compare against Go frp cannot proceed"
fi

# Guard 1: platform. `file` reports the binary's own arch; a macOS x86_64 binary
# on an arm64 host is exactly the mistake this script exists to prevent.
if command -v file >/dev/null 2>&1; then
  go_desc=$(file -b "$GO_FRPS")
  if ! printf '%s' "$go_desc" | grep -Eqi "$file_marker"; then
    die "Go binary is not for this host.
       host:        $go_platform
       got:         $go_desc
       A cross-platform comparison is meaningless. Re-download with:
         bash scripts/download-go-frp.sh $rs_version $go_platform $GO_DIR"
  fi
  echo "Go binary platform: ok ($go_desc)"
fi

# Guard 2: version. Both implementations answer `--version`.
go_version=$("$GO_FRPS" --version 2>/dev/null | head -1 | tr -d 'v \r\n')
[ -n "$go_version" ] || die "could not read a version from $GO_FRPS --version"
if [ "$go_version" != "$rs_version" ]; then
  die "Go frp version mismatch: got $go_version, frp-rs targets $rs_version.
       Comparing across versions is meaningless. Refresh with:
         rm -rf $GO_DIR && bash scripts/download-go-frp.sh $rs_version $go_platform $GO_DIR"
fi
echo "Go version: ok ($go_version)"

# ---------------------------------------------------------------- frp-rs binaries
RS_DEFAULT_S=./target/release/frps
RS_DEFAULT_C=./target/release/frpc
RS_TINY_S=./target/release/frps-tiny
RS_TINY_C=./target/release/frpc-tiny
RS_MICRO_S=./target/release/frps-micro
RS_MICRO_C=./target/release/frpc-micro

if [ "$DO_BUILD" -eq 1 ]; then
  echo
  echo "=== Building frp-rs (release profile, all tiers) ==="
  cargo build --release -p frps -p frpc || die "default tier build failed"
  cargo build --release -p frps -p frpc --no-default-features --features tiny \
    || die "tiny tier build failed"
  cargo build --release -p frps -p frpc --no-default-features --features micro \
    || die "micro tier build failed"
fi

[ -x "$RS_DEFAULT_S" ] || die "$RS_DEFAULT_S missing — run with --build"

# Guard 3: the frp-rs binaries we are about to measure are the version we claim.
rs_reported=$("$RS_DEFAULT_S" --version 2>/dev/null | head -1 | tr -d 'v \r\n')
case "$rs_reported" in
  *"$rs_version"*) echo "frp-rs binary version: ok ($rs_reported)" ;;
  *) die "$RS_DEFAULT_S reports '$rs_reported', expected $rs_version — rebuild with --build" ;;
esac

# ---------------------------------------------------------------- sizes
size_mb() { # <path> -> MB with 1 decimal, or "-" when absent
  [ -f "$1" ] || { printf '%s' "-"; return; }
  awk -v b="$(wc -c < "$1" | tr -d ' ')" 'BEGIN{printf "%.1f", b/1048576}'
}

echo
echo "=== Binary sizes (MB, this platform) ==="

rs_rows=""
for tier in default tiny micro; do
  case "$tier" in
    default) s="$RS_DEFAULT_S"; c="$RS_DEFAULT_C" ;;
    tiny)    s="$RS_TINY_S";    c="$RS_TINY_C" ;;
    micro)   s="$RS_MICRO_S";   c="$RS_MICRO_C" ;;
  esac
  printf '  frp-rs %-8s frps %6s MB   frpc %6s MB\n' "$tier" "$(size_mb "$s")" "$(size_mb "$c")"
  rs_rows="${rs_rows}| frp-rs \`${tier}\` | $(size_mb "$s") MB | $(size_mb "$c") MB |"$'\n'
done
printf '  %-16s frps %6s MB   frpc %6s MB\n' "Go frp ($go_version)" "$(size_mb "$GO_FRPS")" "$(size_mb "$GO_FRPC")"

# ---------------------------------------------------------------- idle RSS
rss_line=""
if [ "$DO_MEMORY" -eq 1 ]; then
  echo
  echo "=== Idle RSS (no proxies, 5 s settle, 5 s max) ==="

  PORT="${COMPARE_PORT:-17250}"
  TOKEN="compare-token"
  CFG=/tmp/compare-go-frp
  mkdir -p "$CFG"

  # Go camelCase keys: frp-rs accepts them too (see the config-normalization
  # compat layer), so ONE config pair drives both implementations. No proxies are
  # configured — this measures the runtime baseline, which is what the README's
  # "Memory (idle)" row claims.
  cat > "$CFG/frps.toml" <<EOF
bindAddr = "127.0.0.1"
bindPort = $PORT
[auth]
method = "token"
token = "$TOKEN"
[log]
level = "error"
EOF
  cat > "$CFG/frpc.toml" <<EOF
serverAddr = "127.0.0.1"
serverPort = $PORT
[auth]
method = "token"
token = "$TOKEN"
[log]
level = "error"
EOF

  sample_pair() { # <label> <frps> <frpc>
    local label="$1" sbin="$2" cbin="$3" spid cpid peak_s=0 peak_c=0 r
    "$sbin" -c "$CFG/frps.toml" >/dev/null 2>&1 & spid=$!
    sleep 1
    "$cbin" -c "$CFG/frpc.toml" >/dev/null 2>&1 & cpid=$!
    sleep 5
    for _ in $(seq 1 10); do
      r=$(ps -o rss= -p "$spid" 2>/dev/null | tr -d ' ')
      [ -n "$r" ] && [ "$r" -gt "$peak_s" ] && peak_s=$r
      r=$(ps -o rss= -p "$cpid" 2>/dev/null | tr -d ' ')
      [ -n "$r" ] && [ "$r" -gt "$peak_c" ] && peak_c=$r
      sleep 0.5
    done
    kill "$cpid" "$spid" 2>/dev/null || true
    wait "$cpid" "$spid" 2>/dev/null || true
    if [ "$peak_s" -eq 0 ] || [ "$peak_c" -eq 0 ]; then
      echo "  WARNING: $label did not stay up (frps=${peak_s}KB frpc=${peak_c}KB)" >&2
    fi
    printf '  %-18s frps %5s MB   frpc %5s MB\n' "$label" \
      "$(awk -v k="$peak_s" 'BEGIN{printf "%.1f", k/1024}')" \
      "$(awk -v k="$peak_c" 'BEGIN{printf "%.1f", k/1024}')"
    RSS_S=$(awk -v k="$peak_s" 'BEGIN{printf "%.1f", k/1024}')
    RSS_C=$(awk -v k="$peak_c" 'BEGIN{printf "%.1f", k/1024}')
  }

  # Every frp-rs tier, not just the default: the small tiers are the ones a
  # constrained deployment would actually run, so their baseline matters.
  sample_pair "frp-rs default" "$RS_DEFAULT_S" "$RS_DEFAULT_C"
  rs_rss_s=$RSS_S; rs_rss_c=$RSS_C
  rss_tiny="—"; rss_micro="—"
  if [ -x "$RS_TINY_S" ]; then
    sample_pair "frp-rs tiny" "$RS_TINY_S" "$RS_TINY_C"; rss_tiny=$RSS_S
  fi
  if [ -x "$RS_MICRO_S" ]; then
    sample_pair "frp-rs micro" "$RS_MICRO_S" "$RS_MICRO_C"; rss_micro=$RSS_S
  fi
  sample_pair "Go frp $go_version" "$GO_FRPS" "$GO_FRPC"
  go_rss_s=$RSS_S; go_rss_c=$RSS_C

  rss_line="| Memory (idle, frps) | ${go_rss_s} MB | ${rs_rss_s} MB | ${rss_tiny} MB | ${rss_micro} MB |"$'\n'
  rss_line="${rss_line}| Memory (idle, frpc) | ${go_rss_c} MB | ${rs_rss_c} MB | — | — |"$'\n'
fi

# ---------------------------------------------------------------- emit
rs_version_stamp=$(rustc --version 2>/dev/null | sed 's/^rustc //' || echo "unknown")
cat <<EOF

=== README-ready table ===
<!-- Generated by scripts/compare-go-frp.sh on $(date -u '+%Y-%m-%d') —
     platform: $go_platform; frp-rs $rs_version; Go frp $go_version;
     rustc $rs_version_stamp; declared release profile.
     Regenerate rather than editing these numbers by hand. -->

| Metric | Go frp v$go_version | frp-rs (default) | frp-rs (\`tiny\`) | frp-rs (\`micro\`) |
|--------|---------------|------------------|-----------------|-------------------|
| frps binary | $(size_mb "$GO_FRPS") MB | $(size_mb "$RS_DEFAULT_S") MB | $(size_mb "$RS_TINY_S") MB | $(size_mb "$RS_MICRO_S") MB |
| frpc binary | $(size_mb "$GO_FRPC") MB | $(size_mb "$RS_DEFAULT_C") MB | $(size_mb "$RS_TINY_C") MB | $(size_mb "$RS_MICRO_C") MB |
${rss_line}
EOF

if [ "$DO_MEMORY" -eq 0 ]; then
  echo "Idle RSS not measured — rerun with --memory."
fi
echo "Missing tiers show '-' — build them with --build."
