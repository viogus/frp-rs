#!/usr/bin/env bash
# =============================================================================
# Download frp-rs release binaries for integration testing.
# Usage: scripts/download-frp-rs.sh [version]
#
# Places frps and frpc in target/debug so integration tests can find them:
# the test harness resolves <NAME>_BIN env -> CARGO_BIN_EXE_<name> ->
# target/debug/<name>. Extracting to the workspace root is impossible — the
# bare frps/frpc tarball entries collide with the crate directories of the
# same name (and --strip-components=1 silently strips the whole entry).
# =============================================================================
set -euo pipefail

VERSION="${1:-0.71.0}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Detect platform triple matching release asset naming.
detect_target() {
    local os arch
    case "$(uname -s)" in
        Darwin) os="apple-darwin" ;;
        Linux)  os="unknown-linux-gnu" ;;
        *)      echo "ERROR: unsupported OS: $(uname -s)" >&2; exit 1 ;;
    esac
    case "$(uname -m)" in
        x86_64|amd64)   arch="x86_64" ;;
        aarch64|arm64)  arch="aarch64" ;;
        armv7l)         arch="armv7"; os="unknown-linux-gnueabihf" ;;
        *)              echo "ERROR: unsupported arch: $(uname -m)" >&2; exit 1 ;;
    esac
    echo "${arch}-${os}"
}

TARGET="$(detect_target)"
ASSET="frp-rs_v${VERSION}_${TARGET}.tar.gz"
URL="https://github.com/viogus/frp-rs/releases/download/v${VERSION}/${ASSET}"
TARBALL="/tmp/${ASSET}"
BIN_DIR="$PROJECT_DIR/target/debug"

echo "Downloading frp-rs v${VERSION} (${TARGET})..."
echo "  URL: ${URL}"
echo "  Dest: ${BIN_DIR}"

# 3-retry download with backoff
for i in 1 2 3; do
    if curl -fsSL --connect-timeout 10 --max-time 120 -o "$TARBALL" "$URL"; then
        break
    fi
    echo "attempt $i failed, retrying in 5s..." >&2
    sleep 5
done

if [[ ! -f "$TARBALL" ]]; then
    echo "ERROR: failed to download frp-rs after 3 attempts" >&2
    exit 1
fi

# Extract into target/debug (tarball entries are bare frps/frpc — no
# strip, no top-level dir).
mkdir -p "$BIN_DIR"
tar xzf "$TARBALL" -C "$BIN_DIR"
rm "$TARBALL"
chmod +x "$BIN_DIR/frps" "$BIN_DIR/frpc"

echo "frp-rs v${VERSION} installed to ${BIN_DIR}:"
"$BIN_DIR/frps" --version 2>&1 || true
"$BIN_DIR/frpc" --version 2>&1 || true

echo ""
echo "Integration tests resolve frps/frpc via <NAME>_BIN env, CARGO_BIN_EXE_<name>, then target/debug/."
echo "This install satisfies the target/debug fallback."
