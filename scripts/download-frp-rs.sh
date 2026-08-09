#!/usr/bin/env bash
# =============================================================================
# Download frp-rs release binaries for integration testing.
# Usage: scripts/download-frp-rs.sh [version] [dest]
#
# Places frps and frpc in the workspace root so integration tests can find
# them via ../frps and ../frpc (test harness checks these paths before
# falling back to target/ builds).
# =============================================================================
set -euo pipefail

VERSION="${1:-0.70.1}"
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

echo "Downloading frp-rs v${VERSION} (${TARGET})..."
echo "  URL: ${URL}"
echo "  Dest: ${PROJECT_DIR}"

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

# Extract to workspace root
tar xzf "$TARBALL" -C "$PROJECT_DIR" --strip-components=1
rm "$TARBALL"
chmod +x "$PROJECT_DIR/frps" "$PROJECT_DIR/frpc"

echo "frp-rs v${VERSION} installed to workspace root:"
echo "  frps: $PROJECT_DIR/frps"
echo "  frpc: $PROJECT_DIR/frpc"
"$PROJECT_DIR/frps" --version 2>&1 || true
"$PROJECT_DIR/frpc" --version 2>&1 || true

echo ""
echo "Integration tests will now find frps/frpc via ../frps and ../frpc."
echo "Set FRPS_BIN or FRPC_BIN env vars to override."
