#!/usr/bin/env bash
# =============================================================================
# Download Go frp release binaries for compatibility testing.
# Usage: download-go-frp.sh [version] [arch] [dest]
#   arch defaults to the host platform (same auto-detect convention as
#   compat-test.sh), e.g. darwin_arm64 on Apple Silicon macOS,
#   linux_amd64 on x86_64 Linux — pass an explicit arch to override.
# =============================================================================
set -euo pipefail

VERSION="${1:-0.71.0}"

# Auto-detect host platform, matching compat-test.sh's path convention
# (/tmp/frp_${VERSION}_${os}_${arch}).
if [[ -n "${2:-}" ]]; then
    ARCH="$2"
else
    _gos="$(uname -s | tr '[:upper:]' '[:lower:]')"
    _goa="$(uname -m)"
    case "$_goa" in
        x86_64)  _goa="amd64" ;;
        aarch64|arm64) _goa="arm64" ;;
    esac
    ARCH="${_gos}_${_goa}"
fi

DEST="${3:-/tmp/frp_${VERSION}_${ARCH}}"

URL="https://github.com/fatedier/frp/releases/download/v${VERSION}/frp_${VERSION}_${ARCH}.tar.gz"

echo "Downloading Go frp v${VERSION} (${ARCH})..."
echo "  URL: ${URL}"
echo "  Dest: ${DEST}"

mkdir -p "$DEST"

# 3-retry download with backoff
TARBALL="/tmp/frp_${VERSION}_${ARCH}.tar.gz"
for i in 1 2 3; do
    if curl -fsSL --connect-timeout 10 --max-time 120 -o "$TARBALL" "$URL"; then
        break
    fi
    echo "attempt $i failed, retrying in 5s..." >&2
    sleep 5
done

if [[ ! -f "$TARBALL" ]]; then
    echo "ERROR: failed to download Go frp after 3 attempts" >&2
    exit 1
fi

tar xzf "$TARBALL" -C "$DEST" --strip-components=1
rm "$TARBALL"
chmod +x "$DEST/frps" "$DEST/frpc"

echo "Go frp v${VERSION} installed:"
echo "  frps: $DEST/frps"
echo "  frpc: $DEST/frpc"
"$DEST/frps" --version 2>&1 || true
