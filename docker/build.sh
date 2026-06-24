#!/bin/sh
set -euo pipefail

COMPONENT="${FRP_COMPONENT:-frps}"

case "${TARGETARCH}" in
  amd64) ARCH=x86_64 ;;
  arm64) ARCH=aarch64 ;;
  arm)   ARCH=armv7 ;;
  *)
    echo "Unsupported arch: ${TARGETARCH}" >&2
    exit 1
    ;;
esac

BASE="frp-rs_v${FRP_VERSION}_${ARCH}-unknown-linux-musl"
URL="https://github.com/viogus/frp-rs/releases/download/v${FRP_VERSION}/${BASE}.tar.gz"

# armv7: no musl build — use gnueabihf
[ "$ARCH" = "armv7" ] && BASE="frp-rs_v${FRP_VERSION}_${ARCH}-unknown-linux-gnueabihf" && URL="https://github.com/viogus/frp-rs/releases/download/v${FRP_VERSION}/${BASE}.tar.gz"

echo "[frp-rs] downloading ${COMPONENT} v${FRP_VERSION} for linux/${ARCH}"
for i in 1 2 3; do
  if curl -fsSL --connect-timeout 10 --max-time 120 \
    -o /tmp/frp-rs.tar.gz "$URL"; then
    break
  fi
  echo "[frp-rs] attempt $i failed, retrying..." >&2
  sleep 5
done

[ -f /tmp/frp-rs.tar.gz ] || { echo "[frp-rs] download failed" >&2; exit 1; }

tar -xzf /tmp/frp-rs.tar.gz -C /tmp/
[ -f "/tmp/${COMPONENT}" ] || { echo "[frp-rs] component not found: ${COMPONENT}" >&2; ls -la /tmp/ >&2; exit 1; }

cp "/tmp/${COMPONENT}" /usr/bin/frp
strip --strip-all /usr/bin/frp || echo "WARN: strip frp failed" >&2
chmod +x /usr/bin/frp

rm -rf /tmp/frp-rs.tar.gz /tmp/frps /tmp/frpc

echo "[frp-rs] ${COMPONENT}: $(/usr/bin/frp --version 2>&1 || true)"
