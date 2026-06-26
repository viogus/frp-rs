# syntax=docker/dockerfile:1
# Multi-arch Docker image from pre-built GitHub release binaries.
# Downloads the musl-static binary matching TARGETARCH.
#
# Pattern: alpine downloader → musl-static binary → scratch runtime (~2 MB).
# Reference: ~/Codes/scripts/docker/frp/Dockerfile
#
# Used when release binaries are already built (faster than building from source).

ARG FRP_VERSION=0.1.6

FROM --platform=$BUILDPLATFORM alpine:latest AS downloader
ARG FRP_VERSION
ARG TARGETARCH
ARG FRP_COMPONENT=frps

RUN apk add --no-cache curl tar binutils gcc musl-dev

# Map Docker TARGETARCH to Rust target triple (musl, for release asset filename)
RUN case "${TARGETARCH}" in \
      amd64) echo "x86_64-unknown-linux-musl" > /tmp/rust_target ;; \
      arm64) echo "aarch64-unknown-linux-musl" > /tmp/rust_target ;; \
      arm)   echo "armv7-unknown-linux-musleabihf" > /tmp/rust_target ;; \
      *)     echo "Unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
    esac

# Download and extract the release binary (musl variant)
RUN RELEASE_URL="https://github.com/viogus/frp-rs/releases/download/v${FRP_VERSION}/frp-rs_v${FRP_VERSION}_$(cat /tmp/rust_target).tar.gz" && \
    echo "Downloading: ${RELEASE_URL}" && \
    for i in 1 2 3; do \
      curl -fsSL --connect-timeout 10 --max-time 120 \
        -o /tmp/release.tar.gz "$RELEASE_URL" && break; \
      echo "[frp-rs] attempt $i failed, retrying..." >&2; \
      sleep 5; \
    done && \
    [ -f /tmp/release.tar.gz ] || { echo "[frp-rs] download failed" >&2; exit 1; } && \
    tar xzf /tmp/release.tar.gz -C /tmp && \
    cp "/tmp/${FRP_COMPONENT}" /usr/bin/frp && \
    chmod +x /usr/bin/frp && \
    strip /usr/bin/frp || true

# Compile entrypoint — fully static (musl, no libc dep)
COPY docker/entrypoint.c /tmp/entrypoint.c
RUN gcc -static -s -O2 -DFRP_MODE=\"${FRP_COMPONENT}\" \
    -o /entrypoint /tmp/entrypoint.c && \
    strip --strip-all /entrypoint || true

# ── Runtime stage ──────────────────────────────────────────
# scratch: 0 MB base. Both binary (musl-static) and entrypoint
# (gcc-static) have zero runtime deps. Total image ~3 MB.
FROM scratch
COPY --from=downloader /usr/bin/frp /usr/bin/frp
COPY --from=downloader /entrypoint /entrypoint
ENV FRP_CONF=/app/frp.toml
ENTRYPOINT ["/entrypoint"]
