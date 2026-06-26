# syntax=docker/dockerfile:1
# Multi-arch Docker image from pre-built GitHub release binaries.
# Downloads the binary matching TARGETARCH and wraps it with the entrypoint.
#
# Used as a fast alternative to Dockerfile.source when the release binaries
# are already built (e.g. local testing against a specific release).

ARG FRP_VERSION=0.1.4

FROM --platform=$BUILDPLATFORM debian:bookworm-slim AS downloader
ARG FRP_VERSION
ARG TARGETARCH
ARG FRP_COMPONENT=frps

# Map Docker TARGETARCH to Go-style arch used in release asset names
RUN case "${TARGETARCH}" in \
      amd64) echo "x86_64" > /tmp/goarch ;; \
      arm64) echo "aarch64" > /tmp/goarch ;; \
      arm)   echo "armv7" > /tmp/goarch ;; \
      *)     echo "Unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
    esac

# Map TARGETARCH to Rust target triple (for the release asset filename)
RUN case "${TARGETARCH}" in \
      amd64) echo "x86_64-unknown-linux-gnu" > /tmp/rust_target ;; \
      arm64) echo "aarch64-unknown-linux-gnu" > /tmp/rust_target ;; \
      arm)   echo "armv7-unknown-linux-gnueabihf" > /tmp/rust_target ;; \
    esac

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates gcc libc6-dev xz-utils && \
    rm -rf /var/lib/apt/lists/*

# Install zig for cross-compiling the entrypoint
RUN curl -sSfL https://ziglang.org/download/0.14.0/zig-linux-$(uname -m)-0.14.0.tar.xz \
    | tar xJ -C /usr/local && \
    ln -s /usr/local/zig-linux-$(uname -m)-0.14.0/zig /usr/local/bin/zig

# Download and extract the release binary
RUN RELEASE_URL="https://github.com/viogus/frp-rs/releases/download/v${FRP_VERSION}/frp-rs_v${FRP_VERSION}_$(cat /tmp/rust_target).tar.gz" && \
    echo "Downloading: ${RELEASE_URL}" && \
    curl -sSfL "${RELEASE_URL}" -o /tmp/release.tar.gz && \
    tar xzf /tmp/release.tar.gz -C /tmp && \
    cp "/tmp/${FRP_COMPONENT}" /usr/bin/frp && \
    chmod +x /usr/bin/frp && \
    strip /usr/bin/frp || true

# Cross-compile the entrypoint
COPY docker/entrypoint.c /tmp/entrypoint.c
RUN zig cc -target $(cat /tmp/rust_target) -static -O2 \
    -DFRP_MODE=\"${FRP_COMPONENT}\" -o /entrypoint /tmp/entrypoint.c

# ── Runtime stage ──────────────────────────────────────────
FROM --platform=$TARGETPLATFORM gcr.io/distroless/static-debian12:latest
COPY --from=downloader /usr/bin/frp /usr/bin/frp
COPY --from=downloader /entrypoint /entrypoint
ENV FRP_CONF=/app/frp.toml
ENTRYPOINT ["/entrypoint"]
