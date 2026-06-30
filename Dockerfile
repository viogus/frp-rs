# syntax=docker/dockerfile:1
# Single-arch build (native target). For multi-arch see docker/Dockerfile.source.
#
# Pattern: alpine builder → musl-static binary → scratch runtime (~2 MB total).
# Reference: ~/Codes/scripts/docker/frp/Dockerfile
#
# Usage:
#   docker build -t frps --build-arg FRP_COMPONENT=frps .

# ── Stage 1: Build ────────────────────────────────────────────
FROM rust:1-alpine AS builder
ARG FRP_COMPONENT=frps

RUN apk add --no-cache musl-dev perl make upx

WORKDIR /app

# Cache dependencies (separate layer for faster rebuilds)
COPY Cargo.toml Cargo.lock ./
COPY frp-core/Cargo.toml    frp-core/
COPY frp-server/Cargo.toml  frp-server/
COPY frp-client/Cargo.toml  frp-client/
COPY frps/Cargo.toml        frps/
COPY frpc/Cargo.toml        frpc/
COPY frp-stress/Cargo.toml  frp-stress/

RUN mkdir -p frp-core/src frp-server/src frp-client/src frps/src frpc/src frp-stress/src && \
    echo 'pub fn main() {}' > frp-core/src/lib.rs && \
    echo 'fn main() {}'     > frp-server/src/main.rs && \
    echo 'fn main() {}'     > frp-client/src/main.rs && \
    echo 'fn main() {}'     > frps/src/main.rs && \
    echo 'fn main() {}'     > frpc/src/main.rs && \
    echo 'fn main() {}'     > frp-stress/src/main.rs && \
    cargo build --release --bin frps --bin frpc && \
    rm -rf frp-core/src frp-server/src frp-client/src frps/src frpc/src frp-stress/src

# Build real source (rust:1-alpine defaults to x86_64-unknown-linux-musl)
COPY frp-core/src   frp-core/src/
COPY frp-server/src frp-server/src/
COPY frp-client/src frp-client/src/
COPY frps/src       frps/src/
COPY frpc/src       frpc/src/

RUN cargo build --release --bin frps --bin frpc && \
    strip target/release/frps target/release/frpc && \
    cp target/release/${FRP_COMPONENT} /usr/bin/frp && \
    upx --best --lzma /usr/bin/frp || true

# Compile entrypoint — fully static (musl, no libc dep)
COPY docker/entrypoint.c /tmp/entrypoint.c
RUN gcc -static -s -O2 -DFRP_MODE=\"${FRP_COMPONENT}\" \
    -o /entrypoint /tmp/entrypoint.c && \
    strip --strip-all /entrypoint || true

# ── Stage 2: Runtime ──────────────────────────────────────────
# scratch: 0 MB base. Binary is musl-static, entrypoint is gcc-static.
# Total image ~2 MB (vs Go frp alpine ~15 MB).
FROM scratch
COPY --from=builder /usr/bin/frp /usr/bin/frp
COPY --from=builder /entrypoint /entrypoint
ENV FRP_CONF=/app/frp.toml
ENTRYPOINT ["/entrypoint"]
