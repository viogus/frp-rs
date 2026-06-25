# syntax=docker/dockerfile:1

# ── Stage 1: Build ────────────────────────────────────────────
FROM rust:1.91-alpine AS builder

RUN apk add --no-cache musl-dev perl make upx

WORKDIR /app

# Cache dependencies (separate layer for faster rebuilds)
COPY Cargo.toml Cargo.lock ./
COPY frp-core/Cargo.toml    frp-core/
COPY frp-server/Cargo.toml  frp-server/
COPY frp-client/Cargo.toml  frp-client/

RUN mkdir -p frp-core/src frp-server/src frp-client/src && \
    echo 'pub fn main() {}' > frp-core/src/lib.rs && \
    echo 'fn main() {}'     > frp-server/src/main.rs && \
    echo 'fn main() {}'     > frp-client/src/main.rs && \
    cargo build --release --bin frps --bin frpc && \
    rm -rf frp-core/src frp-server/src frp-client/src

# Build real source
COPY frp-core/src   frp-core/src/
COPY frp-server/src frp-server/src/
COPY frp-client/src frp-client/src/

RUN cargo build --release --bin frps --bin frpc && \
    upx --best --lzma target/release/frps target/release/frpc

# ── Stage 2: Runtime ──────────────────────────────────────────
FROM gcr.io/distroless/static-debian12:latest

COPY --from=builder /app/target/release/frps /usr/local/bin/frps
COPY --from=builder /app/target/release/frpc /usr/local/bin/frpc

# Default entrypoint: frps (override for frpc)
ENTRYPOINT ["/usr/local/bin/frps"]
CMD ["-c", "/etc/frp/frps.toml"]
