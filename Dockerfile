# syntax=docker/dockerfile:1

# ── Stage 1: Build ────────────────────────────────────────────
# Use glibc builder (not alpine/musl) so the binary runs on distroless/static.
FROM rust:1-slim-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    musl-tools perl make upx-ucl && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Cache dependencies (separate layer for faster rebuilds)
COPY Cargo.toml Cargo.lock ./
COPY frp-core/Cargo.toml    frp-core/
COPY frp-server/Cargo.toml  frp-server/
COPY frp-client/Cargo.toml  frp-client/
COPY frps/Cargo.toml        frps/
COPY frpc/Cargo.toml        frpc/

RUN mkdir -p frp-core/src frp-server/src frp-client/src frps/src frpc/src && \
    echo 'pub fn main() {}' > frp-core/src/lib.rs && \
    echo 'fn main() {}'     > frp-server/src/main.rs && \
    echo 'fn main() {}'     > frp-client/src/main.rs && \
    echo 'fn main() {}'     > frps/src/main.rs && \
    echo 'fn main() {}'     > frpc/src/main.rs && \
    cargo build --release --bin frps --bin frpc && \
    rm -rf frp-core/src frp-server/src frp-client/src frps/src frpc/src

# Build real source
COPY frp-core/src   frp-core/src/
COPY frp-server/src frp-server/src/
COPY frp-client/src frp-client/src/
COPY frps/src       frps/src/
COPY frpc/src       frpc/src/

RUN cargo build --release --bin frps --bin frpc && \
    strip target/release/frps target/release/frpc && \
    upx --best --lzma target/release/frps target/release/frpc

# ── Stage 2: Runtime ──────────────────────────────────────────
# distroless/static: ~3 MB base. Binary ~2 MB after UPX. Total ~5 MB.
FROM gcr.io/distroless/static-debian12:latest

COPY --from=builder /app/target/release/frps /usr/local/bin/frps
COPY --from=builder /app/target/release/frpc /usr/local/bin/frpc

# Default entrypoint: frps (override for frpc)
ENTRYPOINT ["/usr/local/bin/frps"]
CMD ["-c", "/etc/frp/frps.toml"]
