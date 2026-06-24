ARG FRP_VERSION=0.1.4

FROM --platform=$BUILDPLATFORM debian:bookworm-slim AS downloader
ARG FRP_VERSION
ARG TARGETARCH
ARG FRP_COMPONENT=frps

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates binutils gcc libc6-dev && \
    rm -rf /var/lib/apt/lists/*

# Install cross-compiler when building arm64 on amd64 host
RUN if [ "$TARGETARCH" = "arm64" ] && [ "$(uname -m)" != "aarch64" ]; then \
      apt-get update && \
      apt-get install -y --no-install-recommends gcc-aarch64-linux-gnu && \
      rm -rf /var/lib/apt/lists/*; \
    fi

COPY docker/build.sh /tmp/
RUN sh /tmp/build.sh

RUN strip --strip-all /usr/bin/frp || true

COPY docker/entrypoint.c /tmp/
RUN if [ "$TARGETARCH" = "arm64" ] && [ "$(uname -m)" != "aarch64" ]; then \
      aarch64-linux-gnu-gcc -static -s -O2 -DFRP_MODE="${FRP_COMPONENT}" -o /entrypoint /tmp/entrypoint.c; \
    else \
      gcc -static -s -O2 -DFRP_MODE="${FRP_COMPONENT}" -o /entrypoint /tmp/entrypoint.c; \
    fi

FROM alpine:latest
RUN apk add --no-cache ca-certificates
COPY --from=downloader /usr/bin/frp /usr/bin/frp
COPY --from=downloader /entrypoint /entrypoint
ENV FRP_CONF=/app/frp.toml
ENTRYPOINT ["/entrypoint"]
