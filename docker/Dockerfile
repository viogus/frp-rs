ARG FRP_VERSION=0.1.4

FROM alpine:latest AS downloader
ARG FRP_VERSION
ARG TARGETARCH
ARG FRP_COMPONENT=frps

RUN apk add --no-cache curl tar binutils gcc musl-dev upx

COPY docker/build.sh /tmp/
RUN sh /tmp/build.sh

RUN upx --best --lzma /usr/bin/frp || echo "WARN: upx frp failed" >&2

COPY docker/entrypoint.c /tmp/
RUN gcc -static -s -O2 -DFRP_MODE=\"${FRP_COMPONENT}\" -o /entrypoint /tmp/entrypoint.c && \
    strip --strip-all /entrypoint || echo "WARN: strip entrypoint failed" >&2

FROM alpine:latest
COPY --from=downloader /usr/bin/frp /usr/bin/frp
COPY --from=downloader /entrypoint /entrypoint
COPY --from=downloader /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
ENV FRP_CONF=/app/frp.toml
ENTRYPOINT ["/entrypoint"]
