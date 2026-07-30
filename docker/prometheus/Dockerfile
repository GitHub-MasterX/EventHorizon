FROM golang:1.23.9-bookworm@sha256:0c9738aabadd34e99cf5263ae1337ad5330126c87a1fab4ffabec2284944c991 AS go-builder

WORKDIR /app
ENV GOTOOLCHAIN=local \
    GOFLAGS=-mod=readonly
COPY prometheus/go.mod prometheus/go.sum ./
RUN sha256sum go.mod go.sum > /tmp/go-modules.sha256
COPY prometheus/ .
RUN sha256sum -c /tmp/go-modules.sha256 \
    && mkdir -p /out \
    && go build -mod=readonly -o /out/prometheus_exporter

# Final image
FROM debian:bookworm-slim@sha256:63a496b5d3b99214b39f5ed70eb71a61e590a77979c79cbee4faf991f8c0783e

COPY --from=go-builder /out/prometheus_exporter /usr/local/bin/

WORKDIR /app
CMD ["prometheus_exporter"]
