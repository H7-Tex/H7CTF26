FROM golang:1.24-bookworm AS builder
WORKDIR /src
COPY . .
RUN CGO_ENABLED=1 go build -mod=vendor -o /dockyard ./cmd/dockyard

FROM debian:bookworm-slim
RUN groupadd -g 1000 dockyard && useradd -u 1000 -g dockyard -s /sbin/nologin dockyard
COPY --from=builder /dockyard /usr/local/bin/dockyard
RUN mkdir -p /data/blobs/sha256 /data/uploads && chown -R dockyard:dockyard /data
USER dockyard
EXPOSE 7005
CMD ["/usr/local/bin/dockyard"]
