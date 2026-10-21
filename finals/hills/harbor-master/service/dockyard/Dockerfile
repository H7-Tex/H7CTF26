FROM golang:1.24-bookworm AS builder
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN CGO_ENABLED=1 go build -mod=vendor -o /dockyard ./cmd/dockyard

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /dockyard /usr/local/bin/dockyard
RUN mkdir -p /data/blobs/sha256 /data/uploads
EXPOSE 7005
CMD ["/usr/local/bin/dockyard"]
