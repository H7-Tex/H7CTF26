FROM golang:1.22-bookworm AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 go build -o /dockyard ./cmd/dockyard

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /dockyard /usr/local/bin/dockyard
RUN mkdir -p /data/blobs/sha256 /data/uploads
EXPOSE 7005
CMD ["/usr/local/bin/dockyard"]
