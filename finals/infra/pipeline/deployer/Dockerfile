FROM golang:1.23-alpine AS builder
WORKDIR /build
COPY . .
RUN CGO_ENABLED=0 go build -o h7d ./...

FROM docker:27.3-cli
RUN apk add --no-cache git tar python3
RUN docker compose version 2>/dev/null || ( \
    mkdir -p /usr/local/lib/docker/cli-plugins && \
    wget -qO /usr/local/lib/docker/cli-plugins/docker-compose \
      https://github.com/docker/compose/releases/download/v2.29.7/docker-compose-linux-x86_64 && \
    chmod +x /usr/local/lib/docker/cli-plugins/docker-compose )
COPY --from=builder /build/h7d /usr/local/bin/h7d
ENTRYPOINT ["/usr/local/bin/h7d"]
