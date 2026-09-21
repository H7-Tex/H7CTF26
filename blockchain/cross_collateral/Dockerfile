FROM rust:1.88-slim AS builder
RUN apt-get update && apt-get install -y curl git build-essential libssl-dev pkg-config && rm -rf /var/lib/apt/lists/*
RUN curl -L https://github.com/MystenLabs/sui/releases/download/devnet-v1.49.0/sui-devnet-v1.49.0-ubuntu-x86_64.tgz -o /tmp/sui.tgz \
    && mkdir -p /tmp/sui && tar xzf /tmp/sui.tgz -C /tmp/sui \
    && cp "$(find /tmp/sui -name sui -type f | head -1)" /usr/local/bin/sui && rm -rf /tmp/sui /tmp/sui.tgz
WORKDIR /build
COPY challenge ./chall
RUN cd chall && sui move build
COPY server ./server
RUN cd server && cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates libssl3 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /build/chall ./chall
COPY --from=builder /build/server/target/release/cross-collateral-server ./cross-collateral-server
EXPOSE 1337
CMD ["./cross-collateral-server"]
