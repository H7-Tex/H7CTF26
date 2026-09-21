FROM rust:1.89-bookworm AS builder
RUN apt-get update && apt-get install -y curl build-essential pkg-config libudev-dev libssl-dev && rm -rf /var/lib/apt/lists/*
RUN sh -c "$(curl -sSfL https://release.anza.xyz/stable/install)"
ENV PATH="/root/.local/share/solana/install/active_release/bin:${PATH}"
WORKDIR /build
COPY program ./program
COPY server ./server
RUN cd program && cargo build-sbf --sbf-out-dir /build/out
RUN cd server && cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates libssl3 && rm -rf /var/lib/apt/lists/*
WORKDIR /challenge
COPY --from=builder /build/out/perp_guard.so ./perp_guard.so
COPY --from=builder /build/server/target/release/perp-guard-server ./perp-guard-server
EXPOSE 1337
CMD ["./perp-guard-server"]
