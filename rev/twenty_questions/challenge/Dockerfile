FROM rust:1.83-slim AS rust
WORKDIR /build
COPY interrogator/Cargo.toml interrogator/Cargo.toml
COPY interrogator/src interrogator/src
RUN cd interrogator && cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends socat && rm -rf /var/lib/apt/lists/*
RUN useradd -m -u 1000 play
WORKDIR /tq
COPY --from=rust /build/interrogator/target/release/interrogator /tq/interrogator
COPY sealer /tq/sealer
COPY entry.sh /tq/entry.sh
RUN chmod +x /tq/entry.sh /tq/interrogator /tq/sealer
ENV TQ_MODE=live
ENV TQ_SEALER=/tq/sealer
ENV TQ_WIN_BASE=0x4baac0
ENV TQ_CONFESS=0x403019
ENV TQ_BEST_KNOWN=285
USER play
EXPOSE 1337
CMD ["socat", "-T60", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:/tq/entry.sh"]
