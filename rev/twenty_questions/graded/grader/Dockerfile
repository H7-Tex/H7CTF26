FROM rust:1.83-slim AS rust
WORKDIR /build
COPY interrogator/Cargo.toml interrogator/Cargo.toml
COPY interrogator/src interrogator/src
RUN cd interrogator && cargo build --release

FROM gcc:14-bookworm AS cc
WORKDIR /build
COPY target/sealer.c .
RUN gcc -static -no-pie -fno-pic -O1 -fno-stack-protector -o sealer sealer.c

FROM python:3.12-slim
RUN useradd -m -u 1000 grader
WORKDIR /tq
COPY --from=rust /build/interrogator/target/release/interrogator /tq/interrogator
COPY --from=cc /build/sealer /tq/sealer
COPY graded/grader/grade.py graded/grader/report.py /tq/
RUN chmod +x /tq/interrogator /tq/sealer
USER grader
EXPOSE 9000
CMD ["python3", "/tq/grade.py"]
