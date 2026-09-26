FROM rust:1.83-slim AS rust
WORKDIR /build
COPY challenge/interrogator/Cargo.toml interrogator/Cargo.toml
COPY challenge/interrogator/src interrogator/src
RUN cd interrogator && cargo build --release

FROM python:3.12-slim
RUN useradd -m -u 1000 grader
WORKDIR /tq
COPY --from=rust /build/interrogator/target/release/interrogator /tq/interrogator
COPY challenge/sealer /tq/sealer
COPY graded/grader/grade.py graded/grader/report.py /tq/
RUN chmod +x /tq/interrogator /tq/sealer
USER grader
EXPOSE 9000
CMD ["python3", "/tq/grade.py"]
