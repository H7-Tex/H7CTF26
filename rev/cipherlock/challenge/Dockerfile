FROM ubuntu:24.04@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc libc6-dev libssl-dev python3 python3-pip \
    && pip install --no-cache-dir --break-system-packages pycryptodome z3-solver \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY cipherlock.c gen.py ./
COPY serve.py /serve.py
EXPOSE 8080
CMD ["python3", "/serve.py"]
