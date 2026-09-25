FROM golang:1.23-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-pip \
    && pip install --no-cache-dir --break-system-packages pycryptodome \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY main.go gen.py go.mod ./
COPY serve.py /serve.py
ENV GOCACHE=/tmp/gocache
EXPOSE 8080
CMD ["python3", "/serve.py"]
