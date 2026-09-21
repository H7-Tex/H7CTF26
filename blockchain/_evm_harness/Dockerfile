FROM ghcr.io/foundry-rs/foundry:latest
USER root
ENV HOME=/root
RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-pip && rm -rf /var/lib/apt/lists/*
RUN pip3 install --no-cache-dir web3
COPY harness.py /harness.py
RUN mkdir -p /run
WORKDIR /project
ENV CHAIN_ID=31337 SETUP_VALUE=0 PORT=1337 FLAG="H7CTF{harness_selftest}"
EXPOSE 1337
ENTRYPOINT ["python3", "/harness.py"]
