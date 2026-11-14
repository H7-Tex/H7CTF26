FROM ghcr.io/foundry-rs/foundry:latest
USER root
ENV HOME=/root
RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-pip haveged && rm -rf /var/lib/apt/lists/*
RUN pip3 install --no-cache-dir web3
COPY harness.py /harness.py
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh && mkdir -p /run
WORKDIR /project
ENV CHAIN_ID=31337 SETUP_VALUE=0 PORT=1337 FLAG="H7CTF{harness_selftest}"
EXPOSE 1337
ENTRYPOINT ["/entrypoint.sh"]
