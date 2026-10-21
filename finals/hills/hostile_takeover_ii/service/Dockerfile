# syntax=docker/dockerfile:1
FROM ghcr.io/foundry-rs/foundry:stable@sha256:21b1aaf90e7f4c00ab1bee68b4adfbce86a8ef2af2d2e00e7a1d07d16ef2b5be AS foundry

FROM python:3.12-slim

# system deps: haveged for entropy, cast/forge from foundry image
RUN apt-get update && apt-get install -y --no-install-recommends \
        haveged \
    && rm -rf /var/lib/apt/lists/*

COPY --from=foundry /usr/local/bin/forge /usr/local/bin/forge
COPY --from=foundry /usr/local/bin/cast  /usr/local/bin/cast
COPY --from=foundry /usr/local/bin/anvil /usr/local/bin/anvil

# python deps
RUN pip install --no-cache-dir flask==3.0.3 gunicorn==22.0.0

# challenge source (Solidity contracts + foundry setup)
COPY challenge/ /project/

# pre-build (compiles Solc, warms forge cache) so startup is fast
RUN cd /project && forge build

# server scripts
COPY server/server.py      /server.py
COPY server/compute_sig.py /compute_sig.py
COPY server/entrypoint.sh  /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 8080

ENTRYPOINT ["/entrypoint.sh"]
