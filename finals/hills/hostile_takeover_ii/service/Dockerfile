# pin the base by digest: :latest drifted (pip broke + tzdata hangs) -- use the validated digest
FROM ghcr.io/foundry-rs/foundry:latest@sha256:0c00cb0bda1ab1b91c9a6bf60f4c76c09c1a8870824b6d4718afbabacf6f9a17
USER root
ENV HOME=/root

# flask from apt, not pip: the base's pip is unreliable across image drift / PEP 668.
# DEBIAN_FRONTEND=noninteractive: python3-flask pulls tzdata, which blocks on a timezone
# prompt without a TTY and hangs the build.
RUN DEBIAN_FRONTEND=noninteractive apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        python3 python3-flask haveged \
    && rm -rf /var/lib/apt/lists/*

# bake contracts + solc download into the image so startup doesn't need the network.
# forge-std is already vendored in challenge/lib/; forge build warms the solc cache.
COPY challenge/foundry.toml /project/foundry.toml
COPY challenge/lib          /project/lib
COPY challenge/src          /project/src
RUN cd /project && forge build

# server scripts (copied last so contract rebuilds stay fast)
COPY server/server.py      /server.py
COPY server/compute_sig.py /compute_sig.py
COPY server/entrypoint.sh  /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENV PORT=8080
EXPOSE 8080
ENTRYPOINT ["/entrypoint.sh"]
