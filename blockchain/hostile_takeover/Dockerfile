# build context = blockchain/hostile_takeover/
# pin the base by digest: :latest drifted (its pip3 stopped taking --break-system-packages)
# and broke the build. this digest is the validated one.
FROM ghcr.io/foundry-rs/foundry:latest@sha256:0c00cb0bda1ab1b91c9a6bf60f4c76c09c1a8870824b6d4718afbabacf6f9a17
USER root
ENV HOME=/root
# flask from apt, not pip: the base's pip is unreliable across image drift / PEP 668.
# DEBIAN_FRONTEND=noninteractive: python3-flask pulls python-babel→tzdata, which otherwise
# blocks on an interactive timezone prompt (no TTY in the build) and hangs the build.
RUN DEBIAN_FRONTEND=noninteractive apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3 python3-flask haveged \
    && rm -rf /var/lib/apt/lists/*

COPY challenge/foundry.toml /project/foundry.toml
COPY challenge/src /project/src
RUN cd /project && forge build

COPY server/server.py /server.py
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# KOTH_ADMIN_TOKEN injected by the engine (gates /koth/reset). KOTH_VERIFY_URL = engine endpoint,
# POST {token, rpc_secret} -> {valid, public_tag}; with KOTH_REQUIRE_SECRET=true every /rpc write
# must carry the private per-team X-Koth-Secret (issued at buy-in) -> closes token-harvest grief.
ENV PORT=8080
EXPOSE 8080
ENTRYPOINT ["/entrypoint.sh"]
