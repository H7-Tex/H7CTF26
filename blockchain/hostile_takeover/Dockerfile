# build context = blockchain/hostile_takeover/
FROM ghcr.io/foundry-rs/foundry:latest
USER root
ENV HOME=/root
RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-pip haveged \
    && rm -rf /var/lib/apt/lists/*
RUN pip3 install --no-cache-dir --break-system-packages flask

COPY challenge/foundry.toml /project/foundry.toml
COPY challenge/src /project/src
RUN cd /project && forge build

COPY server/server.py /server.py
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# KOTH_ADMIN_TOKEN injected by the engine (gates /koth/reset); KOTH_VERIFY_URL (optional) =
# the engine's token->team_id endpoint so only issued buy-in tokens can play.
ENV PORT=8080
EXPOSE 8080
ENTRYPOINT ["/entrypoint.sh"]
