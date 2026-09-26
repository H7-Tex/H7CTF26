FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        liburcu8 libsodium23 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -u 1000 play

COPY challenge/gatecache /opt/keepalive/gatecache
RUN chmod +x /opt/keepalive/gatecache

USER play
WORKDIR /opt/keepalive
EXPOSE 9006
CMD ["/opt/keepalive/gatecache"]
