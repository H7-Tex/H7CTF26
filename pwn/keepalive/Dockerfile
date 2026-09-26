FROM ubuntu:22.04 AS build

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        g++ make ca-certificates wget \
        liburcu-dev libsodium-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY challenge/gatecache.cpp challenge/build.sh /src/
RUN bash build.sh gatecache

FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        liburcu8 libsodium23 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -u 1000 play

COPY --from=build /src/gatecache /opt/keepalive/gatecache

USER play
WORKDIR /opt/keepalive
EXPOSE 9006
CMD ["/opt/keepalive/gatecache"]
