# One image, run as 5 separate tier containers (TIER=gateway_v1.0 .. gateway_v3.0), each in its
# own container so popping one can't read another's token. Build context = pwn/aegis_gateway.
FROM ubuntu:24.04@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3 AS build
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /w
COPY challenge/build_tiers.sh .
COPY challenge/src ./src
RUN bash build_tiers.sh

FROM ubuntu:24.04@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3
RUN apt-get update && apt-get install -y --no-install-recommends socat && rm -rf /var/lib/apt/lists/*
COPY --from=build /w/build/ /tiers/
COPY graded/tier/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh /tiers/*
EXPOSE 9999
CMD ["/entrypoint.sh"]
