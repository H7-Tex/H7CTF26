FROM ubuntu:24.04@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3 AS build
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev make && rm -rf /var/lib/apt/lists/*
WORKDIR /w
COPY challenge/Makefile ./Makefile
COPY challenge/src ./src
RUN make OUT=/aria

FROM ubuntu:24.04@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3
RUN apt-get update && apt-get install -y --no-install-recommends socat && rm -rf /var/lib/apt/lists/*
COPY --from=build /aria /usr/local/bin/aria
COPY challenge/eq.cfg /srv/eq.cfg
COPY challenge/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh /usr/local/bin/aria
EXPOSE 9999
CMD ["/entrypoint.sh"]
