FROM ubuntu:24.04@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3 AS build
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev libseccomp-dev && rm -rf /var/lib/apt/lists/*
COPY vault.c /tmp/vault.c
RUN gcc /tmp/vault.c -o /vault -lseccomp -no-pie

FROM ubuntu:24.04@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3
RUN apt-get update && apt-get install -y --no-install-recommends socat libseccomp2 && rm -rf /var/lib/apt/lists/*
COPY --from=build /vault /usr/local/bin/vault
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh /usr/local/bin/vault
EXPOSE 9999
CMD ["/entrypoint.sh"]
