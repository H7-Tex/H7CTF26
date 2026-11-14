FROM ubuntu:24.04@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3 AS build
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev && rm -rf /var/lib/apt/lists/*
COPY src/gateway.c /tmp/gateway.c
# v2.0 (2023): NX, stack canary, PIE, Partial RELRO. No FORTIFY, no seccomp, CET off.
RUN gcc -Wno-format-security -fcf-protection=none -fstack-protector-all -fPIE -pie \
        -Wl,-z,relro,-z,lazy -o /gateway /tmp/gateway.c

FROM ubuntu:24.04@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3
RUN apt-get update && apt-get install -y --no-install-recommends socat && rm -rf /var/lib/apt/lists/*
COPY --from=build /gateway /usr/local/bin/gateway
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh /usr/local/bin/gateway
EXPOSE 9999
CMD ["/entrypoint.sh"]
