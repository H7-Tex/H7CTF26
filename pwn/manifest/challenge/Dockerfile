FROM ubuntu:24.04 AS build
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev && rm -rf /var/lib/apt/lists/*
COPY manifest.c /tmp/manifest.c
RUN gcc /tmp/manifest.c -o /manifest -fno-stack-protector -no-pie -O0

FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends socat && rm -rf /var/lib/apt/lists/*
COPY --from=build /manifest /usr/local/bin/manifest
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh /usr/local/bin/manifest
EXPOSE 9999
CMD ["/entrypoint.sh"]
