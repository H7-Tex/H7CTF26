FROM ubuntu:24.04 AS build
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev && rm -rf /var/lib/apt/lists/*
COPY dispatch.c /tmp/dispatch.c
RUN gcc /tmp/dispatch.c -o /dispatch -fno-stack-protector -no-pie -O0

FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends socat && rm -rf /var/lib/apt/lists/*
COPY --from=build /dispatch /usr/local/bin/dispatch
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh /usr/local/bin/dispatch
EXPOSE 9999
CMD ["/entrypoint.sh"]
