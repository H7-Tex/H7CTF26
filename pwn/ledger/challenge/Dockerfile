FROM ubuntu:24.04 AS build
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev && rm -rf /var/lib/apt/lists/*
COPY ledger.c /tmp/ledger.c
RUN gcc /tmp/ledger.c -o /ledger -no-pie -z lazy -O0

FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends socat && rm -rf /var/lib/apt/lists/*
COPY --from=build /ledger /usr/local/bin/ledger
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh /usr/local/bin/ledger
EXPOSE 9999
CMD ["/entrypoint.sh"]
