FROM ubuntu:24.04@sha256:80dd3c3b9c6cecb9f1667e9290b3bc61b78c2678c02cbdae5f0fea92cc6734ab AS build
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev && rm -rf /var/lib/apt/lists/*
COPY challenge/hothouse.c /src/hothouse.c
WORKDIR /src
RUN gcc -O2 -static -s -fno-stack-protector -o /hothouse hothouse.c

FROM ubuntu:24.04@sha256:80dd3c3b9c6cecb9f1667e9290b3bc61b78c2678c02cbdae5f0fea92cc6734ab
RUN apt-get update && apt-get install -y --no-install-recommends socat && rm -rf /var/lib/apt/lists/*
COPY --from=build /hothouse /usr/local/bin/hothouse
COPY challenge/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh /usr/local/bin/hothouse
EXPOSE 1337
CMD ["/entrypoint.sh"]
