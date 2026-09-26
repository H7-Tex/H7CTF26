FROM ubuntu:24.04 AS build
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY challenge/core.c challenge/build.sh ./
RUN sh build.sh

FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends socat && rm -rf /var/lib/apt/lists/*
RUN useradd -m -u 10001 play
COPY --from=build /src/countersign /app/countersign
RUN chmod 555 /app/countersign
USER play
EXPOSE 1337
CMD ["socat", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:/app/countersign"]
