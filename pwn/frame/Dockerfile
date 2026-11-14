FROM ubuntu:24.04@sha256:80dd3c3b9c6cecb9f1667e9290b3bc61b78c2678c02cbdae5f0fea92cc6734ab AS build
RUN apt-get update && apt-get install -y --no-install-recommends clang-18 libstdc++-14-dev && rm -rf /var/lib/apt/lists/*
COPY challenge/attest.cpp /src/attest.cpp
WORKDIR /src
RUN clang++-18 -std=c++20 -O2 -fno-strict-aliasing -fPIE -pie -Wl,-z,relro,-z,now -o /attest attest.cpp

FROM ubuntu:24.04@sha256:80dd3c3b9c6cecb9f1667e9290b3bc61b78c2678c02cbdae5f0fea92cc6734ab
RUN apt-get update && apt-get install -y --no-install-recommends socat && rm -rf /var/lib/apt/lists/*
COPY --from=build /attest /usr/local/bin/attest
COPY challenge/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh /usr/local/bin/attest
EXPOSE 1337
CMD ["/entrypoint.sh"]
