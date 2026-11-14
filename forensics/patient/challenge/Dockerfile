FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends \
      openssh-server sudo gcc libc6-dev openssl coreutils procps psmisc \
      binutils gdb curl less vim-tiny file xxd findutils ca-certificates python3 \
 && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /opt/build
COPY rootkit.c implant.c setup.sh entrypoint.sh /opt/build/
RUN chmod +x /opt/build/setup.sh /opt/build/entrypoint.sh
EXPOSE 22
ENTRYPOINT ["/opt/build/entrypoint.sh"]
