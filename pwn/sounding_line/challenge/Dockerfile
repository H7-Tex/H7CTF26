FROM ubuntu:22.04@sha256:0e5e4a57c2499249aafc3b40fcd541e9a456aab7296681a3994d631587203f97 AS build
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev && rm -rf /var/lib/apt/lists/*
COPY sounding_line.c /tmp/sounding_line.c
COPY manifold.h /tmp/manifold.h
RUN gcc -O2 -fPIE -pie -fstack-protector-strong -Wl,-z,relro,-z,now -I/tmp -o /sounding_line /tmp/sounding_line.c -ldl && strip -s /sounding_line

FROM ubuntu:22.04@sha256:0e5e4a57c2499249aafc3b40fcd541e9a456aab7296681a3994d631587203f97
RUN apt-get update && apt-get install -y --no-install-recommends socat && rm -rf /var/lib/apt/lists/*
COPY --from=build /sounding_line /usr/local/bin/sounding_line
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh /usr/local/bin/sounding_line
EXPOSE 5000
CMD ["/entrypoint.sh"]
