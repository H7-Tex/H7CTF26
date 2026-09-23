FROM python:3.11-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ffmpeg curl ca-certificates \
 && curl -fsSL https://github.com/bluenviron/mediamtx/releases/download/v1.9.3/mediamtx_v1.9.3_linux_amd64.tar.gz \
    | tar xz -C /usr/local/bin mediamtx \
 && apt-get purge -y curl && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir numpy==2.2.1
WORKDIR /app
COPY gen.py mediamtx.yml entrypoint.sh ./
RUN chmod +x entrypoint.sh && mkdir -p /srv
ENV SRV_DIR=/srv
EXPOSE 8080
ENTRYPOINT ["/app/entrypoint.sh"]
