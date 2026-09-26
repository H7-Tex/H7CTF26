FROM python:3.11-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ffmpeg \
 && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir numpy==2.2.1
WORKDIR /app
COPY gen.py serve.py entrypoint.sh ./
RUN chmod +x entrypoint.sh && mkdir -p /srv/hls
ENV SRV_DIR=/srv
EXPOSE 8080
ENTRYPOINT ["/app/entrypoint.sh"]
