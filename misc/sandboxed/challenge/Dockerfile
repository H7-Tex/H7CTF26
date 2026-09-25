FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends socat \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY jail.py entrypoint.sh /app/
RUN chmod +x /app/entrypoint.sh
EXPOSE 9999
CMD ["/app/entrypoint.sh"]
