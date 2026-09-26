FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PORT=8080 APP_ENV=production
WORKDIR /app
COPY requirements.txt .
RUN python -m pip install --no-cache-dir -r requirements.txt \
    && groupadd --system --gid 10001 relay \
    && useradd --system --uid 10001 --gid relay --home-dir /nonexistent relay \
    && groupadd --system --gid 10002 exporter \
    && useradd --system --uid 10002 --gid exporter --home-dir /nonexistent exporter
COPY relay ./relay
COPY exporter ./exporter

FROM base AS exporter
ENV PORT=8090
USER 10002:10002
CMD ["python", "-m", "uvicorn", "exporter.main:app", "--host", "0.0.0.0", "--port", "8090"]

# Keep Relay last so a plain `docker build .` produces the public 8080 image.
# Release publishing still names both targets explicitly.
FROM base AS relay
USER 10001:10001
EXPOSE 8080
CMD ["python", "-m", "uvicorn", "relay.main:app", "--host", "0.0.0.0", "--port", "8080"]
