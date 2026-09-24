FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 DATA_DIR=/data
WORKDIR /app
COPY pyproject.toml ./
COPY echo_chamber ./echo_chamber
RUN pip install --no-cache-dir . && mkdir /data && useradd --uid 10001 --create-home echo && chown echo:echo /data
USER echo
EXPOSE 8080
# --proxy-headers + trust the forwarding proxy (Traefik) so url_for() honors
# X-Forwarded-Proto and emits https:// links (else the browser blocks the
# http:// css/js as mixed content behind TLS).
CMD ["uvicorn", "echo_chamber.main:app", "--host", "0.0.0.0", "--port", "8080", "--proxy-headers", "--forwarded-allow-ips", "*"]
