FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app
COPY requirements.lock ./requirements.lock
COPY pyproject.toml ./pyproject.toml
COPY argus ./argus
RUN python -m pip install --no-cache-dir --requirement requirements.lock \
    && python -m pip install --no-cache-dir --no-build-isolation --no-deps . \
    && addgroup --system --gid 101 argus && adduser --system --ingroup argus --uid 100 argus \
    && install -d -o argus -g argus -m 0750 /var/lib/argus
USER 100:101
VOLUME ["/var/lib/argus"]
ENTRYPOINT ["python", "-m", "argus.main"]
CMD ["all"]
