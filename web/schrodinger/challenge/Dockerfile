# Verified with duplicate-member reference wheel: Python 3.12.14, pip 25.0.1.
FROM python:3.12-slim@sha256:2f17fc044b579bab302c2e8054d3a686e2cb9a83de48e70534b94cd8ebbe06a9

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    ARTIFACT_DATA_DIR=/var/lib/schrodinger

WORKDIR /app
COPY requirements.txt .
RUN python -m pip install --no-cache-dir --upgrade pip==25.0.1 \
    && python -m pip install --no-cache-dir -r requirements.txt \
    && groupadd --system --gid 10001 schrodinger \
    && useradd --system --uid 10001 --gid schrodinger --home-dir /nonexistent schrodinger \
    && mkdir -p /var/lib/schrodinger \
    && chown schrodinger:schrodinger /var/lib/schrodinger

COPY schrodinger ./schrodinger
USER 10001:10001
CMD ["python", "-m", "schrodinger.main", "portal"]
