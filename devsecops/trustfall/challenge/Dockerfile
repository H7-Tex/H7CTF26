FROM aquasec/trivy@sha256:665030f4d33a82c1e8d9d5e0453365842236723c1ee5cc3becca698268e66a56 AS trivy

FROM python:3.12.8-slim-bookworm

ARG TRIVY_VERSION=0.58.2
ARG TRIVY_SHA256=f9d23b40e7a15294e7d3664fb7bdd9e6940cf982b6d8d647e1b1ab9d795e2235

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy

RUN set -eux; \
    echo "${TRIVY_SHA256}  /usr/local/bin/trivy" | sha256sum -c -; \
    mkdir -p /tmp/trivy-contract; \
    printf 'resource "aws_s3_bucket" "contract" {\n  bucket = "trustfall-contract"\n}\n' > /tmp/trivy-contract/main.tf; \
    trivy --debug config \
        --skip-check-update \
        --misconfig-scanners terraform \
        --format sarif \
        --output /tmp/trivy-contract/results.sarif \
        /tmp/trivy-contract; \
    cat /tmp/trivy-contract/results.sarif; \
    grep -F '"ruleId": "s3-bucket-logging"' /tmp/trivy-contract/results.sarif; \
    groupadd --gid 10001 trustfall; \
    useradd --uid 10001 --gid 10001 --create-home trustfall; \
    mkdir /data; \
    chown trustfall:trustfall /data; \
    rm -rf /tmp/trivy-contract
COPY pyproject.toml ./
COPY trustfall ./trustfall
RUN pip install --no-cache-dir .
USER trustfall
ENTRYPOINT ["python", "-m", "trustfall.main"]
