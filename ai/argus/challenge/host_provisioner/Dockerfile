FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1
ARG KUBECTL_VERSION=v1.33.0
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
    && curl -fsSLo /usr/local/bin/kubectl "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/amd64/kubectl" \
    && chmod 0755 /usr/local/bin/kubectl \
    && rm -rf /var/lib/apt/lists/*
COPY host_provisioner/requirements.lock ./requirements.lock
RUN python -m pip install --no-cache-dir --requirement requirements.lock
COPY app/argus ./argus
COPY host_provisioner/argus_host_provisioner ./argus_host_provisioner
RUN addgroup --system argus && adduser --system --ingroup argus --uid 10001 argus
USER 10001:10001
CMD ["python", "-m", "argus_host_provisioner.provision"]
