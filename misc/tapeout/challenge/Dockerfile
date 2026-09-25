FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends socat \
    && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir z3-solver
WORKDIR /app
COPY hdl.py verifier.py server.py reference.hdl entrypoint.sh /app/
RUN chmod +x /app/entrypoint.sh
EXPOSE 9999
CMD ["/app/entrypoint.sh"]
