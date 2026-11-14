FROM python:3.11-slim
RUN pip install --no-cache-dir flask==3.1.0 pycryptodome==3.17 gunicorn==23.0.0
WORKDIR /app
COPY app.py ./
ENV PORT=8080 KOTH_RESET=90 KOTH_CLAIM_COOLDOWN=3
EXPOSE 8080
CMD ["gunicorn", "-w", "1", "--threads", "16", "-b", "0.0.0.0:8080", "app:app"]
