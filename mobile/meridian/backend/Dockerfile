FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .

ENV PORT=8080
EXPOSE 8080

# single worker: v4 mutates in-memory role state, so state must not split across workers
CMD ["gunicorn", "-w", "1", "-b", "0.0.0.0:8080", "app:app"]
