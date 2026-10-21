FROM python:3.12-slim

WORKDIR /checker

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY checker.py .
COPY harborkey.py .

EXPOSE 8000
CMD ["gunicorn", "-k", "uvicorn.workers.UvicornWorker", "-w", "4", "-b", "0.0.0.0:8000", "--timeout", "60", "checker:app"]
