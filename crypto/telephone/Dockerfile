FROM python:3.11-slim

RUN useradd -m -u 10001 murmur
WORKDIR /app

COPY challenge/murmur_crypto.py challenge/server.py /app/

ENV PORT=1337
EXPOSE 1337

USER murmur
CMD ["python3", "-u", "server.py"]
