FROM python:3.12-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends nasm \
 && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir pillow numpy

WORKDIR /app
COPY challenge/ /app/

ENV PORT=8080
EXPOSE 8080

CMD ["sh", "-c", "python bake.py && python server.py"]
