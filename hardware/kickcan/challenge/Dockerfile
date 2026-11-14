FROM python:3.11-slim
WORKDIR /app
COPY gen.py serve.py ./
ENV SRV_DIR=/srv/handout PORT=8080
EXPOSE 8080
CMD ["python3", "serve.py"]
