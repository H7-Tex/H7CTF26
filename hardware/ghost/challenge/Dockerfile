FROM python:3.11-slim
WORKDIR /app
COPY gen.py serve.py ./
RUN mkdir -p /srv/handout
EXPOSE 8080
CMD ["python3", "serve.py"]
