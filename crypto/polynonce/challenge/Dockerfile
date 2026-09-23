FROM python:3.11-slim
RUN pip install --no-cache-dir ecdsa==0.19.2 pycryptodome==3.20.0
WORKDIR /app
COPY gen.py serve.py ./
RUN mkdir -p /srv/handout
EXPOSE 8080
CMD ["python3", "serve.py"]
