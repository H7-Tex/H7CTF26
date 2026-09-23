FROM python:3.11-slim
RUN pip install --no-cache-dir numpy==2.2.1 pycryptodome==3.21.0
WORKDIR /app
COPY aes_sbox.py gen.py serve.py ./
ENV SRV_DIR=/srv/handout PORT=8080
EXPOSE 8080
CMD ["python3", "serve.py"]
