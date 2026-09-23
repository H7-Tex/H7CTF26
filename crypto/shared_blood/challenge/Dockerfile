FROM python:3.11-slim
RUN pip install --no-cache-dir pycryptodome==3.20.0 gmpy2==2.2.1
WORKDIR /app
COPY app.py ./
EXPOSE 8080
CMD ["python3", "app.py"]
