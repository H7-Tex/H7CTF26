FROM python:3.11-slim
RUN pip install --no-cache-dir ecdsa==0.19.2
WORKDIR /app
COPY app.py ./
EXPOSE 8080
CMD ["python3", "app.py"]
