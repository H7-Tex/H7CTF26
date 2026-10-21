FROM python:3.12-slim
RUN pip install --no-cache-dir flask
COPY server.py /server.py
EXPOSE 8085
CMD ["python3", "-u", "/server.py"]
