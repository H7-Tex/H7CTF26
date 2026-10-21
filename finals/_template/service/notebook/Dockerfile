# pin by digest for real services; deps (none here) go in before the source
FROM python:3.12-slim
WORKDIR /app
RUN mkdir /data && chown 1000:1000 /data
COPY app.py .
USER 1000
EXPOSE 7000
CMD ["python3", "-u", "app.py"]
