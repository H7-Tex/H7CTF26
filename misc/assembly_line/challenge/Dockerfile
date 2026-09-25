FROM python:3.12-slim
WORKDIR /app
COPY server.py /app/server.py
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh
EXPOSE 9999
CMD ["/app/entrypoint.sh"]
