FROM docker:27-cli
RUN apk add --no-cache python3
COPY --from=gcr.io/go-containerregistry/crane:latest /ko-app/crane /usr/local/bin/crane
COPY server.py /opt/prod/server.py
EXPOSE 9000
CMD ["python3", "/opt/prod/server.py"]
