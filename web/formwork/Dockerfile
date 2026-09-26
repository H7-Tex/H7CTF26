FROM golang:1.25-bookworm AS build
WORKDIR /src
COPY challenge/go.mod challenge/go.sum ./
RUN go mod download
COPY challenge/ ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags "-s -w" -o /out/formwork .

FROM postgres:16
ENV POSTGRES_HOST_AUTH_METHOD=trust
WORKDIR /app
COPY --from=build /out/formwork /app/formwork
COPY challenge/deploy /app/deploy
COPY challenge/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh
RUN chown -R postgres:postgres /app
USER postgres
EXPOSE 8080
ENTRYPOINT ["/app/entrypoint.sh"]
