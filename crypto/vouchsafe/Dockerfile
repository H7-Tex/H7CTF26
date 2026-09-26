FROM golang:1.22-alpine AS build
WORKDIR /src
COPY challenge/server/ ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /passport .

FROM alpine:3.20
RUN adduser -D -H passport
WORKDIR /app
COPY --from=build /passport /app/passport
COPY challenge/mds_blob.json /app/mds_blob.json
ENV RP_ID=vouchsafe.h7tex.com
ENV ORIGIN=https://vouchsafe.h7tex.com
ENV PORT=8080
ENV MDS_PATH=/app/mds_blob.json
ENV CREDITS=80
USER passport
EXPOSE 8080
ENTRYPOINT ["/app/passport"]
